package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// OSD saved-objects API constants. Mirrors the logging-controller's
// pkg/dashboards import behavior so a Crossplane MR can replace the
// OpensearchDashboard reconciler, adding a Read (Observe/adopt) and a symmetric
// Delete (the controller has neither) so the MR owns full object lifecycle.
const (
	osdSavedObjectsPath = "/api/saved_objects"
	osdImportPath       = "/api/saved_objects/_import"
	osdXsrfHeader       = "osd-xsrf"
	osdTenantHeader     = "securitytenant"
	osdGlobalTenant     = "Global"
)

// savedObjectRef is one parsed ndjson line from the bundle. Only id+type are
// needed for Read/Delete; the rest of the object is ignored.
type savedObjectRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func resourceOpensearchSavedObjectsImport() *schema.Resource {
	return &schema.Resource{
		Description: "Imports an ndjson saved-objects bundle into OpenSearch Dashboards via the /api/saved_objects/_import API, per tenant. Mirrors the logging-controller OpensearchDashboard reconciler (import, overwrite), adding a Read (Observe/adopt) and a symmetric Delete so the MR owns full lifecycle of every object in the bundle. One resource = one bundle in one tenant.",
		Create:      resourceOpensearchSavedObjectsImportCreate,
		Read:        resourceOpensearchSavedObjectsImportRead,
		Update:      resourceOpensearchSavedObjectsImportCreate, // idempotent with overwrite; update == re-import
		Delete:      resourceOpensearchSavedObjectsImportDelete,
		// Passthrough import seeds d.Id() (<tenant>/<name>); Read recovers the
		// ForceNew identity fields from the id so the post-import plan sees no diff.
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Logical bundle name; becomes the multipart filename (<name>.ndjson).",
			},
			"tenant": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     osdGlobalTenant,
				Description: "OSD tenant the bundle is imported into. Part of the resource identity.",
			},
			"contents": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The raw ndjson saved-objects bundle (one JSON object per line).",
			},
			"overwrite": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether to overwrite existing objects on import (?overwrite=). Matches the controller default of true.",
			},
		},
	}
}

// tenantOrDefault mirrors the controller: empty tenant means the Global tenant.
func tenantOrDefault(d *schema.ResourceData) string {
	t := d.Get("tenant").(string)
	if t == "" {
		return osdGlobalTenant
	}
	return t
}

// splitObjectsImportID parses the resource id (<tenant>/<name>) set by Create's
// d.SetId. Used by the importer and Read to recover the ForceNew identity fields.
func splitObjectsImportID(id string) (tenant, name string, err error) {
	parts := strings.SplitN(id, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("objects-import id must be <tenant>/<name>, got %q", id)
	}
	return parts[0], parts[1], nil
}

// osdBaseURL returns the trimmed OSD base URL or an error if unset. The OSD API
// lives on a separate service/port from OpenSearch, so it needs its own URL.
func osdBaseURL(conf *ProviderConf) (string, error) {
	if conf.dashboardsURL == "" {
		return "", fmt.Errorf("dashboards_url must be set on the provider to use opensearch_saved_objects_import")
	}
	return strings.TrimRight(conf.dashboardsURL, "/"), nil
}

// newOSDRequest builds an OSD API request with the standard headers and basic
// auth from the provider credentials. A dedicated request path is used because
// the shared elastic7 client targets the OpenSearch node API, not OSD.
func newOSDRequest(conf *ProviderConf, method, url, tenant string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(osdXsrfHeader, "true")
	req.Header.Set(osdTenantHeader, tenant)
	if conf.username != "" || conf.password != "" {
		req.SetBasicAuth(conf.username, conf.password)
	}
	return req, nil
}

// parseBundle extracts {id, type} from each ndjson line, skipping the trailing
// export summary line (which has no type).
func parseBundle(contents string) ([]savedObjectRef, error) {
	var refs []savedObjectRef
	dec := json.NewDecoder(strings.NewReader(contents))
	for {
		var ref savedObjectRef
		err := dec.Decode(&ref)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse ndjson bundle: %w", err)
		}
		if ref.Type == "" || ref.ID == "" {
			continue // summary line or malformed entry
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func resourceOpensearchSavedObjectsImportCreate(d *schema.ResourceData, meta interface{}) error {
	conf := meta.(*ProviderConf)
	base, err := osdBaseURL(conf)
	if err != nil {
		return err
	}
	name := d.Get("name").(string)
	tenant := tenantOrDefault(d)
	contents := d.Get("contents").(string)
	overwrite := d.Get("overwrite").(bool)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	// Single .ndjson suffix (the controller emits a cosmetic double suffix; the
	// API reads content, not filename).
	filename := name
	if !strings.HasSuffix(filename, ".ndjson") {
		filename += ".ndjson"
	}
	pw, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err = io.Copy(pw, strings.NewReader(contents)); err != nil {
		return err
	}
	writer.Close()

	url := fmt.Sprintf("%s%s?overwrite=%t", base, osdImportPath, overwrite)
	req, err := newOSDRequest(conf, http.MethodPost, url, tenant, bytes.NewReader(body.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(rsp.Body)
		return fmt.Errorf("failed importing saved objects (status %d): %s", rsp.StatusCode, string(rb))
	}

	d.SetId(fmt.Sprintf("%s/%s", tenant, name))
	return resourceOpensearchSavedObjectsImportRead(d, meta)
}

func resourceOpensearchSavedObjectsImportRead(d *schema.ResourceData, meta interface{}) error {
	conf, ok := meta.(*ProviderConf)
	if !ok || conf == nil {
		log.Printf("[WARN] objects-import Read: provider not configured (meta=%v) for id=%q; skipping", meta, d.Id())
		return nil
	}
	base, err := osdBaseURL(conf)
	if err != nil {
		return err
	}
	tenant := tenantOrDefault(d)

	// Keep the ForceNew identity fields populated from the id so a refresh after
	// import does not read them as changed (Read is the only path that runs on
	// an adopted object before the first apply).
	if t, n, err := splitObjectsImportID(d.Id()); err == nil {
		if err := d.Set("tenant", t); err != nil {
			return err
		}
		if err := d.Set("name", n); err != nil {
			return err
		}
		tenant = t
	}

	refs, err := parseBundle(d.Get("contents").(string))
	if err != nil {
		return err
	}

	// Existence policy: every object the bundle imported must still exist. If any
	// managed object is missing, drop the id so the next apply re-imports the
	// bundle. Type-agnostic (dashboard, index-pattern, search, visualization).
	for _, ref := range refs {
		ok, err := osdObjectExists(conf, base, tenant, ref)
		if err != nil {
			return err
		}
		if !ok {
			d.SetId("") // a managed object is missing -> recreate
			return nil
		}
	}
	return nil
}

// osdObjectExists returns true if GET /api/saved_objects/<type>/<id> is 200.
func osdObjectExists(conf *ProviderConf, base, tenant string, ref savedObjectRef) (bool, error) {
	url := fmt.Sprintf("%s%s/%s/%s", base, osdSavedObjectsPath, ref.Type, ref.ID)
	req, err := newOSDRequest(conf, http.MethodGet, url, tenant, nil)
	if err != nil {
		return false, err
	}
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer rsp.Body.Close()
	_, _ = io.Copy(io.Discard, rsp.Body)
	if rsp.StatusCode == http.StatusOK {
		return true, nil
	}
	if rsp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	rb, _ := io.ReadAll(rsp.Body)
	return false, fmt.Errorf("unexpected status %d reading saved object %s/%s: %s", rsp.StatusCode, ref.Type, ref.ID, string(rb))
}

func resourceOpensearchSavedObjectsImportDelete(d *schema.ResourceData, meta interface{}) error {
	conf := meta.(*ProviderConf)
	base, err := osdBaseURL(conf)
	if err != nil {
		return err
	}
	tenant := tenantOrDefault(d)

	refs, err := parseBundle(d.Get("contents").(string))
	if err != nil {
		return err
	}

	// Delete every object the bundle imported (not just dashboards). The
	// controller leaves index-patterns/searches behind; a Crossplane MR owns full
	// lifecycle, so teardown must not orphan them. 200 and 404 both count as gone.
	for _, ref := range refs {
		url := fmt.Sprintf("%s%s/%s/%s", base, osdSavedObjectsPath, ref.Type, ref.ID)
		req, err := newOSDRequest(conf, http.MethodDelete, url, tenant, nil)
		if err != nil {
			return err
		}
		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		rsp.Body.Close()
		if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("failed deleting saved object %s/%s (status %d)", ref.Type, ref.ID, rsp.StatusCode)
		}
	}
	d.SetId("")
	return nil
}
