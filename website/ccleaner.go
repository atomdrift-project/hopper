package website

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func newCCleaner() *ccleaner { return &ccleaner{api: ccleanerProductAPI} }

// ccleanerProductAPI is the JSON endpoint the live download page calls.
//
// Discovery flow:
//  1. The human-facing page https://www.ccleaner.com/ccleaner/download/standard
//     ships a Vue bundle that, on page load, fetches /api/product/info.
//  2. That JSON returns a ProductVariants[] list with stable installer URLs
//     hosted on bits.avcdn.net (the lightweight stub, the full offline
//     installer) plus a versioned portable .zip on download.ccleaner.com.
//
// Caveat observed 2026-05: the API ignores the product= and variant= query
// parameters and always returns the Windows record. macOS will need a
// separate source once we identify its discovery surface.
const ccleanerProductAPI = "https://www.ccleaner.com/api/product/info?product=ccleaner&variant=free"

type ccleaner struct {
	// api is overridable for tests; production uses ccleanerProductAPI.
	api string
}

func (*ccleaner) Name() string     { return "ccleaner" }
func (*ccleaner) Hostname() string { return "ccleaner.com" }
func (*ccleaner) MonitorPage() string {
	return "https://www.ccleaner.com/ccleaner/download/standard"
}

// Type codes observed in CCleaner's product API. Codes 1 and 2 both point at
// the same online (stub) installer; we dedupe identical URLs in Discover.
const (
	ccleanerTypeOnlineA  = 1
	ccleanerTypeOnlineB  = 2
	ccleanerTypeFull     = 3
	ccleanerTypePortable = 4
)

type ccleanerAPIVariant struct {
	URL  string `json:"Url"`
	Type int    `json:"Type"`
}

type ccleanerAPIProduct struct {
	ProductVariants    []ccleanerAPIVariant `json:"ProductVariants"`
	MajorVersionNumber int                  `json:"MajorVersionNumber"`
	MinorVersionNumber int                  `json:"MinorVersionNumber"`
	BuildNumber        int                  `json:"BuildNumber"`
}

type ccleanerAPIResponse struct {
	Product ccleanerAPIProduct `json:"product"`
}

func (c *ccleaner) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req) //nolint:gosec // c.api is the configured product-info endpoint.
	if err != nil {
		return nil, fmt.Errorf("product api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("product api: HTTP %d", resp.StatusCode)
	}

	var pr ccleanerAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("product api decode: %w", err)
	}

	seen := make(map[string]bool, len(pr.Product.ProductVariants))
	targets := make([]Target, 0, len(pr.Product.ProductVariants))
	for _, v := range pr.Product.ProductVariants {
		if v.URL == "" || seen[v.URL] {
			continue
		}
		seen[v.URL] = true
		targets = append(targets, Target{URL: v.URL, Variant: ccleanerVariantLabel(v.Type)})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("product api: no variants in response (build=%d.%d.%d)",
			pr.Product.MajorVersionNumber, pr.Product.MinorVersionNumber, pr.Product.BuildNumber)
	}
	return targets, nil
}

func ccleanerVariantLabel(t int) string {
	switch t {
	case ccleanerTypeOnlineA, ccleanerTypeOnlineB:
		return "windows-online-installer"
	case ccleanerTypeFull:
		return "windows-full-installer"
	case ccleanerTypePortable:
		return "windows-portable"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}
