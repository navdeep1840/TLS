// Package ipinfo queries https://ipinfo.codexsecurity.io for geolocation and
// threat intel on an IP address. Results are cached in-memory for 1 hour so
// repeated events for the same destination don't hammer the API.
package ipinfo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	apiBase    = "https://ipinfo.codexsecurity.io/api/v1/lookup"
	cacheTTL   = time.Hour
	httpTimeout = 5 * time.Second
)

// IPInfo mirrors the JSON response from the lookup API.
type IPInfo struct {
	IP                string  `json:"ip"`
	IPVersion         string  `json:"ip_version"`
	Country           string  `json:"country"`
	CountryCode       string  `json:"country_code"`
	CountryInEU       bool    `json:"country_in_eu"`
	Continent         string  `json:"continent"`
	ContinentCode     string  `json:"continent_code"`
	Region            string  `json:"region"`
	RegionCode        string  `json:"region_code"`
	City              string  `json:"city"`
	PostalCode        string  `json:"postal_code"`
	Timezone          string  `json:"timezone"`
	Latitude          float64 `json:"latitude"`
	Longitude         float64 `json:"longitude"`
	AccuracyRadiusKm  int     `json:"accuracy_radius_km"`
	ASN               int     `json:"asn"`
	ASNOrg            string  `json:"asn_org"`
	Network           string  `json:"network"`
	IsAnonymous       bool    `json:"is_anonymous"`
	IsAnonymousVPN    bool    `json:"is_anonymous_vpn"`
	IsHostingProvider bool    `json:"is_hosting_provider"`
	IsPublicProxy     bool    `json:"is_public_proxy"`
	IsResidentialProxy bool   `json:"is_residential_proxy"`
	IsTorExitNode     bool    `json:"is_tor_exit_node"`
	IsBogon           bool    `json:"is_bogon"`
}

type cacheEntry struct {
	info      *IPInfo
	expiresAt time.Time
}

// Client is a thread-safe IP info client with an in-memory cache.
type Client struct {
	mu         sync.RWMutex
	cache      map[string]cacheEntry
	httpClient *http.Client
}

// New returns a ready-to-use Client.
func New() *Client {
	return &Client{
		cache:      make(map[string]cacheEntry),
		httpClient: &http.Client{Timeout: httpTimeout},
	}
}

// Lookup returns enriched info for ip, using the in-memory cache when possible.
func (c *Client) Lookup(ip string) (*IPInfo, error) {
	// Fast path: cache hit
	c.mu.RLock()
	if entry, ok := c.cache[ip]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.info, nil
	}
	c.mu.RUnlock()

	// Slow path: HTTP call
	url := fmt.Sprintf("%s/%s", apiBase, ip)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ipinfo GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipinfo GET %s: status %s", url, resp.Status)
	}

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("ipinfo decode: %w", err)
	}

	// Store in cache
	c.mu.Lock()
	c.cache[ip] = cacheEntry{info: &info, expiresAt: time.Now().Add(cacheTTL)}
	c.mu.Unlock()

	return &info, nil
}
