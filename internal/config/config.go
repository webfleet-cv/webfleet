package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir             string
	DatabaseURL         string
	Listen              string
	CheckInterval       time.Duration
	CrawlInterval       time.Duration
	CheckConcurrency    int
	AuditSandbox        string
	TrustedProxies      []netip.Prefix
	PublicURL           string
	AnalyticsServerSide bool
	GeoIPURL            string
	GeoIPAutoUpdate     bool
	Replication         ReplicationConfig
}

type ReplicationConfig struct {
	Enabled           bool
	NodeID            string
	Listen            string
	Bootstrap         bool
	TLSCert           string
	TLSKey            string
	TLSCA             string
	InsecurePlaintext bool
}

func Load() (Config, error) {
	c := Config{DataDir: "./data", Listen: "127.0.0.1:7336", CheckInterval: time.Minute, CrawlInterval: 6 * time.Hour, CheckConcurrency: 8, AuditSandbox: "strict"}
	if v := os.Getenv("WEBFLEET_DATABASE_URL"); v != "" {
		c.DatabaseURL = v
	}
	if v := os.Getenv("WEBFLEET_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("WEBFLEET_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("WEBFLEET_CHECK_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("WEBFLEET_CHECK_INTERVAL: %w", err)
		}
		c.CheckInterval = d
	}
	if v := os.Getenv("WEBFLEET_CRAWL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("WEBFLEET_CRAWL_INTERVAL: %w", err)
		}
		c.CrawlInterval = d
	}
	if v := os.Getenv("WEBFLEET_CHECK_CONCURRENCY"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 128 {
			return c, fmt.Errorf("WEBFLEET_CHECK_CONCURRENCY must be 1..128")
		}
		c.CheckConcurrency = n
	}
	if v := os.Getenv("WEBFLEET_AUDIT_SANDBOX"); v != "" {
		if v != "strict" && v != "allow-no-sandbox" {
			return c, fmt.Errorf("WEBFLEET_AUDIT_SANDBOX must be strict or allow-no-sandbox")
		}
		c.AuditSandbox = v
	}
	if v := os.Getenv("WEBFLEET_TRUSTED_PROXIES"); v != "" {
		prefixes, err := ParsePrefixList(v)
		if err != nil {
			return c, fmt.Errorf("WEBFLEET_TRUSTED_PROXIES: %w", err)
		}
		c.TrustedProxies = prefixes
	}
	if v := os.Getenv("WEBFLEET_PUBLIC_URL"); v != "" {
		if err := validatePublicURL(v); err != nil {
			return c, fmt.Errorf("WEBFLEET_PUBLIC_URL: %w", err)
		}
		c.PublicURL = strings.TrimRight(v, "/")
	}
	if v := os.Getenv("WEBFLEET_ANALYTICS_SERVER_SIDE"); v == "1" || strings.EqualFold(v, "true") {
		c.AnalyticsServerSide = true
	}
	if v := os.Getenv("WEBFLEET_GEOIP_URL"); v != "" {
		c.GeoIPURL = v
	} else {
		// DB-IP Lite country dataset (CC BY 4.0, no registration required).
		c.GeoIPURL = "https://download.db-ip.com/free/dbip-country-lite.csv.gz"
	}
	if v := os.Getenv("WEBFLEET_REPLICATION_ENABLED"); v == "1" || strings.EqualFold(v, "true") {
		c.Replication.Enabled = true
	}
	c.Replication.NodeID = os.Getenv("WEBFLEET_REPLICATION_NODE_ID")
	c.Replication.Listen = os.Getenv("WEBFLEET_REPLICATION_LISTEN")
	if v := os.Getenv("WEBFLEET_REPLICATION_BOOTSTRAP"); v == "1" || strings.EqualFold(v, "true") {
		c.Replication.Bootstrap = true
	}
	c.Replication.TLSCert = os.Getenv("WEBFLEET_REPLICATION_TLS_CERT")
	c.Replication.TLSKey = os.Getenv("WEBFLEET_REPLICATION_TLS_KEY")
	c.Replication.TLSCA = os.Getenv("WEBFLEET_REPLICATION_TLS_CA")
	if v := os.Getenv("WEBFLEET_REPLICATION_INSECURE_PLAINTEXT"); v == "1" || strings.EqualFold(v, "true") {
		c.Replication.InsecurePlaintext = true
	}
	if v := os.Getenv("WEBFLEET_GEOIP_AUTO_UPDATE"); v == "0" || strings.EqualFold(v, "false") {
		c.GeoIPAutoUpdate = false
	} else {
		c.GeoIPAutoUpdate = true
	}
	abs, err := filepath.Abs(c.DataDir)
	if err == nil {
		c.DataDir = abs
	}
	if c.DatabaseURL == "" {
		if choice, e := LoadDatabaseChoice(c.DataDir); e == nil && choice.Provider == "postgres" {
			c.DatabaseURL = choice.URL
		}
	}
	if c.Replication.Enabled {
		if c.DatabaseURL != "" {
			return c, fmt.Errorf("Webfleet clustering currently requires SQLite")
		}
		if strings.TrimSpace(c.Replication.Listen) == "" {
			return c, fmt.Errorf("WEBFLEET_REPLICATION_LISTEN is required when replication is enabled")
		}
		if !c.Replication.InsecurePlaintext && (c.Replication.TLSCert == "" || c.Replication.TLSKey == "" || c.Replication.TLSCA == "") {
			return c, fmt.Errorf("replication TLS cert, key and CA are required")
		}
	}
	return c, nil
}

type DatabaseChoice struct {
	Provider string `json:"provider"`
	URL      string `json:"url,omitempty"`
}

// ParsePrefixList parses a comma-separated list of IP addresses or CIDR
// prefixes. A bare IP becomes a host prefix (/32 for IPv4, /128 for IPv6).
func ParsePrefixList(raw string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			pfx, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid prefix %q", part)
			}
			out = append(out, pfx.Masked())
			continue
		}
		ip, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", part)
		}
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

// validatePublicURL accepts an http(s) origin with no path/query/fragment and
// no userinfo, so it can serve as the canonical external origin.
func validatePublicURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("must be an http(s) origin")
	}
	if u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not contain a path, query, fragment or credentials")
	}
	return nil
}

func DatabaseChoicePath(dataDir string) string { return filepath.Join(dataDir, "database.json") }
func LoadDatabaseChoice(dataDir string) (DatabaseChoice, error) {
	b, err := os.ReadFile(DatabaseChoicePath(dataDir))
	if os.IsNotExist(err) {
		return DatabaseChoice{Provider: "sqlite"}, nil
	}
	if err != nil {
		return DatabaseChoice{}, err
	}
	var c DatabaseChoice
	if err = json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Provider == "" {
		c.Provider = "sqlite"
	}
	return c, nil
}
func SaveDatabaseChoice(dataDir string, c DatabaseChoice) error {
	if c.Provider != "sqlite" && c.Provider != "postgres" {
		return fmt.Errorf("unsupported database provider")
	}
	if c.Provider == "postgres" && strings.TrimSpace(c.URL) == "" {
		return fmt.Errorf("PostgreSQL URL is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dataDir, 0o700)
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(DatabaseChoicePath(dataDir), append(b, '\n'), 0o600)
}
