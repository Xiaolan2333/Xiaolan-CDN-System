package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

type SSLCert struct {
	ID         int
	Name       string
	PublicKey  string
	PrivateKey string
}

type LuaScript struct {
	ID      int
	Name    string
	Content string
}

type Site struct {
	ID               int
	Name             string
	OriginScheme     string
	OriginAddress    string
	OriginHost       string
	HTTPSEnabled     bool
	SSLCertificateID *int
	HSTSEnabled      bool
	TLSVersions      string
	HTTP2Enabled     bool
	HTTP3Enabled     bool
	WebSocketEnabled bool
}

type SiteDomain struct {
	Domain string
}

type RedirectRule struct {
	FromPath     string
	ToURL        string
	RedirectType int
}

type CacheRule struct {
	Suffix    string
	CacheTime string
}

type PathOriginRule struct {
	PathPattern   string
	OriginScheme  string
	OriginAddress string
	OriginHost    string
	LuaScriptID   *int
	LuaContent    string
	LuaName       string
}

type LuaBinding struct {
	LuaScriptID int
	ScriptName  string
	Content     string
}

type IPBlacklist struct {
	IPAddress string
}

func main() {
	args := parseArgs()
	db := connectDB(args)
	defer db.Close()

	outputDir := args["output"]
	os.MkdirAll(outputDir, 0755)

	// Generate main nginx.conf
	generateMainConfig(outputDir)

	// Get all sites
	sites := getSites(db)
	for _, site := range sites {
		generateSiteConfig(db, site, outputDir)
	}

	// Export Lua scripts to output directory
	exportLuaScripts(db, outputDir)

	fmt.Println("Nginx config generation completed")
}

func parseArgs() map[string]string {
	args := make(map[string]string)
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "--") {
				args[key] = os.Args[i+1]
				i++
			} else {
				args[key] = "true"
			}
		}
	}
	return args
}

func connectDB(args map[string]string) *sql.DB {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true",
		args["db-user"], args["db-pass"], args["db-host"], args["db-port"], args["db-name"])
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	if err = db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to ping database: %v\n", err)
		os.Exit(1)
	}
	return db
}

func generateMainConfig(outputDir string) {
	config := `worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /opt/xiaolan-cdn/xiaolan-cdn-node/conf/mime.types;
    default_type application/octet-stream;

    lua_package_path "/opt/xiaolan-cdn/xiaolan-cdn-node/lib/lua/?.lua;;";

    proxy_cache_path /opt/xiaolan-cdn/xiaolan-cdn-node/cache/proxy levels=1:2 keys_zone=xiaolan_cache:100m max_size=10g inactive=7d use_temp_path=off;

    log_format xiaolan_cdn '$status $host "$request" $remote_addr [$time_local] '
                           '"$http_cookie" "$http_user_agent" $body_bytes_sent';

    access_log /opt/xiaolan-cdn/xiaolan-cdn-node/logs/access.log xiaolan_cdn buffer=64k flush=5s;
    error_log /opt/xiaolan-cdn/xiaolan-cdn-node/logs/error.log warn;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens on;

    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml text/javascript;

    include /opt/xiaolan-cdn/xiaolan-cdn-node/conf/sites-enabled/*.conf;
}
`
	os.WriteFile(filepath.Join(outputDir, "nginx.conf"), []byte(config), 0644)

	// Create sites-enabled directory
	os.MkdirAll(filepath.Join(outputDir, "sites-enabled"), 0755)
}

func getSites(db *sql.DB) []Site {
	rows, err := db.Query(`SELECT id, name, origin_scheme, origin_address, origin_host,
		https_enabled, ssl_certificate_id, hsts_enabled, tls_versions,
		http2_enabled, http3_enabled, websocket_enabled FROM sites`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to query sites: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var https, hsts, http2, http3, ws int
		if err := rows.Scan(&s.ID, &s.Name, &s.OriginScheme, &s.OriginAddress, &s.OriginHost,
			&https, &s.SSLCertificateID, &hsts, &s.TLSVersions, &http2, &http3, &ws); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to scan site: %v\n", err)
			continue
		}
		s.HTTPSEnabled = https == 1
		s.HSTSEnabled = hsts == 1
		s.HTTP2Enabled = http2 == 1
		s.HTTP3Enabled = http3 == 1
		s.WebSocketEnabled = ws == 1
		sites = append(sites, s)
	}
	return sites
}

func getSiteDomains(db *sql.DB, siteID int) []SiteDomain {
	rows, err := db.Query("SELECT domain FROM site_domains WHERE site_id=?", siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var domains []SiteDomain
	for rows.Next() {
		var d SiteDomain
		rows.Scan(&d.Domain)
		domains = append(domains, d)
	}
	return domains
}

func getRedirectRules(db *sql.DB, siteID int) []RedirectRule {
	rows, err := db.Query("SELECT from_path, to_url, redirect_type FROM redirect_rules WHERE site_id=? ORDER BY sort_order", siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var rules []RedirectRule
	for rows.Next() {
		var r RedirectRule
		rows.Scan(&r.FromPath, &r.ToURL, &r.RedirectType)
		rules = append(rules, r)
	}
	return rules
}

func getCacheRules(db *sql.DB, siteID int) []CacheRule {
	rows, err := db.Query("SELECT suffix, cache_time FROM cache_rules WHERE site_id=?", siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var rules []CacheRule
	for rows.Next() {
		var r CacheRule
		rows.Scan(&r.Suffix, &r.CacheTime)
		rules = append(rules, r)
	}
	return rules
}

func getPathOriginRules(db *sql.DB, siteID int) []PathOriginRule {
	rows, err := db.Query(`SELECT por.path_pattern, por.origin_scheme, por.origin_address, 
		COALESCE(por.origin_host,''), por.lua_script_id, COALESCE(ls.name,''), COALESCE(ls.content,'')
		FROM path_origin_rules por
		LEFT JOIN lua_scripts ls ON ls.id = por.lua_script_id
		WHERE por.site_id=? ORDER BY por.sort_order`, siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var rules []PathOriginRule
	for rows.Next() {
		var r PathOriginRule
		rows.Scan(&r.PathPattern, &r.OriginScheme, &r.OriginAddress, &r.OriginHost, &r.LuaScriptID, &r.LuaName, &r.LuaContent)
		rules = append(rules, r)
	}
	return rules
}

func getLuaBindings(db *sql.DB, siteID int) []LuaBinding {
	rows, err := db.Query(`SELECT slb.lua_script_id, ls.name, ls.content
		FROM site_lua_bindings slb
		JOIN lua_scripts ls ON ls.id = slb.lua_script_id
		WHERE slb.site_id=?`, siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var bindings []LuaBinding
	for rows.Next() {
		var b LuaBinding
		rows.Scan(&b.LuaScriptID, &b.ScriptName, &b.Content)
		bindings = append(bindings, b)
	}
	return bindings
}

func getIPBlacklist(db *sql.DB, siteID int) []IPBlacklist {
	rows, err := db.Query("SELECT ip_address FROM site_ip_blacklist WHERE site_id=?", siteID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []IPBlacklist
	for rows.Next() {
		var ip IPBlacklist
		rows.Scan(&ip.IPAddress)
		list = append(list, ip)
	}
	return list
}

func getSSLCertificate(db *sql.DB, certID int) *SSLCert {
	var c SSLCert
	err := db.QueryRow("SELECT id, name, public_key, private_key FROM ssl_certificates WHERE id=?", certID).
		Scan(&c.ID, &c.Name, &c.PublicKey, &c.PrivateKey)
	if err != nil {
		return nil
	}
	return &c
}

func generateSiteConfig(db *sql.DB, site Site, outputDir string) {
	domains := getSiteDomains(db, site.ID)
	redirectRules := getRedirectRules(db, site.ID)
	if len(domains) == 0 && len(redirectRules) == 0 {
		return
	}

	var domainNames []string
	for _, d := range domains {
		domainNames = append(domainNames, d.Domain)
	}
	sort.Strings(domainNames)
	serverName := strings.Join(domainNames, " ")

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Site: %s\n", site.Name))

	if len(domains) > 0 {
		sb.WriteString("server {\n")

		// Listen directives
		sb.WriteString("    listen 80;\n")
		if site.HTTPSEnabled {
			sb.WriteString("    listen 443 ssl;\n")
			if site.HTTP2Enabled {
				sb.WriteString("    http2 on;\n")
			}
			if site.HTTP3Enabled {
				sb.WriteString("    listen 443 quic reuseport;\n")
			}
		}
		sb.WriteString(fmt.Sprintf("    server_name %s;\n", serverName))

		// SSL certificate (only if HTTPS enabled)
		if site.HTTPSEnabled && site.SSLCertificateID != nil {
			cert := getSSLCertificate(db, *site.SSLCertificateID)
			if cert != nil {
				sb.WriteString(fmt.Sprintf("    ssl_certificate /opt/xiaolan-cdn/xiaolan-cdn-node/conf/%s.pem;\n", cert.Name))
				sb.WriteString(fmt.Sprintf("    ssl_certificate_key /opt/xiaolan-cdn/xiaolan-cdn-node/conf/%s.key;\n", cert.Name))
				os.WriteFile(filepath.Join(outputDir, cert.Name+".pem"), []byte(cert.PublicKey), 0644)
				os.WriteFile(filepath.Join(outputDir, cert.Name+".key"), []byte(cert.PrivateKey), 0600)
			}
		}

		// TLS settings
		if site.HTTPSEnabled {
			if site.TLSVersions != "" {
				sb.WriteString(fmt.Sprintf("    ssl_protocols %s;\n", site.TLSVersions))
			}
			sb.WriteString("    ssl_prefer_server_ciphers on;\n")
			sb.WriteString("    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n")
		}

		// HSTS
		if site.HSTSEnabled && site.HTTPSEnabled {
			sb.WriteString("    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n")
		}
		// HTTP3 alt-svc
		if site.HTTP3Enabled {
			sb.WriteString("    add_header Alt-Svc 'h3=\":443\"; ma=86400';\n")
		}

		// HTTP to HTTPS redirect
		if site.HTTPSEnabled {
			sb.WriteString("    if ($scheme = http) {\n")
			sb.WriteString("        return 301 https://$host$request_uri;\n")
			sb.WriteString("    }\n")
		}

	writeLocationBlock(&sb, site, db)
	sb.WriteString("}\n\n")
	}

	filename := fmt.Sprintf("site-%d-%s.conf", site.ID, sanitizeFilename(site.Name))
	os.WriteFile(filepath.Join(outputDir, "sites-enabled", filename), []byte(sb.String()), 0644)
}

func writeLocationBlock(sb *strings.Builder, site Site, db *sql.DB) {
	// Lua scripts (access phase)
	luaBindings := getLuaBindings(db, site.ID)
	for _, lb := range luaBindings {
		luaFile := fmt.Sprintf("%s.lua", lb.ScriptName)
		sb.WriteString(fmt.Sprintf("    access_by_lua_file /opt/xiaolan-cdn/xiaolan-cdn-node/conf/%s;\n", luaFile))
	}

	// IP blacklist
	ipList := getIPBlacklist(db, site.ID)
	if len(ipList) > 0 {
		for _, ip := range ipList {
			sb.WriteString(fmt.Sprintf("    deny %s;\n", ip.IPAddress))
		}
		sb.WriteString("    allow all;\n")
	}

	// Domain redirect rules (in-server, matched by $host)
	redirectRules := getRedirectRules(db, site.ID)
	for _, rule := range redirectRules {
		code := rule.RedirectType
		if code != 301 && code != 302 {
			code = 301
		}
		sb.WriteString(fmt.Sprintf("    if ($host = \"%s\") {\n", rule.FromPath))
		sb.WriteString(fmt.Sprintf("        return %d %s;\n", code, rule.ToURL))
		sb.WriteString("    }\n")
	}

	// Path-based origin rules
	pathRules := getPathOriginRules(db, site.ID)
	for _, rule := range pathRules {
		locationMod := ""
		pattern := rule.PathPattern
		if !strings.HasPrefix(rule.PathPattern, "~") && !strings.HasPrefix(rule.PathPattern, "=") {
			locationMod = "~ "
		}
		sb.WriteString(fmt.Sprintf("    location %s%s {\n", locationMod, pattern))
		sb.WriteString(fmt.Sprintf("        proxy_pass %s://%s;\n", rule.OriginScheme, rule.OriginAddress))
		sb.WriteString("        proxy_ssl_server_name on;\n")
		if rule.OriginScheme == "https" {
			sb.WriteString("        proxy_ssl_verify off;\n")
		}
		if rule.OriginHost != "" {
			sb.WriteString(fmt.Sprintf("        proxy_set_header Host %s;\n", rule.OriginHost))
		}
		if rule.LuaScriptID != nil && *rule.LuaScriptID > 0 {
			sb.WriteString(fmt.Sprintf("        access_by_lua_file /opt/xiaolan-cdn/xiaolan-cdn-node/conf/%s.lua;\n", rule.LuaName))
		}
		sb.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		sb.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		sb.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		sb.WriteString("    }\n")
	}

	// Cache rules - grouped by cache time
	cacheRules := getCacheRules(db, site.ID)
	if len(cacheRules) > 0 {
		// Group suffixes by cache time
		groups := make(map[string][]string)
		for _, r := range cacheRules {
			s := strings.TrimPrefix(r.Suffix, ".")
			groups[r.CacheTime] = append(groups[r.CacheTime], s)
		}
		for ct, suffixes := range groups {
			sb.WriteString(fmt.Sprintf("    location ~* \\.(%s)$ {\n", strings.Join(suffixes, "|")))
			if ct != "" {
				sb.WriteString(fmt.Sprintf("        expires %s;\n", ct))
			}
			sb.WriteString("        proxy_cache xiaolan_cache;\n")
			sb.WriteString("        proxy_cache_key $scheme$proxy_host$uri$is_args$args;\n")
			sb.WriteString("        proxy_cache_valid 200 301 302 1h;\n")
			sb.WriteString("        proxy_cache_valid 404 1m;\n")
			sb.WriteString("        proxy_cache_bypass $http_x_purge;\n")
			sb.WriteString("        proxy_no_cache $http_x_purge;\n")
			sb.WriteString(fmt.Sprintf("        proxy_pass %s://%s;\n", site.OriginScheme, site.OriginAddress))
			sb.WriteString("        proxy_ssl_server_name on;\n")
			if site.OriginScheme == "https" {
				sb.WriteString("        proxy_ssl_verify off;\n")
			}
			if site.OriginHost != "" {
				sb.WriteString(fmt.Sprintf("        proxy_set_header Host %s;\n", site.OriginHost))
			}
			sb.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
			sb.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
			sb.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
			sb.WriteString("    }\n")
		}
	}

	// Default location
	sb.WriteString("    location / {\n")
	sb.WriteString(fmt.Sprintf("        proxy_pass %s://%s;\n", site.OriginScheme, site.OriginAddress))
	sb.WriteString("        proxy_ssl_server_name on;\n")
	if site.OriginScheme == "https" {
		sb.WriteString("        proxy_ssl_verify off;\n")
	}
	if site.WebSocketEnabled {
		sb.WriteString("        proxy_http_version 1.1;\n")
		sb.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		sb.WriteString("        proxy_set_header Connection \"upgrade\";\n")
		sb.WriteString("        proxy_read_timeout 3600s;\n")
	} else {
		sb.WriteString("        proxy_read_timeout 60s;\n")
	}
	if site.OriginHost != "" {
		sb.WriteString(fmt.Sprintf("        proxy_set_header Host %s;\n", site.OriginHost))
	}
	sb.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	sb.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	sb.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	sb.WriteString("        proxy_buffering on;\n")
	sb.WriteString("        proxy_buffer_size 4k;\n")
	sb.WriteString("        proxy_buffers 8 4k;\n")
	sb.WriteString("        proxy_connect_timeout 10s;\n")
	sb.WriteString("        proxy_send_timeout 60s;\n")
	sb.WriteString("    }\n")
}

func sanitizeFilename(name string) string {
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)
	return result
}

// Export cert files to output directory
func exportCertFiles(db *sql.DB, outputDir string) {
	rows, err := db.Query("SELECT name, public_key, private_key FROM ssl_certificates")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name, pub, priv string
		rows.Scan(&name, &pub, &priv)
		os.WriteFile(filepath.Join(outputDir, name+".pem"), []byte(pub), 0644)
		os.WriteFile(filepath.Join(outputDir, name+".key"), []byte(priv), 0600)
	}
}

// Export lua scripts to output directory
func exportLuaScripts(db *sql.DB, outputDir string) {
	rows, err := db.Query("SELECT name, content FROM lua_scripts")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name, content string
		rows.Scan(&name, &content)
		os.WriteFile(filepath.Join(outputDir, name+".lua"), []byte(content), 0644)
	}
}

