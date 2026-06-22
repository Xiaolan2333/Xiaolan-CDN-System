package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ==================== Config ====================

type AdminConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SecurityConfig struct {
	LoginMaxAttempts   int `json:"login_max_attempts"`
	LoginWindowSeconds int `json:"login_window_seconds"`
	LoginBlockSeconds  int `json:"login_block_seconds"`
}

type DBConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type HTTPConfig struct {
	Listen string    `json:"listen"`
	TLS    TLSConfig `json:"tls"`
}

type NodeConfig struct {
	ConfigDir string `json:"config_dir"`
	LogsDir   string `json:"logs_dir"`
	NginxPath string `json:"nginx_path"`
}

type TmpConfig struct {
	ConfDir string `json:"conf_dir"`
	LogDir  string `json:"log_dir"`
}

type ScheduleConfig struct {
	SyncInterval       int `json:"sync_interval"`
	LogCollectInterval int `json:"log_collect_interval"`
}

type Config struct {
	Admin    AdminConfig    `json:"admin"`
	Security SecurityConfig `json:"security"`
	Database DBConfig       `json:"database"`
	HTTP     HTTPConfig     `json:"http"`
	Node     NodeConfig     `json:"node"`
	Tmp      TmpConfig      `json:"tmp"`
	Schedule ScheduleConfig `json:"schedule"`
}

var config Config
var db *sql.DB

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &config)
}

func (d DBConfig) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		d.User, d.Password, d.Host, d.Port, d.DBName)
}

// ==================== Auth / Token Store ====================

type tokenInfo struct {
	Username  string
	CreatedAt time.Time
}

var tokenStore sync.Map
var tokenDuration = 24 * time.Hour

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ==================== Brute-Force Rate Limiter ====================

type loginAttemptInfo struct {
	Count        int
	FirstAttempt time.Time
	BlockedUntil time.Time
}

var loginAttempts sync.Map

// Defaults: 5 attempts in 10min -> block 15min
func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

func isLoginBlocked(ip string) (bool, int) {
	val, ok := loginAttempts.Load(ip)
	if !ok {
		return false, 0
	}
	info := val.(*loginAttemptInfo)
	if !info.BlockedUntil.IsZero() && time.Now().Before(info.BlockedUntil) {
		remaining := int(time.Until(info.BlockedUntil).Seconds())
		return true, remaining
	}
	// Window expired, clean up
	window := time.Duration(config.Security.LoginWindowSeconds) * time.Second
	if config.Security.LoginWindowSeconds == 0 {
		window = 600 * time.Second
	}
	if time.Since(info.FirstAttempt) > window {
		loginAttempts.Delete(ip)
		return false, 0
	}
	return false, 0
}

func recordLoginAttempt(ip string, success bool) {
	if success {
		loginAttempts.Delete(ip)
		return
	}

	maxAttempts := config.Security.LoginMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	blockSec := config.Security.LoginBlockSeconds
	if blockSec <= 0 {
		blockSec = 900
	}

	val, _ := loginAttempts.LoadOrStore(ip, &loginAttemptInfo{Count: 0, FirstAttempt: time.Now()})
	info := val.(*loginAttemptInfo)
	info.Count++
	if info.Count >= maxAttempts {
		info.BlockedUntil = time.Now().Add(time.Duration(blockSec) * time.Second)
	}
}

func startLoginAttemptCleanup() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			window := time.Duration(config.Security.LoginWindowSeconds) * time.Second
			if window <= 0 {
				window = 600 * time.Second
			}
			blockSec := time.Duration(config.Security.LoginBlockSeconds) * time.Second
			if blockSec <= 0 {
				blockSec = 900 * time.Second
			}
			now := time.Now()
			loginAttempts.Range(func(key, value interface{}) bool {
				info := value.(*loginAttemptInfo)
				if time.Since(info.FirstAttempt) > window && (info.BlockedUntil.IsZero() || now.After(info.BlockedUntil)) {
					loginAttempts.Delete(key)
				}
				return true
			})
		}
	}()
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(APIResponse{Code: 401, Message: "unauthorized"})
			return
		}
		val, ok := tokenStore.Load(token)
		if !ok {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(APIResponse{Code: 401, Message: "invalid token"})
			return
		}
		info := val.(tokenInfo)
		if time.Since(info.CreatedAt) > tokenDuration {
			tokenStore.Delete(token)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(APIResponse{Code: 401, Message: "token expired"})
			return
		}
		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Code: 405, Message: "Method not allowed"})
		return
	}

	clientIP := getClientIP(r)

	// Check rate limit
	if blocked, remaining := isLoginBlocked(clientIP); blocked {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(APIResponse{Code: 429, Message: fmt.Sprintf("Too many attempts, try again in %d seconds", remaining)})
		writeSystemLog("WARN", "system", "Login blocked (rate limit)", clientIP)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Code: 400, Message: "Invalid JSON"})
		return
	}
	if req.Username != config.Admin.Username || req.Password != config.Admin.Password {
		recordLoginAttempt(clientIP, false)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(APIResponse{Code: 401, Message: "Invalid credentials"})
		return
	}
	recordLoginAttempt(clientIP, true)
	token := generateToken()
	tokenStore.Store(token, tokenInfo{Username: req.Username, CreatedAt: time.Now()})
	writeSystemLog("INFO", "system", "Admin login", req.Username)
	successResponse(w, map[string]string{"token": token})
}

func handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	successResponse(w, map[string]string{"status": "authenticated"})
}

// Periodic token cleanup
func startTokenCleanup() {
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			tokenStore.Range(func(key, value interface{}) bool {
				info := value.(tokenInfo)
				if time.Since(info.CreatedAt) > tokenDuration {
					tokenStore.Delete(key)
				}
				return true
			})
		}
	}()
}

// ==================== Database ====================

func initDB() {
	var err error
	db, err = sql.Open("mysql", config.Database.DSN())
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	for {
		if err = db.Ping(); err == nil {
			break
		}
		log.Printf("Database not available: %v, retrying in 5s...", err)
		time.Sleep(5 * time.Second)
	}
	log.Println("Database connected")
}

// ==================== Models ====================

type SSLCertificate struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type LuaScript struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Node struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Site struct {
	ID               int       `json:"id"`
	Name             string    `json:"name"`
	OriginScheme     string    `json:"origin_scheme"`
	OriginAddress    string    `json:"origin_address"`
	OriginHost       string    `json:"origin_host"`
	HTTPSEnabled     bool      `json:"https_enabled"`
	SSLCertificateID *int      `json:"ssl_certificate_id"`
	HSTSEnabled      bool      `json:"hsts_enabled"`
	TLSVersions      string    `json:"tls_versions"`
	HTTP2Enabled     bool      `json:"http2_enabled"`
	HTTP3Enabled     bool      `json:"http3_enabled"`
	WebSocketEnabled bool      `json:"websocket_enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type SiteDomain struct {
	ID     int    `json:"id"`
	SiteID int    `json:"site_id"`
	Domain string `json:"domain"`
}

type RedirectRule struct {
	ID           int    `json:"id"`
	SiteID       int    `json:"site_id"`
	FromPath     string `json:"from_path"`
	ToURL        string `json:"to_url"`
	RedirectType int    `json:"redirect_type"`
	SortOrder    int    `json:"sort_order"`
}

type CacheRule struct {
	ID        int    `json:"id"`
	SiteID    int    `json:"site_id"`
	Suffix    string `json:"suffix"`
	CacheTime string `json:"cache_time"`
}

type PathOriginRule struct {
	ID            int    `json:"id"`
	SiteID        int    `json:"site_id"`
	PathPattern   string `json:"path_pattern"`
	OriginScheme  string `json:"origin_scheme"`
	OriginAddress string `json:"origin_address"`
	OriginHost    string `json:"origin_host"`
	LuaScriptID   *int   `json:"lua_script_id"`
	SortOrder     int    `json:"sort_order"`
}

type SiteLuaBinding struct {
	ID          int `json:"id"`
	SiteID      int `json:"site_id"`
	LuaScriptID int `json:"lua_script_id"`
}

type SiteIPBlacklist struct {
	ID        int    `json:"id"`
	SiteID    int    `json:"site_id"`
	IPAddress string `json:"ip_address"`
}

type AccessLog struct {
	ID          int64     `json:"id"`
	NodeID      int       `json:"node_id"`
	SiteID      *int      `json:"site_id"`
	StatusCode  int       `json:"status_code"`
	Domain      string    `json:"domain"`
	RequestPath string    `json:"request_path"`
	ClientIP    string    `json:"client_ip"`
	RequestTime time.Time `json:"request_time"`
	Cookie      string    `json:"cookie"`
	UserAgent   string    `json:"user_agent"`
	BytesSent   int64     `json:"bytes_sent"`
}

type SystemLog struct {
	ID        int64     `json:"id"`
	Level     string    `json:"level"`
	Category  string    `json:"category"`
	Message   string    `json:"message"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// ==================== API Response ====================

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func jsonResponse(w http.ResponseWriter, code int, msg string, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp := APIResponse{Code: code, Message: msg, Data: data}
	json.NewEncoder(w).Encode(resp)
}

func successResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp := APIResponse{Code: 0, Message: "success", Data: data}
	json.NewEncoder(w).Encode(resp)
}

func errorResponse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	resp := APIResponse{Code: code, Message: msg}
	json.NewEncoder(w).Encode(resp)
}

// ==================== System Logger ====================

func writeSystemLog(level, category, message, detail string) {
	_, err := db.Exec("INSERT INTO system_logs (level, category, message, detail) VALUES (?,?,?,?)",
		level, category, message, detail)
	if err != nil {
		log.Printf("Failed to write system log: %v", err)
	}
}

// ==================== Mark Config Changed ====================

var syncRunningMu sync.Mutex
var syncRunning bool

var dirtyCount int32

func markConfigChanged() {
	atomic.AddInt32(&dirtyCount, 1)
	go doFullSync()
}

func hasConfigChanged() bool {
	return atomic.LoadInt32(&dirtyCount) > 0
}

func clearDirty() {
	atomic.AddInt32(&dirtyCount, -1)
}

// ==================== Sync Operations ====================

func doFullSync() {
	syncRunningMu.Lock()
	if syncRunning {
		syncRunningMu.Unlock()
		log.Println("Sync already in progress, skipping")
		return
	}
	syncRunning = true
	syncRunningMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("doFullSync panic recovered: %v", r)
		}
		syncRunningMu.Lock()
		syncRunning = false
		syncRunningMu.Unlock()
	}()

	log.Println("Starting full sync...")
	writeSystemLog("INFO", "sync", "Full sync started", "")

	// Clean tmp dirs
	os.RemoveAll(config.Tmp.ConfDir)
	os.RemoveAll(config.Tmp.LogDir)
	os.MkdirAll(config.Tmp.ConfDir, 0755)
	os.MkdirAll(config.Tmp.LogDir, 0755)

	// Step 1: Generate Nginx config
	ngxgenPath := filepath.Join(".", "backend", "ngxgen", "main")
	cmd := exec.Command(ngxgenPath, "--db-host", config.Database.Host,
		"--db-port", strconv.Itoa(config.Database.Port),
		"--db-user", config.Database.User,
		"--db-pass", config.Database.Password,
		"--db-name", config.Database.DBName,
		"--output", config.Tmp.ConfDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("ngxgen failed: %v, output: %s", err, string(output))
		writeSystemLog("ERROR", "sync", "Nginx config generation failed", fmt.Sprintf("%v: %s", err, string(output)))
		return
	}
	log.Printf("ngxgen output: %s", string(output))

	// Step 2: Push to all nodes
	nodes, err := getAllNodes()
	if err != nil {
		log.Printf("Failed to get nodes: %v", err)
		writeSystemLog("ERROR", "sync", "Failed to get node list", err.Error())
		return
	}
	if len(nodes) == 0 {
		log.Println("No nodes configured, skipping push")
		writeSystemLog("WARN", "sync", "No nodes configured", "")
		return
	}

	pushPath := filepath.Join(".", "backend", "push", "main")

	var pushArgs []string
	pushArgs = append(pushArgs, "--source", config.Tmp.ConfDir)
	pushArgs = append(pushArgs, "--target", config.Node.ConfigDir)
	pushArgs = append(pushArgs, "--nginx", config.Node.NginxPath)

	nodesJSON, _ := json.Marshal(nodes)
	pushArgs = append(pushArgs, "--nodes", string(nodesJSON))

	cmd2 := exec.Command(pushPath, pushArgs...)
	output2, err := cmd2.CombinedOutput()
	if err != nil {
		log.Printf("push failed: %v, output: %s", err, string(output2))
		writeSystemLog("ERROR", "sync", "Push to nodes failed", fmt.Sprintf("%v: %s", err, string(output2)))
	} else {
		log.Printf("push output: %s", string(output2))
		writeSystemLog("INFO", "sync", "Push to nodes completed", string(output2))
	}

	// Step 3: Clean tmp
	os.RemoveAll(config.Tmp.ConfDir)
	os.RemoveAll(config.Tmp.LogDir)

	clearDirty()
	writeSystemLog("INFO", "sync", "Full sync completed", "")
	// If another change happened during sync, re-trigger
	if hasConfigChanged() {
		go doFullSync()
	}
}

func doLogCollect() {
	log.Println("Starting log collection...")
	writeSystemLog("INFO", "log_collect", "Log collection started", "")

	os.RemoveAll(config.Tmp.LogDir)
	os.MkdirAll(config.Tmp.LogDir, 0755)

	nodes, err := getAllNodes()
	if err != nil {
		log.Printf("Failed to get nodes: %v", err)
		writeSystemLog("ERROR", "log_collect", "Failed to get node list", err.Error())
		return
	}

	logsPath := filepath.Join(".", "backend", "logs", "main")

	nodesJSON, _ := json.Marshal(nodes)

	cmd := exec.Command(logsPath,
		"--db-host", config.Database.Host,
		"--db-port", strconv.Itoa(config.Database.Port),
		"--db-user", config.Database.User,
		"--db-pass", config.Database.Password,
		"--db-name", config.Database.DBName,
		"--log-dir", config.Node.LogsDir,
		"--tmp-dir", config.Tmp.LogDir,
		"--nodes-data", string(nodesJSON))
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("logs collect failed: %v, output: %s", err, string(output))
		writeSystemLog("ERROR", "log_collect", "Log collection failed", fmt.Sprintf("%v: %s", err, string(output)))
	} else {
		log.Printf("logs collect output: %s", string(output))
		writeSystemLog("INFO", "log_collect", "Log collection completed", string(output))
	}

	os.RemoveAll(config.Tmp.LogDir)
}

func getAllNodes() ([]Node, error) {
	rows, err := db.Query("SELECT id, name, host, port, username, password FROM nodes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.Host, &n.Port, &n.Username, &n.Password); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// ==================== HTTPS Redirection ====================

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// ==================== SSL Certificate Handlers ====================

func handleSSLCerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, name, public_key, private_key, created_at, updated_at FROM ssl_certificates ORDER BY id")
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var certs []SSLCertificate
		for rows.Next() {
			var c SSLCertificate
			if err := rows.Scan(&c.ID, &c.Name, &c.PublicKey, &c.PrivateKey, &c.CreatedAt, &c.UpdatedAt); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			certs = append(certs, c)
		}
		successResponse(w, certs)
	case "POST":
		var c SSLCertificate
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if c.Name == "" || c.PublicKey == "" || c.PrivateKey == "" {
			errorResponse(w, 400, "name, public_key, private_key are required")
			return
		}
		_, err := db.Exec("INSERT INTO ssl_certificates (name, public_key, private_key) VALUES (?,?,?)",
			c.Name, c.PublicKey, c.PrivateKey)
		if err != nil {
			if strings.Contains(err.Error(), "Duplicate") {
				errorResponse(w, 400, "Certificate name already exists")
				return
			}
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "ssl", "Certificate created", c.Name)
		markConfigChanged()
		successResponse(w, nil)
	case "PUT":
		var c SSLCertificate
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if c.ID == 0 {
			errorResponse(w, 400, "id is required")
			return
		}
		_, err := db.Exec("UPDATE ssl_certificates SET name=?, public_key=?, private_key=? WHERE id=?",
			c.Name, c.PublicKey, c.PrivateKey, c.ID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "ssl", "Certificate updated", c.Name)
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

func handleSSLCert(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/ssl/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		errorResponse(w, 400, "Invalid ID")
		return
	}
	if r.Method == "DELETE" {
		_, err := db.Exec("DELETE FROM ssl_certificates WHERE id=?", id)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "ssl", "Certificate deleted", fmt.Sprintf("id=%d", id))
		markConfigChanged()
		successResponse(w, nil)
	} else {
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Lua Script Handlers ====================

func handleLuaScripts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, name, content, created_at, updated_at FROM lua_scripts ORDER BY id")
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var scripts []LuaScript
		for rows.Next() {
			var s LuaScript
			if err := rows.Scan(&s.ID, &s.Name, &s.Content, &s.CreatedAt, &s.UpdatedAt); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			scripts = append(scripts, s)
		}
		successResponse(w, scripts)
	case "POST":
		var s LuaScript
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if s.Name == "" || s.Content == "" {
			errorResponse(w, 400, "name and content are required")
			return
		}
		_, err := db.Exec("INSERT INTO lua_scripts (name, content) VALUES (?,?)", s.Name, s.Content)
		if err != nil {
			if strings.Contains(err.Error(), "Duplicate") {
				errorResponse(w, 400, "Script name already exists")
				return
			}
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "lua", "Lua script created", s.Name)
		markConfigChanged()
		successResponse(w, nil)
	case "PUT":
		var s LuaScript
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if s.ID == 0 {
			errorResponse(w, 400, "id is required")
			return
		}
		_, err := db.Exec("UPDATE lua_scripts SET name=?, content=? WHERE id=?", s.Name, s.Content, s.ID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "lua", "Lua script updated", s.Name)
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

func handleLuaScript(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/lua/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		errorResponse(w, 400, "Invalid ID")
		return
	}
	if r.Method == "DELETE" {
		_, err := db.Exec("DELETE FROM lua_scripts WHERE id=?", id)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "lua", "Lua script deleted", fmt.Sprintf("id=%d", id))
		markConfigChanged()
		successResponse(w, nil)
	} else {
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Node Handlers ====================

func handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, name, host, port, username, password, created_at, updated_at FROM nodes ORDER BY id")
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var nodes []Node
		for rows.Next() {
			var n Node
			if err := rows.Scan(&n.ID, &n.Name, &n.Host, &n.Port, &n.Username, &n.Password, &n.CreatedAt, &n.UpdatedAt); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			nodes = append(nodes, n)
		}
		successResponse(w, nodes)
	case "POST":
		var n Node
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if n.Name == "" || n.Host == "" || n.Password == "" {
			errorResponse(w, 400, "name, host, password are required")
			return
		}
		if n.Port == 0 {
			n.Port = 22
		}
		if n.Username == "" {
			n.Username = "root"
		}
		_, err := db.Exec("INSERT INTO nodes (name, host, port, username, password) VALUES (?,?,?,?,?)",
			n.Name, n.Host, n.Port, n.Username, n.Password)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "node", "Node created", n.Name)
		markConfigChanged()
		successResponse(w, nil)
	case "PUT":
		var n Node
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if n.ID == 0 {
			errorResponse(w, 400, "id is required")
			return
		}
		_, err := db.Exec("UPDATE nodes SET name=?, host=?, port=?, username=?, password=? WHERE id=?",
			n.Name, n.Host, n.Port, n.Username, n.Password, n.ID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "node", "Node updated", n.Name)
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

func handleNode(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/node/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		errorResponse(w, 400, "Invalid ID")
		return
	}
	if r.Method == "DELETE" {
		_, err := db.Exec("DELETE FROM nodes WHERE id=?", id)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "node", "Node deleted", fmt.Sprintf("id=%d", id))
		markConfigChanged()
		successResponse(w, nil)
	} else {
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Site Handlers ====================

func handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		rows, err := db.Query(`SELECT id, name, origin_scheme, origin_address, origin_host,
			https_enabled, ssl_certificate_id, hsts_enabled, tls_versions,
			http2_enabled, http3_enabled, websocket_enabled, created_at, updated_at FROM sites ORDER BY id`)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var sites []Site
		for rows.Next() {
			var s Site
			var https int
			var hsts int
			var http2 int
			var http3 int
			var ws int
			if err := rows.Scan(&s.ID, &s.Name, &s.OriginScheme, &s.OriginAddress, &s.OriginHost,
				&https, &s.SSLCertificateID, &hsts, &s.TLSVersions,
				&http2, &http3, &ws, &s.CreatedAt, &s.UpdatedAt); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			s.HTTPSEnabled = https == 1
			s.HSTSEnabled = hsts == 1
			s.HTTP2Enabled = http2 == 1
			s.HTTP3Enabled = http3 == 1
			s.WebSocketEnabled = ws == 1
			sites = append(sites, s)
		}
		successResponse(w, sites)
	case "POST":
		var s Site
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if s.Name == "" || s.OriginAddress == "" {
			errorResponse(w, 400, "name and origin_address are required")
			return
		}
		if s.HTTPSEnabled && (s.SSLCertificateID == nil || *s.SSLCertificateID == 0) {
			errorResponse(w, 400, "HTTPS requires an SSL certificate")
			return
		}
		if s.OriginScheme == "" {
			s.OriginScheme = "http"
		}
		https := boolToInt(s.HTTPSEnabled)
		hsts := boolToInt(s.HSTSEnabled)
		http2 := boolToInt(s.HTTP2Enabled)
		http3 := boolToInt(s.HTTP3Enabled)
		ws := boolToInt(s.WebSocketEnabled)
		result, err := db.Exec(`INSERT INTO sites (name, origin_scheme, origin_address, origin_host,
			https_enabled, ssl_certificate_id, hsts_enabled, tls_versions,
			http2_enabled, http3_enabled, websocket_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			s.Name, s.OriginScheme, s.OriginAddress, s.OriginHost,
			https, s.SSLCertificateID, hsts, s.TLSVersions, http2, http3, ws)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		id, _ := result.LastInsertId()
		writeSystemLog("INFO", "site", "Site created", fmt.Sprintf("%s (id=%d)", s.Name, id))
		markConfigChanged()
		successResponse(w, map[string]int64{"id": id})
	case "PUT":
		var s Site
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if s.ID == 0 {
			errorResponse(w, 400, "id is required")
			return
		}
		if s.HTTPSEnabled && (s.SSLCertificateID == nil || *s.SSLCertificateID == 0) {
			errorResponse(w, 400, "HTTPS requires an SSL certificate")
			return
		}
		https := boolToInt(s.HTTPSEnabled)
		hsts := boolToInt(s.HSTSEnabled)
		http2 := boolToInt(s.HTTP2Enabled)
		http3 := boolToInt(s.HTTP3Enabled)
		ws := boolToInt(s.WebSocketEnabled)
		_, err := db.Exec(`UPDATE sites SET name=?, origin_scheme=?, origin_address=?, origin_host=?,
			https_enabled=?, ssl_certificate_id=?, hsts_enabled=?, tls_versions=?,
			http2_enabled=?, http3_enabled=?, websocket_enabled=? WHERE id=?`,
			s.Name, s.OriginScheme, s.OriginAddress, s.OriginHost,
			https, s.SSLCertificateID, hsts, s.TLSVersions, http2, http3, ws, s.ID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "site", "Site updated", s.Name)
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

func handleSite(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/site/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		errorResponse(w, 400, "Invalid ID")
		return
	}
	if r.Method == "DELETE" {
		_, err := db.Exec("DELETE FROM sites WHERE id=?", id)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "site", "Site deleted", fmt.Sprintf("id=%d", id))
		markConfigChanged()
		successResponse(w, nil)
	} else {
		errorResponse(w, 405, "Method not allowed")
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ==================== Site Domain Handlers ====================

func handleSiteDomains(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/site/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "domains" {
		errorResponse(w, 400, "Invalid URL")
		return
	}
	siteID, err := strconv.Atoi(pathParts[0])
	if err != nil {
		errorResponse(w, 400, "Invalid site ID")
		return
	}

	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, site_id, domain FROM site_domains WHERE site_id=? ORDER BY id", siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var domains []SiteDomain
		for rows.Next() {
			var d SiteDomain
			if err := rows.Scan(&d.ID, &d.SiteID, &d.Domain); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			domains = append(domains, d)
		}
		successResponse(w, domains)
	case "POST":
		var d SiteDomain
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if d.Domain == "" {
			errorResponse(w, 400, "domain is required")
			return
		}
		_, err := db.Exec("INSERT INTO site_domains (site_id, domain) VALUES (?,?)", siteID, d.Domain)
		if err != nil {
			if strings.Contains(err.Error(), "Duplicate") {
				errorResponse(w, 400, "Domain already exists")
				return
			}
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "site", "Domain added", fmt.Sprintf("site=%d domain=%s", siteID, d.Domain))
		markConfigChanged()
		successResponse(w, nil)
	case "DELETE":
		if len(pathParts) < 3 {
			errorResponse(w, 400, "Missing resource ID in URL")
			return
		}
		idStr := pathParts[2]
		id, _ := strconv.Atoi(idStr)
		_, err := db.Exec("DELETE FROM site_domains WHERE id=? AND site_id=?", id, siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Redirect Rule Handlers ====================

func handleRedirectRules(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/site/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "redirects" {
		errorResponse(w, 400, "Invalid URL")
		return
	}
	siteID, err := strconv.Atoi(pathParts[0])
	if err != nil {
		errorResponse(w, 400, "Invalid site ID")
		return
	}

	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, site_id, from_path, to_url, redirect_type, sort_order FROM redirect_rules WHERE site_id=? ORDER BY sort_order", siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var rules []RedirectRule
		for rows.Next() {
			var rl RedirectRule
			if err := rows.Scan(&rl.ID, &rl.SiteID, &rl.FromPath, &rl.ToURL, &rl.RedirectType, &rl.SortOrder); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			rules = append(rules, rl)
		}
		successResponse(w, rules)
	case "POST":
		var rl RedirectRule
		if err := json.NewDecoder(r.Body).Decode(&rl); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if rl.FromPath == "" || rl.ToURL == "" {
			errorResponse(w, 400, "from_path and to_url are required")
			return
		}
		// Validate that the source domain belongs to this site
		var domainCount int
		db.QueryRow("SELECT COUNT(*) FROM site_domains WHERE site_id=? AND domain=?", siteID, rl.FromPath).Scan(&domainCount)
		if domainCount == 0 {
			errorResponse(w, 400, "来源域名不属于该站点，请先在域名管理中添加")
			return
		}
		if rl.RedirectType == 0 {
			rl.RedirectType = 301
		}
		_, err := db.Exec("INSERT INTO redirect_rules (site_id, from_path, to_url, redirect_type, sort_order) VALUES (?,?,?,?,?)",
			siteID, rl.FromPath, rl.ToURL, rl.RedirectType, rl.SortOrder)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		writeSystemLog("INFO", "site", "Redirect rule added", fmt.Sprintf("site=%d from=%s", siteID, rl.FromPath))
		markConfigChanged()
		successResponse(w, nil)
	case "DELETE":
		if len(pathParts) < 3 {
			errorResponse(w, 400, "Missing resource ID in URL")
			return
		}
		idStr := pathParts[2]
		id, _ := strconv.Atoi(idStr)
		_, err := db.Exec("DELETE FROM redirect_rules WHERE id=? AND site_id=?", id, siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Cache Rule Handlers ====================

func handleCacheRules(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/site/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "cache" {
		errorResponse(w, 400, "Invalid URL")
		return
	}
	siteID, err := strconv.Atoi(pathParts[0])
	if err != nil {
		errorResponse(w, 400, "Invalid site ID")
		return
	}

	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, site_id, suffix, cache_time FROM cache_rules WHERE site_id=? ORDER BY id", siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var rules []CacheRule
		for rows.Next() {
			var cr CacheRule
			if err := rows.Scan(&cr.ID, &cr.SiteID, &cr.Suffix, &cr.CacheTime); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			rules = append(rules, cr)
		}
		successResponse(w, rules)
	case "POST":
		var cr CacheRule
		if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if cr.Suffix == "" {
			errorResponse(w, 400, "suffix is required")
			return
		}
		_, err := db.Exec("INSERT INTO cache_rules (site_id, suffix, cache_time) VALUES (?,?,?)",
			siteID, cr.Suffix, cr.CacheTime)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	case "DELETE":
		if len(pathParts) < 3 {
			errorResponse(w, 400, "Missing resource ID in URL")
			return
		}
		idStr := pathParts[2]
		id, _ := strconv.Atoi(idStr)
		_, err := db.Exec("DELETE FROM cache_rules WHERE id=? AND site_id=?", id, siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Path Origin Rule Handlers ====================

func handlePathOriginRules(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/site/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "pathorigin" {
		errorResponse(w, 400, "Invalid URL")
		return
	}
	siteID, err := strconv.Atoi(pathParts[0])
	if err != nil {
		errorResponse(w, 400, "Invalid site ID")
		return
	}

	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, site_id, path_pattern, origin_scheme, origin_address, origin_host, lua_script_id, sort_order FROM path_origin_rules WHERE site_id=? ORDER BY sort_order", siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var rules []PathOriginRule
		for rows.Next() {
			var pr PathOriginRule
			if err := rows.Scan(&pr.ID, &pr.SiteID, &pr.PathPattern, &pr.OriginScheme, &pr.OriginAddress, &pr.OriginHost, &pr.LuaScriptID, &pr.SortOrder); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			rules = append(rules, pr)
		}
		successResponse(w, rules)
	case "POST":
		var pr PathOriginRule
		if err := json.NewDecoder(r.Body).Decode(&pr); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if pr.PathPattern == "" || pr.OriginAddress == "" {
			errorResponse(w, 400, "path_pattern and origin_address are required")
			return
		}
		if pr.OriginScheme == "" {
			pr.OriginScheme = "http"
		}
		_, err := db.Exec("INSERT INTO path_origin_rules (site_id, path_pattern, origin_scheme, origin_address, origin_host, lua_script_id, sort_order) VALUES (?,?,?,?,?,?,?)",
			siteID, pr.PathPattern, pr.OriginScheme, pr.OriginAddress, pr.OriginHost, pr.LuaScriptID, pr.SortOrder)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	case "DELETE":
		if len(pathParts) < 3 {
			errorResponse(w, 400, "Missing resource ID in URL")
			return
		}
		idStr := pathParts[2]
		id, _ := strconv.Atoi(idStr)
		_, err := db.Exec("DELETE FROM path_origin_rules WHERE id=? AND site_id=?", id, siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Lua Binding Handlers ====================

func handleLuaBindings(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/site/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "lua" {
		errorResponse(w, 400, "Invalid URL")
		return
	}
	siteID, err := strconv.Atoi(pathParts[0])
	if err != nil {
		errorResponse(w, 400, "Invalid site ID")
		return
	}

	switch r.Method {
	case "GET":
		var bindingID int
		var luaScriptID int
		var scriptName string
		err := db.QueryRow(`SELECT slb.id, slb.lua_script_id, ls.name
			FROM site_lua_bindings slb
			JOIN lua_scripts ls ON ls.id = slb.lua_script_id
			WHERE slb.site_id=? LIMIT 1`, siteID).Scan(&bindingID, &luaScriptID, &scriptName)
		if err != nil {
			successResponse(w, nil)
			return
		}
		successResponse(w, map[string]interface{}{
			"id": bindingID, "site_id": siteID, "lua_script_id": luaScriptID, "script_name": scriptName,
		})
	case "POST":
		var b SiteLuaBinding
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		// Remove all existing bindings, then insert the new one
		db.Exec("DELETE FROM site_lua_bindings WHERE site_id=?", siteID)
		if b.LuaScriptID > 0 {
			_, err := db.Exec("INSERT INTO site_lua_bindings (site_id, lua_script_id) VALUES (?,?)", siteID, b.LuaScriptID)
			if err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
		}
		markConfigChanged()
		successResponse(w, nil)
	case "DELETE":
		db.Exec("DELETE FROM site_lua_bindings WHERE site_id=?", siteID)
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== IP Blacklist Handlers ====================

func handleIPBlacklist(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/site/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "blacklist" {
		errorResponse(w, 400, "Invalid URL")
		return
	}
	siteID, err := strconv.Atoi(pathParts[0])
	if err != nil {
		errorResponse(w, 400, "Invalid site ID")
		return
	}

	switch r.Method {
	case "GET":
		rows, err := db.Query("SELECT id, site_id, ip_address FROM site_ip_blacklist WHERE site_id=? ORDER BY id", siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		defer rows.Close()
		var list []SiteIPBlacklist
		for rows.Next() {
			var ip SiteIPBlacklist
			if err := rows.Scan(&ip.ID, &ip.SiteID, &ip.IPAddress); err != nil {
				errorResponse(w, 500, err.Error())
				return
			}
			list = append(list, ip)
		}
		successResponse(w, list)
	case "POST":
		var ip SiteIPBlacklist
		if err := json.NewDecoder(r.Body).Decode(&ip); err != nil {
			errorResponse(w, 400, "Invalid JSON")
			return
		}
		if ip.IPAddress == "" {
			errorResponse(w, 400, "ip_address is required")
			return
		}
		_, err := db.Exec("INSERT INTO site_ip_blacklist (site_id, ip_address) VALUES (?,?)", siteID, ip.IPAddress)
		if err != nil {
			if strings.Contains(err.Error(), "Duplicate") {
				errorResponse(w, 400, "IP already in blacklist")
				return
			}
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	case "DELETE":
		if len(pathParts) < 3 {
			errorResponse(w, 400, "Missing resource ID in URL")
			return
		}
		idStr := pathParts[2]
		id, _ := strconv.Atoi(idStr)
		_, err := db.Exec("DELETE FROM site_ip_blacklist WHERE id=? AND site_id=?", id, siteID)
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		markConfigChanged()
		successResponse(w, nil)
	default:
		errorResponse(w, 405, "Method not allowed")
	}
}

// ==================== Log Handlers ====================

func handleAccessLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		before := r.URL.Query().Get("before")
		var result sql.Result
		var err error
		if before == "all" {
			result, err = db.Exec("DELETE FROM access_logs")
		} else {
			days, _ := strconv.Atoi(before)
			if days <= 0 {
				days = 1
			}
			result, err = db.Exec("DELETE FROM access_logs WHERE request_time < DATE_SUB(NOW(), INTERVAL ? DAY)", days)
		}
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		n, _ := result.RowsAffected()
		writeSystemLog("INFO", "system", "Access logs deleted", fmt.Sprintf("before=%s, rows=%d", before, n))
		successResponse(w, map[string]int64{"deleted": n})
		return
	}
	if r.Method != "GET" {
		errorResponse(w, 405, "Method not allowed")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	domain := r.URL.Query().Get("domain")
	statusCode := r.URL.Query().Get("status_code")
	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	where := "WHERE 1=1"
	var args []interface{}
	if domain != "" {
		where += " AND domain LIKE ?"
		args = append(args, "%"+domain+"%")
	}
	if statusCode != "" {
		where += " AND status_code = ?"
		args = append(args, statusCode)
	}
	if startTime != "" {
		where += " AND request_time >= ?"
		args = append(args, startTime)
	}
	if endTime != "" {
		where += " AND request_time <= ?"
		args = append(args, endTime)
	}

	var total int64
	countQuery := "SELECT COUNT(*) FROM access_logs " + where
	db.QueryRow(countQuery, args...).Scan(&total)

	offset := (page - 1) * pageSize
	dataQuery := "SELECT id, node_id, site_id, status_code, domain, request_path, client_ip, request_time, COALESCE(cookie,''), COALESCE(user_agent,''), bytes_sent FROM access_logs " + where + " ORDER BY request_time DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := db.Query(dataQuery, args...)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}
	defer rows.Close()

	var logs []AccessLog
	for rows.Next() {
		var l AccessLog
		if err := rows.Scan(&l.ID, &l.NodeID, &l.SiteID, &l.StatusCode, &l.Domain, &l.RequestPath, &l.ClientIP, &l.RequestTime, &l.Cookie, &l.UserAgent, &l.BytesSent); err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		logs = append(logs, l)
	}

	successResponse(w, map[string]interface{}{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"data":      logs,
	})
}

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		before := r.URL.Query().Get("before")
		var result sql.Result
		var err error
		if before == "all" {
			result, err = db.Exec("DELETE FROM system_logs")
		} else {
			days, _ := strconv.Atoi(before)
			if days <= 0 {
				days = 1
			}
			result, err = db.Exec("DELETE FROM system_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)", days)
		}
		if err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		n, _ := result.RowsAffected()
		writeSystemLog("INFO", "system", "System logs deleted", fmt.Sprintf("before=%s, rows=%d", before, n))
		successResponse(w, map[string]int64{"deleted": n})
		return
	}
	if r.Method != "GET" {
		errorResponse(w, 405, "Method not allowed")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	level := r.URL.Query().Get("level")
	category := r.URL.Query().Get("category")

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	where := "WHERE 1=1"
	var args []interface{}
	if level != "" {
		where += " AND level = ?"
		args = append(args, level)
	}
	if category != "" {
		where += " AND category = ?"
		args = append(args, category)
	}

	var total int64
	countQuery := "SELECT COUNT(*) FROM system_logs " + where
	db.QueryRow(countQuery, args...).Scan(&total)

	offset := (page - 1) * pageSize
	dataQuery := "SELECT id, level, category, message, COALESCE(detail,''), created_at FROM system_logs " + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := db.Query(dataQuery, args...)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}
	defer rows.Close()

	var logs []SystemLog
	for rows.Next() {
		var l SystemLog
		if err := rows.Scan(&l.ID, &l.Level, &l.Category, &l.Message, &l.Detail, &l.CreatedAt); err != nil {
			errorResponse(w, 500, err.Error())
			return
		}
		logs = append(logs, l)
	}

	successResponse(w, map[string]interface{}{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"data":      logs,
	})
}

// ==================== Actions ====================

func handleForceSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errorResponse(w, 405, "Method not allowed")
		return
	}
	go doFullSync()
	successResponse(w, map[string]string{"status": "sync started"})
}

func handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errorResponse(w, 405, "Method not allowed")
		return
	}
	var req struct {
		SiteID int    `json:"site_id"`
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, 400, "Invalid JSON")
		return
	}
	if req.SiteID == 0 {
		errorResponse(w, 400, "site_id is required")
		return
	}

	// Get site domains
	rows, err := db.Query("SELECT domain FROM site_domains WHERE site_id=?", req.SiteID)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}
	var domains []string
	for rows.Next() {
		var d string
		rows.Scan(&d)
		domains = append(domains, d)
	}
	rows.Close()

	if len(domains) == 0 {
		errorResponse(w, 400, "No domains configured for this site")
		return
	}

	// Execute cache purge via SSH on all nodes
	nodes, err := getAllNodes()
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}

	purgePath := req.Path
	if purgePath == "" {
		purgePath = "/"
	}

	var wg sync.WaitGroup
	errCh := make(chan string, len(nodes))

	for _, node := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			// Use push module for SSH - send a cache purge command
			pushPath := filepath.Join(".", "backend", "push", "main")
			for _, domain := range domains {
				cmd := exec.Command(pushPath,
					"--source", "",
					"--target", "",
					"--nginx", config.Node.NginxPath,
					"--purge", fmt.Sprintf("%s%s", domain, purgePath),
					"--nodes", fmt.Sprintf(`[{"id":%d,"name":"%s","host":"%s","port":%d,"username":"%s","password":"%s"}]`,
						n.ID, n.Name, n.Host, n.Port, n.Username, n.Password))
				output, err := cmd.CombinedOutput()
				if err != nil {
					errCh <- fmt.Sprintf("Node %s failed: %v - %s", n.Name, err, string(output))
					return
				}
			}
		}(node)
	}
	wg.Wait()
	close(errCh)

	var errors []string
	for e := range errCh {
		errors = append(errors, e)
	}

	if len(errors) > 0 {
		errorResponse(w, 500, strings.Join(errors, "; "))
		return
	}

	writeSystemLog("INFO", "cache", "Cache purged", fmt.Sprintf("site=%d path=%s", req.SiteID, purgePath))
	successResponse(w, map[string]string{"status": "purge completed"})
}

// ==================== Site Domain Traffic ====================

func handleSiteTraffic(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/site/"), "/")
	if len(pathParts) < 2 || pathParts[1] != "traffic" {
		errorResponse(w, 400, "Invalid URL")
		return
	}
	siteID, err := strconv.Atoi(pathParts[0])
	if err != nil {
		errorResponse(w, 400, "Invalid site ID")
		return
	}

	if r.Method != "GET" {
		errorResponse(w, 405, "Method not allowed")
		return
	}

	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")
	rangeParam := r.URL.Query().Get("range")

	if startTime == "" && endTime == "" {
		switch rangeParam {
		case "7d":
			startTime = time.Now().Add(-7 * 24 * time.Hour).Format("2006-01-02 15:04:05")
		case "30d":
			startTime = time.Now().Add(-30 * 24 * time.Hour).Format("2006-01-02 15:04:05")
		case "all":
			startTime = "2000-01-01 00:00:00"
		default:
			startTime = time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
		}
		endTime = time.Now().Format("2006-01-02 15:04:05")
	}
	if startTime == "" {
		startTime = time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	}
	if endTime == "" {
		endTime = time.Now().Format("2006-01-02 15:04:05")
	}

	// Get domains for this site
	domainRows, err := db.Query("SELECT domain FROM site_domains WHERE site_id=?", siteID)
	if err != nil {
		errorResponse(w, 500, err.Error())
		return
	}
	var domains []string
	for domainRows.Next() {
		var d string
		domainRows.Scan(&d)
		domains = append(domains, d)
	}
	domainRows.Close()

	type DomainTraffic struct {
		Domain       string `json:"domain"`
		RequestCount int64  `json:"request_count"`
		TotalBytes   int64  `json:"total_bytes"`
	}

	var trafficData []DomainTraffic
	for _, d := range domains {
		var count, bytes int64
		db.QueryRow("SELECT COUNT(*), COALESCE(SUM(bytes_sent),0) FROM access_logs WHERE domain=? AND request_time BETWEEN ? AND ?",
			d, startTime, endTime).Scan(&count, &bytes)
		trafficData = append(trafficData, DomainTraffic{Domain: d, RequestCount: count, TotalBytes: bytes})
	}

	successResponse(w, trafficData)
}

// ==================== Static File Server ====================

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	filePath := filepath.Join(".", "public", path)

	// Prevent directory traversal
	absPublic, _ := filepath.Abs(filepath.Join(".", "public"))
	absFile, _ := filepath.Abs(filePath)
	if !strings.HasPrefix(absFile, absPublic) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	info, err := os.Stat(filePath)
	if err != nil || info.IsDir() {
		http.ServeFile(w, r, filepath.Join(".", "public", "index.html"))
		return
	}

	// Set content type
	ext := filepath.Ext(filePath)
	contentTypes := map[string]string{
		".html": "text/html; charset=utf-8",
		".css":  "text/css; charset=utf-8",
		".js":   "application/javascript; charset=utf-8",
		".json": "application/json; charset=utf-8",
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".gif":  "image/gif",
		".svg":  "image/svg+xml",
		".ico":  "image/x-icon",
	}
	if ct, ok := contentTypes[ext]; ok {
		w.Header().Set("Content-Type", ct)
	}
	http.ServeFile(w, r, filePath)
}

// ==================== Router ====================

func setupRouter() http.Handler {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/login", corsMiddleware(handleLogin))
	mux.HandleFunc("/api/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		successResponse(w, map[string]string{"status": "ok"})
	}))

	// Auth-protected API routes
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return corsMiddleware(authMiddleware(h))
	}

	mux.HandleFunc("/api/check-auth", auth(handleCheckAuth))
	mux.HandleFunc("/api/ssl", auth(handleSSLCerts))
	mux.HandleFunc("/api/ssl/", auth(handleSSLCert))
	mux.HandleFunc("/api/lua", auth(handleLuaScripts))
	mux.HandleFunc("/api/lua/", auth(handleLuaScript))
	mux.HandleFunc("/api/nodes", auth(handleNodes))
	mux.HandleFunc("/api/node/", auth(handleNode))
	mux.HandleFunc("/api/sites", auth(handleSites))
	mux.HandleFunc("/api/site/", auth(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/site/")
		parts := strings.Split(path, "/")
		if len(parts) == 1 {
			handleSite(w, r)
		} else if len(parts) >= 2 {
			switch parts[1] {
			case "domains":
				handleSiteDomains(w, r)
			case "redirects":
				handleRedirectRules(w, r)
			case "cache":
				handleCacheRules(w, r)
			case "pathorigin":
				handlePathOriginRules(w, r)
			case "lua":
				handleLuaBindings(w, r)
			case "blacklist":
				handleIPBlacklist(w, r)
			case "traffic":
				handleSiteTraffic(w, r)
			default:
				errorResponse(w, 400, "Unknown sub-resource")
			}
		}
	}))
	mux.HandleFunc("/api/logs/access", auth(handleAccessLogs))
	mux.HandleFunc("/api/logs/system", auth(handleSystemLogs))
	mux.HandleFunc("/api/action/sync", auth(handleForceSync))
	mux.HandleFunc("/api/action/purge", auth(handleCachePurge))
	mux.HandleFunc("/api/config", auth(func(w http.ResponseWriter, r *http.Request) {
		successResponse(w, map[string]interface{}{
			"node_config_dir": config.Node.ConfigDir,
			"node_logs_dir":   config.Node.LogsDir,
			"node_nginx_path": config.Node.NginxPath,
		})
	}))

	// Static files (public)
	mux.HandleFunc("/", handleStatic)

	return mux
}

// ==================== Scheduler ====================

func startScheduler() {
	// Sync scheduler - every N seconds, only if no recent config change
	syncTicker := time.NewTicker(time.Duration(config.Schedule.SyncInterval) * time.Second)
	logCollectTicker := time.NewTicker(time.Duration(config.Schedule.LogCollectInterval) * time.Second)

	// Track last sync time to avoid double-sync
	var lastSyncTime time.Time

	go func() {
		for range syncTicker.C {
			if hasConfigChanged() {
				log.Println("Scheduled sync: config changed, triggering sync")
				lastSyncTime = time.Now()
				doFullSync()
			} else {
				// Periodic sync without config change
				log.Println("Scheduled sync: periodic sync without config change")
				doFullSync()
			}
		}
	}()

	go func() {
		for range logCollectTicker.C {
			// Avoid log collect during a recent sync
			if time.Since(lastSyncTime) < 30*time.Second {
				log.Println("Skipping log collect: recent sync in progress")
				continue
			}
			go doLogCollect()
		}
	}()

	log.Printf("Scheduler started: sync every %ds, log collect every %ds",
		config.Schedule.SyncInterval, config.Schedule.LogCollectInterval)
}

// ==================== Main ====================

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Load config
	if err := loadConfig(filepath.Join(".", "config", "config.json")); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Init database
	initDB()

	// Ensure tmp directories exist
	os.MkdirAll(config.Tmp.ConfDir, 0755)
	os.MkdirAll(config.Tmp.LogDir, 0755)

	// Write startup log
	writeSystemLog("INFO", "system", "Xiaolan-CDN-System started", "")

	// Setup HTTP server
	router := setupRouter()
	server := &http.Server{
		Addr:         config.HTTP.Listen,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start scheduler
	startScheduler()
	startTokenCleanup()
	startLoginAttemptCleanup()

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		writeSystemLog("INFO", "system", "Xiaolan-CDN-System shutting down", "")
		server.Close()
	}()

	if config.HTTP.TLS.Enabled {
		certFile := config.HTTP.TLS.CertFile
		keyFile := config.HTTP.TLS.KeyFile
		if certFile == "" {
			certFile = "./config/cert.pem"
		}
		if keyFile == "" {
			keyFile = "./config/cert.key"
		}
		log.Printf("HTTPS server listening on %s (cert=%s, key=%s)", config.HTTP.Listen, certFile, keyFile)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	} else {
		log.Printf("HTTP server listening on %s", config.HTTP.Listen)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}
}
