package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"
)

type Node struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type AccessLogEntry struct {
	NodeID      int
	SiteID      *int
	StatusCode  int
	Domain      string
	RequestPath string
	ClientIP    string
	RequestTime time.Time
	Cookie      string
	UserAgent   string
	BytesSent   int64
}

func main() {
	args := parseArgs()
	db := connectDB(args)
	defer db.Close()

	logDir := args["log-dir"]
	tmpDir := args["tmp-dir"]
	nodesData := args["nodes-data"]

	os.MkdirAll(tmpDir, 0755)

	var nodes []Node
	if nodesData != "" {
		if err := json.Unmarshal([]byte(nodesData), &nodes); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse nodes data: %v\n", err)
			os.Exit(1)
		}
	}

	var allEntries []AccessLogEntry
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, len(nodes))

	for _, node := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			entries, err := collectLogsFromNode(n, logDir, tmpDir)
			if err != nil {
				errCh <- fmt.Errorf("node %s: %v", n.Name, err)
				return
			}
			mu.Lock()
			allEntries = append(allEntries, entries...)
			mu.Unlock()
		}(node)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	insertCount := insertAccessLogs(db, allEntries)
	fmt.Printf("Collected and inserted %d log entries\n", insertCount)
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

func sshConnect(node Node) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            node.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(node.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", node.Host, node.Port), config)
}

func sshExec(node Node, command string) error {
	client, err := sshConnect(node)
	if err != nil {
		return fmt.Errorf("SSH connect failed: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session failed: %v", err)
	}
	defer session.Close()

	return session.Run(command)
}

func sshDownload(node Node, remoteCmd string, w io.Writer) error {
	client, err := sshConnect(node)
	if err != nil {
		return fmt.Errorf("SSH connect failed: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session failed: %v", err)
	}
	defer session.Close()

	session.Stdout = w
	var stderrBuf bytes.Buffer
	session.Stderr = &stderrBuf

	if err := session.Run(remoteCmd); err != nil {
		return fmt.Errorf("remote command failed: %v - %s", err, stderrBuf.String())
	}
	return nil
}

func collectLogsFromNode(node Node, logDir, tmpDir string) ([]AccessLogEntry, error) {
	nodeTmpDir := filepath.Join(tmpDir, fmt.Sprintf("node-%d", node.ID))
	os.MkdirAll(nodeTmpDir, 0755)

	localFile := filepath.Join(nodeTmpDir, "logs.tar.gz")

	// Download both access and error logs compressed via SSH
	remoteCmd := fmt.Sprintf("cd %s && tar czf - access.log* error.log* 2>/dev/null", logDir)
	outFile, err := os.Create(localFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create local file: %v", err)
	}

	if err := sshDownload(node, remoteCmd, outFile); err != nil {
		outFile.Close()
		return nil, fmt.Errorf("failed to download logs: %v", err)
	}
	outFile.Close()

	// Extract tar.gz
	extractDir := filepath.Join(nodeTmpDir, "extracted")
	os.MkdirAll(extractDir, 0755)

	if err := extractTarGz(localFile, extractDir); err != nil {
		entries, _ := parseLogFile(localFile, node.ID)
		return entries, nil
	}

	// Parse all extracted log files
	var entries []AccessLogEntry
	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		filename := filepath.Base(path)
		var parsed []AccessLogEntry
		var parseErr error
		if strings.HasPrefix(filename, "error.log") {
			parsed, parseErr = parseErrorLogFile(path, node.ID)
		} else {
			parsed, parseErr = parseLogFile(path, node.ID)
		}
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", path, parseErr)
			return nil
		}
		entries = append(entries, parsed...)
		return nil
	})

	// Clean remote after successful parsing
	cleanCmd := fmt.Sprintf("find %s \\( -name 'access.log.*' -o -name 'error.log.*' \\) -type f -mmin +1 -delete 2>/dev/null; truncate -s 0 %s/access.log %s/error.log 2>/dev/null", logDir, logDir, logDir)
	sshExec(node, cleanCmd)

	return entries, nil
}

func extractTarGz(tarGzPath, destDir string) error {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	tr := tar.NewReader(gzReader)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		targetPath := filepath.Join(destDir, header.Name)
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(targetPath, 0755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(targetPath), 0755)
			outFile, err := os.Create(targetPath)
			if err != nil {
				return err
			}
			io.Copy(outFile, tr)
			outFile.Close()
		}
	}
	return nil
}

func parseLogFile(filePath string, nodeID int) ([]AccessLogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []AccessLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		entry, err := parseLogLine(line, nodeID)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func parseLogLine(line string, nodeID int) (AccessLogEntry, error) {
	entry := AccessLogEntry{NodeID: nodeID}
	pos := 0

	statusEnd := strings.IndexByte(line[pos:], ' ')
	if statusEnd < 0 {
		return entry, fmt.Errorf("no status code")
	}
	statusStr := line[pos : pos+statusEnd]
	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return entry, fmt.Errorf("invalid status: %s", statusStr)
	}
	entry.StatusCode = status
	pos += statusEnd + 1

	domainEnd := strings.IndexByte(line[pos:], ' ')
	if domainEnd < 0 {
		return entry, fmt.Errorf("no domain")
	}
	entry.Domain = line[pos : pos+domainEnd]
	pos += domainEnd + 1

	if pos >= len(line) || line[pos] != '"' {
		return entry, fmt.Errorf("expected quote for request")
	}
	pos++
	reqEnd := strings.IndexByte(line[pos:], '"')
	if reqEnd < 0 {
		return entry, fmt.Errorf("unterminated request quote")
	}
	request := line[pos : pos+reqEnd]
	parts := strings.Split(request, " ")
	if len(parts) >= 2 {
		entry.RequestPath = parts[1]
	}
	pos += reqEnd + 2

	ipEnd := strings.IndexByte(line[pos:], ' ')
	if ipEnd < 0 {
		return entry, fmt.Errorf("no IP")
	}
	entry.ClientIP = line[pos : pos+ipEnd]
	pos += ipEnd + 1

	if pos >= len(line) || line[pos] != '[' {
		return entry, fmt.Errorf("expected [ for time")
	}
	pos++
	timeEnd := strings.IndexByte(line[pos:], ']')
	if timeEnd < 0 {
		return entry, fmt.Errorf("unterminated time")
	}
	timeStr := line[pos : pos+timeEnd]
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr)
	if err != nil {
		return entry, fmt.Errorf("invalid time: %s", timeStr)
	}
	entry.RequestTime = t
	pos += timeEnd + 2

	if pos < len(line) && line[pos] == '"' {
		pos++
		cookieEnd := strings.IndexByte(line[pos:], '"')
		if cookieEnd >= 0 {
			entry.Cookie = line[pos : pos+cookieEnd]
			pos += cookieEnd + 2
		}
	} else {
		skipEnd := strings.IndexByte(line[pos:], ' ')
		if skipEnd >= 0 {
			entry.Cookie = line[pos : pos+skipEnd]
			pos += skipEnd + 1
		}
	}

	if pos < len(line) && line[pos] == '"' {
		pos++
		uaEnd := strings.IndexByte(line[pos:], '"')
		if uaEnd >= 0 {
			entry.UserAgent = line[pos : pos+uaEnd]
			pos += uaEnd + 2
		}
	} else {
		skipEnd := strings.IndexByte(line[pos:], ' ')
		if skipEnd >= 0 {
			entry.UserAgent = line[pos : pos+skipEnd]
			pos += skipEnd + 1
		}
	}

	if pos < len(line) {
		bytesStr := strings.TrimSpace(line[pos:])
		if bytesStr != "" && bytesStr != "-" {
			bytes, err := strconv.ParseInt(bytesStr, 10, 64)
			if err == nil {
				entry.BytesSent = bytes
			}
		}
	}

	return entry, nil
}

func parseErrorLogFile(filePath string, nodeID int) ([]AccessLogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []AccessLogEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		entry := parseErrorLogLine(line, nodeID)
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// Nginx error log: YYYY/MM/DD HH:MM:SS [level] pid#tid: *cid message...
func parseErrorLogLine(line string, nodeID int) AccessLogEntry {
	entry := AccessLogEntry{NodeID: nodeID, StatusCode: 0, BytesSent: 0}

	// Extract timestamp: "2024/06/20 12:00:00 "
	if len(line) < 20 {
		entry.UserAgent = line
		return entry
	}
	timeStr := line[:19]
	t, err := time.Parse("2006/01/02 15:04:05", timeStr)
	if err == nil {
		entry.RequestTime = t
	}

	rest := line[20:]

	// Extract level: [error] [warn] [crit] etc.
	levelEnd := strings.IndexByte(rest, ']')
	if levelEnd > 0 && strings.HasPrefix(rest, "[") {
		level := rest[1:levelEnd]
		entry.Cookie = level // store level in cookie field
		rest = rest[levelEnd+1:]
	}

	// Extract client IP: "client: 1.2.3.4"
	if idx := strings.Index(rest, "client: "); idx >= 0 {
		start := idx + len("client: ")
		end := strings.IndexAny(rest[start:], ", \t\n")
		if end < 0 {
			end = len(rest) - start
		}
		entry.ClientIP = rest[start : start+end]
	}

	// Extract server: "server: example.com"
	if idx := strings.Index(rest, "server: "); idx >= 0 {
		start := idx + len("server: ")
		end := strings.IndexAny(rest[start:], ", \t\n")
		if end < 0 {
			end = len(rest) - start
		}
		entry.Domain = rest[start : start+end]
	}

	// Extract request path: 'request: "GET /path HTTP/1.1"'
	if idx := strings.Index(rest, "request: \""); idx >= 0 {
		start := idx + len("request: \"")
		reqStr := rest[start:]
		// Find the second space to skip method
		firstSpace := strings.IndexByte(reqStr, ' ')
		if firstSpace >= 0 {
			pathStart := firstSpace + 1
			pathEnd := strings.IndexByte(reqStr[pathStart:], ' ')
			if pathEnd >= 0 {
				entry.RequestPath = reqStr[pathStart : pathStart+pathEnd]
			}
		}
	}

	// Extract host: 'host: "example.com"'
	if entry.Domain == "" {
		if idx := strings.Index(rest, "host: \""); idx >= 0 {
			start := idx + len("host: \"")
			end := strings.IndexByte(rest[start:], '"')
			if end >= 0 {
				entry.Domain = rest[start : start+end]
			}
		}
	}

	// Derive status code from error type
	restLower := strings.ToLower(rest)
	if strings.Contains(restLower, "upstream timed out") || strings.Contains(restLower, "timed out") {
		entry.StatusCode = 504
	} else if strings.Contains(restLower, "connection refused") || strings.Contains(restLower, "connect() failed") {
		entry.StatusCode = 502
	} else if strings.Contains(restLower, "no live upstreams") {
		entry.StatusCode = 502
	} else if strings.Contains(restLower, "ssl") && (strings.Contains(restLower, "error") || strings.Contains(restLower, "handshake")) {
		entry.StatusCode = 502
	}

	// Store full error message in user_agent
	entry.UserAgent = line

	return entry
}

func insertAccessLogs(db *sql.DB, entries []AccessLogEntry) int {
	if len(entries) == 0 {
		return 0
	}

	batchSize := 500
	inserted := 0

	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}
		batch := entries[i:end]

		var sb strings.Builder
		sb.WriteString("INSERT INTO access_logs (node_id, site_id, status_code, domain, request_path, client_ip, request_time, cookie, user_agent, bytes_sent) VALUES ")
		var values []interface{}

		for j, e := range batch {
			if j > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
			values = append(values, e.NodeID, e.SiteID, e.StatusCode, e.Domain, e.RequestPath, e.ClientIP, e.RequestTime, e.Cookie, e.UserAgent, e.BytesSent)
		}

		_, err := db.Exec(sb.String(), values...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to insert batch: %v\n", err)
			continue
		}
		inserted += len(batch)
	}

	return inserted
}
