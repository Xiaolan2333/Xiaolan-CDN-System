package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

func main() {
	args := parseArgs()

	source := args["source"]
	target := args["target"]
	nginxPath := args["nginx"]
	nodesJSON := args["nodes"]
	purgeURL := args["purge"]

	if purgeURL != "" {
		if nodesJSON == "" {
			fmt.Fprintln(os.Stderr, "nodes is required for purge")
			os.Exit(1)
		}
		doCachePurge(nodesJSON, nginxPath, purgeURL)
		return
	}

	if source == "" || target == "" || nodesJSON == "" {
		fmt.Fprintln(os.Stderr, "Usage: push --source DIR --target DIR --nginx PATH --nodes JSON")
		os.Exit(1)
	}

	var nodes []Node
	if err := json.Unmarshal([]byte(nodesJSON), &nodes); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse nodes JSON: %v\n", err)
		os.Exit(1)
	}

	results := pushToNodes(nodes, source, target, nginxPath)

	for _, r := range results {
		fmt.Println(r)
	}
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
	_, err := sshExecOutput(node, command)
	return err
}

func sshExecOutput(node Node, command string) (string, error) {
	client, err := sshConnect(node)
	if err != nil {
		return "", fmt.Errorf("SSH connect failed: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH session failed: %v", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(command)
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n" + stderr.String()
	}
	if err != nil {
		return output, fmt.Errorf("command failed: %v", err)
	}
	return output, nil
}

func pushToNodes(nodes []Node, sourceDir, targetDir, nginxPath string) []string {
	var wg sync.WaitGroup
	results := make(chan string, len(nodes))

	for _, node := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			result := pushToNode(n, sourceDir, targetDir, nginxPath)
			results <- result
		}(node)
	}

	wg.Wait()
	close(results)

	var output []string
	for r := range results {
		output = append(output, r)
	}
	return output
}

func pushToNode(node Node, sourceDir, targetDir, nginxPath string) string {
	mkdirCmd := fmt.Sprintf("mkdir -p %s", targetDir)
	if err := sshExec(node, mkdirCmd); err != nil {
		return fmt.Sprintf("[FAIL] %s: mkdir failed - %v", node.Name, err)
	}

	// Clean conf dir except mime.types before uploading new configs
	cleanCmd := fmt.Sprintf("find %s -mindepth 1 ! -name 'mime.types' -exec rm -rf {} + 2>/dev/null; true", targetDir)
	sshExec(node, cleanCmd)

	if err := scpUpload(node, sourceDir, targetDir); err != nil {
		return fmt.Sprintf("[FAIL] %s: upload failed - %v", node.Name, err)
	}

	chmodCmd := fmt.Sprintf("chmod -R 644 %s/*.pem %s/*.conf %s/*.lua 2>/dev/null; chmod 600 %s/*.key 2>/dev/null", targetDir, targetDir, targetDir, targetDir)
	sshExec(node, chmodCmd)

	testCmd := fmt.Sprintf("%s -t", nginxPath)
	if output, err := sshExecOutput(node, testCmd); err != nil {
		return fmt.Sprintf("[FAIL] %s: nginx config test failed - %v, output: %s", node.Name, err, output)
	}

	reloadCmd := fmt.Sprintf("%s -s reload", nginxPath)
	if err := sshExec(node, reloadCmd); err != nil {
		return fmt.Sprintf("[FAIL] %s: nginx reload failed - %v", node.Name, err)
	}

	return fmt.Sprintf("[OK] %s: config pushed and nginx reloaded", node.Name)
}

func scpUpload(node Node, sourceDir, targetDir string) error {
	client, err := sshConnect(node)
	if err != nil {
		return fmt.Errorf("SSH connect failed: %v", err)
	}
	defer client.Close()

	// Create tar.gz of source files
	var buf bytes.Buffer
	if err := createTarGz(sourceDir, &buf); err != nil {
		return fmt.Errorf("tar creation failed: %v", err)
	}

	// Open SSH session and pipe tar.gz to remote
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session failed: %v", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(buf.Bytes())
	var stderrBuf bytes.Buffer
	session.Stderr = &stderrBuf

	cmd := fmt.Sprintf("tar xzf - -C %s", targetDir)
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("remote untar failed: %v - %s", err, stderrBuf.String())
	}
	return nil
}

func createTarGz(sourceDir string, w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(sourceDir, path)
		relPath = filepath.ToSlash(relPath)

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		io.Copy(tw, file)
		file.Close()
		return nil
	})
}

func doCachePurge(nodesJSON, nginxPath, purgeURL string) {
	var nodes []Node
	if err := json.Unmarshal([]byte(nodesJSON), &nodes); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse nodes JSON: %v\n", err)
		os.Exit(1)
	}

	slashIdx := strings.Index(purgeURL, "/")
	if slashIdx < 0 {
		fmt.Fprintf(os.Stderr, "Invalid purge URL: %s\n", purgeURL)
		return
	}
	host := purgeURL[:slashIdx]
	path := purgeURL[slashIdx:]

	for _, node := range nodes {
		purgeCmd := fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' -X PURGE http://127.0.0.1%s -H 'Host: %s'", path, host)
		output, err := sshExecOutput(node, purgeCmd)
		if err != nil {
			fmt.Printf("[FAIL] %s: cache purge failed - %v\n", node.Name, err)
		} else {
			fmt.Printf("[OK] %s: cache purge - HTTP %s\n", node.Name, strings.TrimSpace(output))
		}

		cleanCmd := "find /opt/xiaolan-cdn/xiaolan-cdn-node/cache -type f -delete 2>/dev/null; echo done"
		sshExec(node, cleanCmd)
	}
}
