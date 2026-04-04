package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type ServerInfo struct {
	Name     string
	IP       string
	Port     string
	User     string
	Password string
}

func main() {
	// 读取配置文件
	servers, err := readConfig("node.conf")
	if err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}

	// 依次对服务器进行操作
	for _, server := range servers {
		err := processServer(server)
		if err != nil {
			log.Printf("服务器 [%s] 操作失败: %v", server.Name, err)
			continue
		}
		fmt.Printf("%s 更新完成\n", server.Name)
	}

	fmt.Println("所有服务器已更新完成")
}

// 解析服务器配置文件
func readConfig(filename string) ([]ServerInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var servers []ServerInfo
	scanner := bufio.NewScanner(file)
	
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if len(lines) >= 5 {
				servers = append(servers, parseServer(lines))
				lines = []string{}
			}
			continue
		}
		lines = append(lines, line)
	}
	// 处理文件末尾没有空行的情况
	if len(lines) >= 5 {
		servers = append(servers, parseServer(lines))
	}

	return servers, nil
}

func parseServer(lines []string) ServerInfo {
	return ServerInfo{
		Name:     lines[0],
		IP:       lines[1],
		Port:     lines[2],
		User:     lines[3],
		Password: lines[4],
	}
}

func processServer(s ServerInfo) error {
	// 配置SSH
	config := &ssh.ClientConfig{
		User: s.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// 建立SSH连接
	addr := fmt.Sprintf("%s:%s", s.IP, s.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH 连接失败: %w", err)
	}
	defer client.Close()

	// 执行清理命令
	if err := runCommand(client, "rm -rf /opt/xiaolan-cdn/xiaolan-cdn-node/conf/*"); err != nil {
		return fmt.Errorf("清理旧文件失败: %w", err)
	}

	// 使用SFTP上传文件
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("创建 SFTP 连接失败: %w", err)
	}
	defer sftpClient.Close()

	localDir := "./node-config"
	remoteDir := "/opt/xiaolan-cdn/xiaolan-cdn-node/conf"

	files, err := os.ReadDir(localDir)
	if err != nil {
		return fmt.Errorf("读取本地目录失败: %w", err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		localPath := filepath.Join(localDir, f.Name())
		remotePath := filepath.Join(remoteDir, f.Name())

		if err := uploadFile(sftpClient, localPath, remotePath); err != nil {
			return fmt.Errorf("上传文件 %s 失败: %w", f.Name(), err)
		}
	}

	// 执行Nginx重载
	if err := runCommand(client, "/opt/xiaolan-cdn/xiaolan-cdn-node/sbin/nginx -s reload"); err != nil {
		return fmt.Errorf("Nginx 重载失败: %w", err)
	}

	return nil
}

// 执行远程命令
func runCommand(client *ssh.Client, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	return session.Run(cmd)
}

// 上传单个文件
func uploadFile(sc *sftp.Client, localPath, remotePath string) error {
	srcFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := sc.Create(remotePath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
