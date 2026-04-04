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
	// 初始化目录
	setupDirs()

	// 读取配置文件
	servers, err := readConfig("node.conf")
	if err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}

	// 依次处理每一台服务器
	for _, server := range servers {
		err := processServer(server)
		if err != nil {
			fmt.Printf("服务器 %s 处理失败: %v\n", server.Name, err)
			continue
		}
		fmt.Printf("%s 更新完成\n", server.Name)
	}
}

// 确保必要的目录存在
func setupDirs() {
	dirs := []string{"tmp", "node-access-logs"}
	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			os.MkdirAll(d, 0755)
		}
	}
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
		if line != "" {
			lines = append(lines, line)
		}
		if len(lines) == 5 {
			servers = append(servers, ServerInfo{
				Name:     lines[0],
				IP:       lines[1],
				Port:     lines[2],
				User:     lines[3],
				Password: lines[4],
			})
			lines = nil
		}
	}
	return servers, scanner.Err()
}

func processServer(s ServerInfo) error {
	// SSH连接配置
	config := &ssh.ClientConfig{
		User: s.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}

	// 建立SSH连接
	addr := fmt.Sprintf("%s:%s", s.IP, s.Port)
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH连接失败: %v", err)
	}
	defer conn.Close()

	// 建立SFTP会话
	client, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("SFTP连接失败: %v", err)
	}
	defer client.Close()

	// 定义文件名
	now := time.Now()
	timestamp := now.Format("20060102-150405")
	today := now.Format("2006.1.2")
	
	remotePath := "/opt/xiaolan-cdn/xiaolan-cdn-node/logs/access.log"
	tempFileName := fmt.Sprintf("%s-%s.log", s.Name, timestamp)
	tempPath := filepath.Join("tmp", tempFileName)
	finalLogPath := filepath.Join("node-access-logs", fmt.Sprintf("%s-%s.log", s.Name, today))

	// 从服务器下载文件
	srcFile, err := client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("无法打开远程文件: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("无法创建临时文件: %v", err)
	}
	
	_, err = io.Copy(dstFile, srcFile)
	dstFile.Close()
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}

	// 将内容写入/追加到当天日志文件中
	content, err := os.ReadFile(tempPath)
	if err != nil {
		return fmt.Errorf("读取临时文件失败: %v", err)
	}

	// 以追加模式打开或创建文件
	f, err := os.OpenFile(finalLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("操作最终日志文件失败: %v", err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("写入内容失败: %v", err)
	}

	// 删除下载的临时文件
	os.Remove(tempPath)

	return nil
}
