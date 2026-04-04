package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

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
	// 读取 update.conf
	cmdBytes, err := ioutil.ReadFile("update.conf")
	if err != nil {
		log.Fatalf("无法读取 update.conf: %v", err)
	}
	command := strings.Split(string(cmdBytes), "\n")[0]
	command = strings.TrimSpace(command)

	if command == "" {
		return
	}

	// 读取服务器配置
	servers, err := readConfig("node.conf")
	if err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}

	// 依次执行
	for _, server := range servers {
		err := processServer(server, command)
		if err != nil {
			log.Printf("服务器 [%s] 操作失败: %v", server.Name, err)
			continue
		}
		fmt.Printf("%s 更新完成\n", server.Name)
	}
}

// 解析配置文件
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

func processServer(s ServerInfo, cmd string) error {
	config := &ssh.ClientConfig{
		User: s.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%s", s.IP, s.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("连接失败: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// 实时输出远程命令的结果
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	return session.Run(cmd)
}