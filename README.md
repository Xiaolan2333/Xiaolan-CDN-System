# Xiaolan-CDN-System

## 环境要求：

x86-64架构的 Debian 10-13 或 Ubuntu 18-24（Ubuntu理论支持，未测试）

MySQL 5.7及以上

## 安装：

### 一键安装（此安装脚本不包含安装MySQL）：

MySQL数据库用户建议使用root

```Bash
apt update && apt install wget unzip -y && wget -O Xiaolan-CDN-System-V0.1.2-Install.sh https://github.com/Xiaolan2333/Xiaolan-CDN-System/releases/download/Xiaolan-CDN-System-V0.1.2/Xiaolan-CDN-System-V0.1.2-Install.sh && chmod 777 Xiaolan-CDN-System-V0.1.2-Install.sh && bash ./Xiaolan-CDN-System-V0.1.2-Install.sh
```

### 手动安装（此处以V0.1.1作为演示，不包含MySQL安装）：

1.创建文件夹并进入

```Bash
mkdir -p /opt/xiaolan-cdn/xiaolan-cdn-system && cd /opt/xiaolan-cdn/xiaolan-cdn-system
```

2.下载编译后文件的压缩包并解压

```Bash
wget https://github.com/Xiaolan2333/Xiaolan-CDN-System/releases/download/Xiaolan-CDN-System-V0.1.1/Xiaolan-CDN-System.zip && unzip Xiaolan-CDN-System.zip
```

3.设置目录权限

```Bash
chmod 777 -R /opt/xiaolan-cdn
```

4.导入数据库

```Bash
mysql -h'数据库IP' -u'数据库用户' -p'数据库用户的密码' < "/opt/xiaolan-cdn/xiaolan-cdn-system/setup.sql"
```

5.修改config/config.json

使用喜欢的编辑器打开./config/config.json，这里以vim举例

```Bash
vim ./config/config.json
```

修改用户名、密码、数据库相关信息、监听端口（监听端口可不修改，默认8080）

```json
{
  "admin": {
    "username": "admin",          //用户名
    "password": "admin123"        //密码
  },
  "security": {
    "login_max_attempts": 5,
    "login_window_seconds": 600,
    "login_block_seconds": 900
  },
  "database": {
    "host": "127.0.0.1",           //数据库IP
    "port": 3306,                  //数据库端口
    "user": "root",                //数据库用户名
    "password": "your_password",   //数据库用户密码
    "dbname": "xiaolan-cdn"        //最好别动这个
  },
  "http": {
    "listen": "0.0.0.0:8080",      //:后面的即为端口
    "tls": {
      "enabled": false,
      "cert_file": "./config/cert.pem",
      "key_file": "./config/cert.key"
    }
  },
  "node": {
    "config_dir": "/opt/xiaolan-cdn/xiaolan-cdn-node/conf",
    "logs_dir": "/opt/xiaolan-cdn/xiaolan-cdn-node/logs",
    "nginx_path": "/opt/xiaolan-cdn/xiaolan-cdn-node/sbin/nginx"
  },
  "tmp": {
    "conf_dir": "./tmp/conf",
    "log_dir": "./tmp/log"
  },
  "schedule": {
    "sync_interval": 300,
    "log_collect_interval": 60
  }
}
```

编辑完后记得保存再退出

6.清理临时文件

```Bash
rm /opt/xiaolan-cdn/xiaolan-cdn-system/Xiaolan-CDN-System.zip && rm /opt/xiaolan-cdn/xiaolan-cdn-system/setup.sql
```

7.设置Systemd配置文件

```Bash
cat > /etc/systemd/system/xiaolan-cdn-system.service <<'SVC'
[Unit]
Description=Xiaolan-CDN-System
After=network.target mysqld.service mariadb.service
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/xiaolan-cdn/xiaolan-cdn-system
ExecStart=/opt/xiaolan-cdn/xiaolan-cdn-system/xiaolan-cdn-system
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xiaolan-cdn-system
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
SVC
```

8.启动服务

```Bash
systemctl daemon-reload && systemctl enable xiaolan-cdn-system --now
```

至此，安装完成。访问地址：http://服务器IP:监听端口

## 其它：

### 其它命令：

查看服务状态：

```Bash
systemctl status xiaolan-cdn-system
```

重启服务：

```Bash
systemctl stop xiaolan-cdn-system
```

### 节点仓库：

[https://github.com/Xiaolan2333/Xiaolan-CDN-Node](https://github.com/Xiaolan2333/Xiaolan-CDN-Node)