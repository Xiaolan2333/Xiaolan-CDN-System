#!/bin/bash
echo "Xiaolan-CDN主控安装脚本"
echo "安装所需运行库"
apt update
apt install wget unzip -y
echo "安装完成"
echo "创建目录"
mkdir -p /opt/xiaolan-cdn/xiaolan-cdn-system
echo "创建目录完成"
echo "下载压缩包"
wget -P /opt/xiaolan-cdn/xiaolan-cdn-system https://github.com/Xiaolan2333/Xiaolan-CDN-System/releases/latest/download/Xiaolan-CDN-System.zip
echo "压缩包下载完成"
echo "解压压缩包"
unzip /opt/xiaolan-cdn/xiaolan-cdn-system/Xiaolan-CDN-System.zip -d /opt/xiaolan-cdn/xiaolan-cdn-system
chmod -R 777 /opt/xiaolan-cdn/xiaolan-cdn-system
echo "解压完成"
echo "设置Systemd配置文件"
cat > /etc/systemd/system/xiaolan-cdn-log.timer << 'EOF'
[Unit]
Description=Xiaolan-CDN-System-Log
Documentation=https://xiaolan2333.github.io

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/xiaolan-cdn-log.service << 'EOF'
[Unit]
Description=Xiaolan-CDN-System-Log
Documentation=https://xiaolan2333.github.io
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/xiaolan-cdn/xiaolan-cdn-system
ExecStart=/opt/xiaolan-cdn/xiaolan-cdn-system/log
SyslogIdentifier=xiaolan-cdn-log

[Install]
WantedBy=multi-user.target
EOF
echo "设置Systemd配置文件成功"
echo "启动日志同步系统"
systemctl daemon-reload
systemctl enable xiaolan-cdn-log.timer --now
echo "日志同步系统启动成功"
cd /opt/xiaolan-cdn/xiaolan-cdn-system
echo "清理临时文件"
rm /opt/xiaolan-cdn/xiaolan-cdn-system/Xiaolan-CDN-System.zip
echo "清理完成"
echo "主控安装完成"