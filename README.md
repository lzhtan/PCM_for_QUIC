# QUIC主动连接迁移

这是一个基于 QUIC 协议实现的主动连接迁移服务器和客户端，使用 Python 异步编程开发。

## 功能特点

- 基于QUIC协议的可靠传输
- 支持大文件分块传输
- 异步I/O操作
- 内置错误处理和日志记录
- 支持并发连接

## 系统要求

- Python 3.8+
- 支持的操作系统：Linux, macOS, Windows
- 设备通常配置两张及以上可用网卡

## 安装

1. 克隆仓库：
bash
git clone https://github.com/lzhtan/PCM_for_QUIC.git
cd PCM_for_QUIC

2. 安装依赖：
bash
pip3 install -r requirements.txt

## 运行

1. 启动服务器：
bash
python3 server.py

2. 启动客户端：
bash
python3 client.py
注意修改代码中的server_ip和server_port以匹配服务器的IP和端口。


## 使用

1. 服务器启动后，会监听指定地址和端口，等待客户端连接。
2. 客户端连接到服务器后，可以发送文件请求，服务器会返回文件数据。
3. 客户端可手动选择连接迁移。

必要时候，可能需要Python虚拟环境执行：
python3 -m venv path
source path/bin/activate