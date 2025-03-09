# QUIC主动连接迁移

这是一个基于 QUIC 协议实现的主动连接迁移服务器和客户端，使用 Python 异步编程开发。

## 功能特点

- 基于QUIC协议的可靠传输
- 支持大文件分块传输
- 异步I/O操作
- 内置错误处理和日志记录
- 支持并发连接
- **支持主动连接迁移**

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

必要时候，可能需要Python虚拟环境执行：
python3 -m venv path
source path/bin/activate

## 运行

1. 启动服务器：
bash
python3 server.py

2. 启动客户端：
bash
python3 client.py

**注意**: 修改代码中的server_ip和server_port以匹配服务器的IP和端口。


## 使用

1. 服务器启动后，会监听指定地址和端口，等待客户端连接。
2. 客户端连接到服务器后，可以发送文件请求，服务器会返回文件数据。
3. 客户端可通过交互式菜单选择连接迁移到不同的网络接口。
4. 系统会自动显示文件传输性能报告，包括传输速度和总时间。

## 连接迁移功能

本项目实现了QUIC协议的主动连接迁移功能，允许客户端在不中断数据传输的情况下切换网络接口。迁移过程中会保持连接状态并继续数据传输，同时记录连接ID的变化。

## 故障排除

- 如果遇到权限问题，可能需要使用管理员/root权限运行
- 确保防火墙允许UDP流量通过
- 检查网络接口配置是否正确

更多信息和详细说明，请参考我们的论文和演示视频。