import asyncio
import logging
import socket
import psutil  # 替换 netifaces
from typing import Dict, Optional
from src.transport.udp import QuicTransport
from src.connection.connection import QuicConnection, Path
from src.packet.header import Header

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("quic.client")

class NetworkInterface:
    """网络接口信息"""
    def __init__(self, name: str, ip: str):
        self.name = name
        self.ip = ip
        self.transport: Optional[QuicTransport] = None
        self.is_active = False

class QuicClient:
    def __init__(self, server_host: str, server_port: int):
        self.server_addr = (server_host, server_port)
        self.interfaces: Dict[str, NetworkInterface] = {}
        self.active_interface: Optional[NetworkInterface] = None
        self.connection: Optional[QuicConnection] = None
        self._handshake_complete = asyncio.Event()
    
    def discover_interfaces(self):
        """发现可用的网络接口"""
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                # psutil 使用 family 属性来标识地址类型
                if addr.family == socket.AF_INET:  # IPv4
                    ip = addr.address
                    if not ip.startswith('127.'):  # 排除本地回环
                        logger.info(f"Found interface {iface} with IP {ip}")
                        self.interfaces[iface] = NetworkInterface(iface, ip)
                        break  # 找到一个 IPv4 地址就跳出内层循环
    
    def handle_handshake_response(self):
        """处理握手响应"""
        logger.info("Handshake response received, marking connection as established")
        if self.connection:
            self.connection.is_established = True
            self._handshake_complete.set()
    
    async def setup_interface(self, interface: NetworkInterface):
        """为网络接口设置 QUIC 传输"""
        transport = QuicTransport()
        try:
            # 使用接口的 IP 地址绑定
            await transport.create_endpoint(interface.ip, 0)
            # 设置握手回调
            transport.on_handshake_complete = self.handle_handshake_response
            interface.transport = transport
            interface.is_active = True
            logger.info(f"Setup complete for interface {interface.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to setup interface {interface.name}: {e}")
            return False
    
    async def start(self):
        """启动 QUIC 客户端"""
        # 发现网络接口
        self.discover_interfaces()
        if not self.interfaces:
            raise RuntimeError("No suitable network interfaces found")
        
        # 设置所有接口
        for interface in self.interfaces.values():
            await self.setup_interface(interface)
        
        # 选择第一个接口作为初始接口
        self.active_interface = next(iter(self.interfaces.values()))
        
        # 创建连接
        conn_id = Header.generate_connection_id()
        self.connection = QuicConnection(conn_id, is_client=True)
        self.connection.transport = self.active_interface.transport
        self.active_interface.transport.connections[conn_id] = self.connection
        
        # 设置初始路径
        initial_path = Path(
            (self.active_interface.ip, self.active_interface.transport.transport.get_extra_info('socket').getsockname()[1]),
            self.server_addr
        )
        self.connection.active_path = initial_path
        
        # 开始握手
        logger.info(f"Starting handshake using interface {self.active_interface.name} to server {self.server_addr}")
        await self.connection.start_handshake()
        
        # 等待连接建立
        timeout = 10  # 10秒超时
        try:
            await asyncio.wait_for(self._handshake_complete.wait(), timeout)
            logger.info("Connection established successfully")
        except asyncio.TimeoutError:
            logger.error("Handshake timeout. Server might be unreachable.")
            raise TimeoutError("Handshake timeout")
    
    async def migrate_to_interface(self, interface_name: str):
        """迁移到新的网络接口"""
        if interface_name not in self.interfaces:
            raise ValueError(f"Interface {interface_name} not found")
        
        new_interface = self.interfaces[interface_name]
        if not new_interface.is_active:
            await self.setup_interface(new_interface)
        
        if not self.connection:
            raise RuntimeError("No active connection")
        
        # 创建新路径
        new_path = Path(
            (new_interface.ip, new_interface.transport.transport.get_extra_info('socket').getsockname()[1]),
            self.server_addr
        )
        
        # 开始路径验证
        await self.connection.validate_path(new_path)
        logger.info(f"Started path validation for interface {interface_name}")

async def main():
    # 使用实际的服务器 IP
    server_ip = "172.29.26.221"  # 根据实际情况修改
    server_port = 5000
    
    client = QuicClient(server_ip, server_port)
    
    try:
        await client.start()
        
        while True:
            print("\nAvailable interfaces:")
            for name in client.interfaces:
                print(f"- {name}")
            
            iface = input("\nEnter interface name to migrate to (or 'q' to quit): ")
            if iface.lower() == 'q':
                break
            
            try:
                await client.migrate_to_interface(iface)
            except Exception as e:
                logger.error(f"Migration failed: {e}")
    
    except KeyboardInterrupt:
        logger.info("Client stopped by user")
    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 