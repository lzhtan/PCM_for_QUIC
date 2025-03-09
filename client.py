import asyncio
import logging
import socket
import psutil  # 替换 netifaces
import time
import os
from typing import Dict, Optional
from src.transport.udp import QuicTransport
from src.connection.connection import QuicConnection, Path
from src.packet.header import Header, PacketType
from src.packet.frame import FileRequestFrame, FileResponseFrame, FileDataFrame
from src.packet.packet_processor import PacketProcessor

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
        self.receiving_files: Dict[str, Dict] = {}
        self.transfer_complete = asyncio.Event()  # 添加传输完成事件
        self.transfer_stats = {}
        logger.info("QuicClient initialized")
    
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
        transport.client = self  # 设置客户端引用
        try:
            await transport.create_endpoint(interface.ip, 0)
            transport.on_handshake_complete = self.handle_handshake_response
            interface.transport = transport
            interface.is_active = True
            logger.info(f"Setup complete for interface {interface.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to setup interface {interface.name}: {e}")
            return False
    
    async def start(self):
        """启动 QUIC 客户端并建立连接"""
        logger.info("Starting QUIC client...")
        
        # 发现网络接口
        self.discover_interfaces()
        if not self.interfaces:
            raise RuntimeError("No suitable network interfaces found")
        
        # 设置所有接口
        for interface in self.interfaces.values():
            await self.setup_interface(interface)
            
        # 选择第一个接口作为初始接口
        self.active_interface = next(iter(self.interfaces.values()))
        logger.info(f"Selected active interface: {self.active_interface.name}")
        
        # 创建连接
        conn_id = os.urandom(8)
        self.connection = QuicConnection(conn_id, is_client=True)
        self.connection.transport = self.active_interface.transport
        self.active_interface.transport.connections[conn_id] = self.connection
        
        # 发送 Initial 包
        initial_packet = PacketProcessor.create_packet(
            Header(
                PacketType.INITIAL,
                destination_connection_id=os.urandom(8),
                source_connection_id=conn_id
            ),
            []
        )
        
        logger.info(f"Starting handshake with source CID: {conn_id.hex()}")
        self.active_interface.transport.send_datagram(initial_packet, self.server_addr)
        
        # 等待连接建立
        try:
            await asyncio.wait_for(self._handshake_complete.wait(), timeout=10.0)
            logger.info("Connection established successfully")
            return True
        except asyncio.TimeoutError:
            logger.error("Handshake timeout")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during start: {e}")
            raise
    
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
        
        # 保存旧的连接 ID 用于比较
        old_connection_id = self.connection.connection_id.hex()
        
        # 开始路径验证
        await self.connection.validate_path(new_path)
        logger.info(f"Started path validation for interface {interface_name}")
        
        # 打印连接迁移前后的连接 ID
        new_connection_id = self.connection.connection_id.hex()
        logger.info(f"连接迁移信息:")
        logger.info(f"  - 旧连接 ID: {old_connection_id}")
        logger.info(f"  - 新连接 ID: {new_connection_id}")
        logger.info(f"  - 对端连接 ID: {self.connection.peer_connection_id.hex()}")
    
    async def connect(self):
        """连接到服务器"""
        logger.info("Starting connection process...")
        # ... 连接建立过程 ...
        try:
            await asyncio.wait_for(self._handshake_complete.wait(), timeout=5.0)
            logger.info("Connection established successfully")
        except asyncio.TimeoutError:
            logger.error("Connection timeout")
            raise
        
    async def request_file(self, filename: str):
        """请求文件"""
        if not self.connection or not self.connection.is_established:
            logger.error("Cannot request file: connection not established")
            return
            
        logger.info(f"Requesting file: {filename}")
        
        # 初始化文件接收状态
        self.receiving_files[filename] = {
            'size': None,
            'chunk_size': None,
            'total_chunks': None,
            'start_time': time.time(),
            'received_chunks': {},
            'complete': False
        }
        self.transfer_complete.clear()
        
        # 发送文件请求
        request_frame = FileRequestFrame(filename)
        packet = PacketProcessor.create_packet(
            Header(PacketType.SHORT, self.connection.peer_connection_id, self.connection.connection_id),
            [request_frame]
        )
        self.connection.transport.send_datagram(packet, self.server_addr)
        
        # 等待传输完成
        try:
            await asyncio.wait_for(self.transfer_complete.wait(), timeout=300)
            return True
        except asyncio.TimeoutError:
            logger.error(f"File transfer timeout: {filename}")
            return False
            
    def handle_file_response(self, frame: FileResponseFrame, filename: str):
        """处理文件响应"""
        logger.info(f"收到文件响应: 大小={frame.file_size}, 分片大小={frame.chunk_size}")
        
        if filename not in self.receiving_files:
            logger.error(f"未找到文件信息: {filename}")
            return
            
        file_info = self.receiving_files[filename]
        file_info['size'] = frame.file_size
        file_info['chunk_size'] = frame.chunk_size
        file_info['start_time'] = time.time()  # 重置开始时间
        
        logger.info(f"文件传输开始: {filename}")
        
    def handle_file_data(self, frame: FileDataFrame, filename: str):
        """处理文件数据"""
        if filename not in self.receiving_files:
            logger.error(f"No file info found for: {filename}")
            return
            
        file_info = self.receiving_files[filename]
        file_info['received_chunks'][frame.chunk_id] = frame.data
        
        if file_info.get('size') is not None:
            current_size = sum(len(chunk) for chunk in file_info['received_chunks'].values())
            if current_size >= file_info['size']:
                # 打印传输性能报告
                elapsed_time = time.time() - file_info['start_time']
                throughput = current_size / (1024 * 1024 * elapsed_time)  # MB/s
                
                logger.info("\n=== 文件传输完成报告 ===")
                logger.info(f"文件名称: {filename}")
                logger.info(f"文件大小: {current_size / (1024*1024):.2f} MB")
                logger.info(f"传输时间: {elapsed_time:.2f} 秒")
                logger.info(f"平均带宽: {throughput:.2f} MB/s")
                logger.info(f"总分片数: {len(file_info['received_chunks'])}")
                logger.info("========================")
                
                file_info['complete'] = True
                self.transfer_complete.set()
                
    def print_congestion_stats(self):
        """打印拥塞控制统计信息"""
        if not self.connection:
            logger.info("没有活动连接")
            return
        
        stats = self.connection.get_congestion_stats()
        logger.info("\n=== 拥塞控制状态 ===")
        logger.info(f"拥塞窗口: {stats['cwnd']} 包")
        logger.info(f"慢启动阈值: {stats['ssthresh']} 包")
        logger.info(f"状态: {stats['state']}")
        logger.info(f"RTT: {stats['smoothed_rtt_ms']:.2f} ms (最小: {stats['min_rtt_ms']:.2f} ms, 最新: {stats['latest_rtt_ms']:.2f} ms)")
        logger.info(f"飞行中的包: {stats['in_flight']} / {stats['cwnd']}")
        logger.info("=====================")

async def main():
    """主函数"""
    server_ip = "169.254.141.86"
    server_port = 5000
    
    client = QuicClient(server_ip, server_port)
    
    try:
        # 1. 启动并建立连接
        logger.info("Phase 1: Starting client and establishing connection...")
        await client.start()
        logger.info("Connection established")
        
        # 2. 请求视频
        while True:
            choice = input("\nChoose action:\n1. Request video\n2. Migrate connection\n3. Show congestion stats\n4. Quit\nYour choice: ")
            
            if choice == '1':
                logger.info("\nPhase 2: Requesting video file...")
                success = await client.request_file("movie.mp4")
                if not success:
                    logger.error("Video transfer failed")
                    
            elif choice == '2':
                # 3. 连接迁移
                logger.info("\nPhase 3: Connection migration...")
                print("\nAvailable interfaces:")
                for name in client.interfaces:
                    print(f"- {name}")
                
                iface = input("\nEnter interface name to migrate to: ")
                try:
                    await client.migrate_to_interface(iface)
                    logger.info(f"Successfully migrated to interface: {iface}")
                except Exception as e:
                    logger.error(f"Migration failed: {e}")
            
            elif choice == '3':
                # 显示拥塞控制统计信息
                client.print_congestion_stats()
                    
            elif choice == '4':
                logger.info("Exiting...")
                break
            else:
                print("Invalid choice, please try again")
    
    except KeyboardInterrupt:
        logger.info("Client stopped by user")
    except Exception as e:
        logger.error(f"Client error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 