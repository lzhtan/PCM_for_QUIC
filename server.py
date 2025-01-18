import asyncio
import logging
from pathlib import Path
from src.transport.udp import QuicTransport
from src.connection.connection import QuicConnection
from src.packet.header import Header, PacketType
from src.packet.packet_processor import PacketProcessor
from src.packet.frame import FileRequestFrame, FileResponseFrame, FileDataFrame

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("quic.server")

class QuicServer:
    def __init__(self, host: str, port: int, resource_path: str):
        self.host = host
        self.port = port
        self.transport = QuicTransport()
        self.transport.server = self
        self.resource_path = Path(resource_path)
        
    async def handle_initial_packet(self, connection: QuicConnection, 
                                  header: Header, payload: bytes, addr: tuple[str, int]):
        """处理 Initial 包"""
        logger.info(f"Handling Initial packet from {addr}")
        
        # 设置连接 ID
        connection.peer_connection_id = header.source_connection_id
        
        # 创建响应包
        response_header = Header(
            packet_type=PacketType.INITIAL,
            destination_connection_id=header.source_connection_id,
            source_connection_id=connection.connection_id
        )
        
        # 获取服务器的公钥
        public_key = connection.tls.get_public_key()
        
        # 创建响应包
        response_packet = PacketProcessor.create_packet(response_header, [])
        
        # 发送响应
        logger.info(f"Sending Initial response to {addr}")
        self.transport.send_datagram(response_packet, addr)
        
        # 更新连接状态
        connection.is_established = True
        logger.info(f"Connection established with {addr}")
    
    async def handle_file_request(self, connection: QuicConnection, 
                                frame: FileRequestFrame, addr: tuple[str, int]):
        """处理文件请求"""
        file_path = self.resource_path / frame.filename
        
        if not file_path.exists():
            logger.error(f"Requested file not found: {frame.filename}")
            return
        
        file_size = file_path.stat().st_size
        chunk_size = 8192  # 8KB chunks
        
        logger.info(f"开始发送文件: {frame.filename}, 大小: {file_size} bytes")
        
        # 发送文件响应
        response_frame = FileResponseFrame(file_size, chunk_size)
        response_packet = PacketProcessor.create_packet(
            Header(
                PacketType.SHORT,
                connection.peer_connection_id,
                connection.connection_id
            ),
            [response_frame]
        )
        self.transport.send_datagram(response_packet, addr)
        
        # 分块发送文件数据
        total_chunks = 0
        with open(file_path, 'rb') as f:
            chunk_id = 0
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                    
                data_frame = FileDataFrame(chunk_id, data)
                data_packet = PacketProcessor.create_packet(
                    Header(
                        PacketType.SHORT,
                        connection.peer_connection_id,
                        connection.connection_id
                    ),
                    [data_frame]
                )
                self.transport.send_datagram(data_packet, addr)
                chunk_id += 1
                total_chunks += 1
                await asyncio.sleep(0.001)  # 防止发送太快
        
        logger.info(f"文件发送完成: {frame.filename}")
        logger.info(f"总共发送了 {total_chunks} 个数据块")
    
    async def start(self):
        """启动 QUIC 服务器"""
        logger.info(f"Starting QUIC server on {self.host}:{self.port}")
        await self.transport.create_endpoint(self.host, self.port)
        
        # 扩展 QuicTransport 的处理逻辑
        self.transport.handle_initial_packet = self.handle_initial_packet
        
        try:
            # 保持服务器运行
            while True:
                await asyncio.sleep(3600)  # 每小时检查一次
        except asyncio.CancelledError:
            logger.info("Server shutting down...")
        finally:
            if self.transport.transport:
                self.transport.transport.close()

async def main():
    # 创建服务器实例，指定监听地址、端口和资源目录
    server = QuicServer("0.0.0.0", 5000, "./resource")
    try:
        await server.start()
        logger.info("Server started on 0.0.0.0:5000")
        # 保持服务器运行
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 