import asyncio
import logging
from src.transport.udp import QuicTransport
from src.connection.connection import QuicConnection, Path
from src.packet.header import Header, PacketType
from src.packet.packet_processor import PacketProcessor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("quic.server")

class QuicServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.transport = QuicTransport()
        
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
    # 默认监听所有接口
    server = QuicServer("0.0.0.0", 5000)
    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 