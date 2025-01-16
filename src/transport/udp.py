import asyncio
import logging
from typing import Optional, Callable, Dict
from ..packet.header import Header, PacketType
from ..packet.packet_processor import PacketProcessor
from ..connection.connection import QuicConnection, Path
from ..packet.frame import PathChallengeFrame, PathResponseFrame
from ..crypto.tls import TlsContext

logger = logging.getLogger("quic.transport")

class QuicTransport:
    """QUIC UDP 传输层"""
    
    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.connections: Dict[bytes, QuicConnection] = {}  # connection_id -> connection
        self._local_addr: Optional[tuple[str, int]] = None
        self.on_handshake_complete = None  # 添加回调
    
    async def create_endpoint(self, host: str, port: int):
        """创建 UDP 端点"""
        loop = asyncio.get_running_loop()
        
        transport, _ = await loop.create_datagram_endpoint(
            lambda: QuicDatagramProtocol(self),
            local_addr=(host, port)
        )
        
        self.transport = transport
        self._local_addr = (host, port)
        logger.info(f"QUIC endpoint created on {host}:{port}")
    
    def connection_made(self, transport: asyncio.DatagramTransport):
        """连接建立回调"""
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        """收到数据包回调"""
        try:
            # 解析包头
            header, consumed = Header.parse(data)
            logger.info(f"Received packet type {header.packet_type} from {addr}")
            logger.info(f"Packet CIDs - Source: {header.source_connection_id.hex()}, "
                       f"Destination: {header.destination_connection_id.hex()}")
            
            # 查找或创建连接
            connection = self.connections.get(header.destination_connection_id)
            
            if connection is None:
                if header.packet_type == PacketType.INITIAL:
                    # 新连接
                    connection = QuicConnection(header.destination_connection_id, is_client=False)
                    connection.transport = self
                    self.connections[header.destination_connection_id] = connection
                    logger.info(f"New connection from {addr}")
                    
                    # 处理 Initial 包
                    if hasattr(self, 'handle_initial_packet'):
                        asyncio.create_task(
                            self.handle_initial_packet(connection, header, data[consumed:], addr)
                        )
                else:
                    logger.warning(f"Received packet for unknown connection from {addr}")
                    return
            else:
                # 现有连接
                if header.packet_type == PacketType.INITIAL and connection.is_client:
                    logger.info("Received Initial response as client")
                    connection.peer_connection_id = header.source_connection_id
                    if self.on_handshake_complete:
                        self.on_handshake_complete()
                    return
            
            # 更新路径信息
            if connection.active_path is None:
                connection.active_path = Path(self._local_addr, addr)
            elif addr != connection.active_path.peer_addr:
                # 可能的路径迁移
                self._handle_path_migration(connection, addr)
            
            # 处理数据包
            self._process_packet(connection, data[consumed:], addr)
            
        except Exception as e:
            logger.error(f"Error processing packet from {addr}: {e}", exc_info=True)
    
    def _handle_path_migration(self, connection: QuicConnection, new_addr: tuple[str, int]):
        """处理可能的路径迁移"""
        logger.info(f"Potential path migration detected: {new_addr}")
        
        # 创建新路径
        new_path = Path(self._local_addr, new_addr)
        connection.validating_paths[new_addr] = new_path
        
        # 发起路径验证
        asyncio.create_task(connection.send_path_challenge(new_path))
    
    def _process_packet(self, connection: QuicConnection, payload: bytes, 
                       addr: tuple[str, int]):
        """处理数据包负载"""
        try:
            logger.info(f"Processing packet from {addr}, payload length: {len(payload)}")
            
            # 如果是空负载，可能是握手包
            if len(payload) < 2:
                return
            
            frames_length = int.from_bytes(payload[:2], "big")
            frames_data = payload[2:2+frames_length]
            
            # 解析帧
            frames = PacketProcessor.parse_frames(frames_data)
            
            # 处理每个帧
            for frame in frames:
                if isinstance(frame, PathChallengeFrame):
                    logger.info(f"Received PATH_CHALLENGE from {addr}")
                    response = PathResponseFrame(frame.data)
                    response_packet = PacketProcessor.create_packet(
                        Header(
                            PacketType.SHORT,
                            connection.peer_connection_id,
                            connection.connection_id
                        ),
                        [response]
                    )
                    self.send_datagram(response_packet, addr)
                    
                elif isinstance(frame, PathResponseFrame):
                    logger.info(f"Received PATH_RESPONSE from {addr}")
                    if frame.data in connection.pending_path_challenges:
                        path = connection.pending_path_challenges[frame.data]
                        path.is_validated = True
                        if addr == path.peer_addr:
                            connection.active_path = path
                            logger.info(f"Path migration complete: {addr}")
                
        except Exception as e:
            logger.error(f"Error processing frames: {e}")
    
    def send_datagram(self, data: bytes, addr: tuple[str, int]):
        """发送数据包"""
        if self.transport:
            self.transport.sendto(data, addr)

class QuicDatagramProtocol(asyncio.DatagramProtocol):
    """QUIC UDP 协议处理"""
    
    def __init__(self, quic_transport: QuicTransport):
        self.quic_transport = quic_transport
    
    def connection_made(self, transport: asyncio.DatagramTransport):
        self.quic_transport.connection_made(transport)
    
    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        self.quic_transport.datagram_received(data, addr) 