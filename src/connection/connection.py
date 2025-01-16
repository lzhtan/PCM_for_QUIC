from dataclasses import dataclass
from typing import Dict, Optional, Set
import asyncio
import logging
import os
from ..crypto.tls import TlsContext, TlsState
from ..packet.header import PacketType, Header
from ..packet.frame import Frame, PathChallengeFrame, PathResponseFrame
from ..packet.packet_processor import PacketProcessor

logger = logging.getLogger("quic")

@dataclass
class Path:
    """表示一个网络路径"""
    local_addr: tuple[str, int]
    peer_addr: tuple[str, int]
    is_validated: bool = False

class QuicConnection:
    """QUIC 连接类"""
    def __init__(self, connection_id: bytes, is_client: bool = False):
        self.connection_id = connection_id
        self.peer_connection_id: Optional[bytes] = None
        
        # 添加日志
        logger.info(f"Creating {'client' if is_client else 'server'} connection with CID: {connection_id.hex()}")
        
        # 路径管理
        self.active_path: Optional[Path] = None
        self.validating_paths: Dict[tuple[str, int], Path] = {}
        
        # 路径验证
        self.pending_path_challenges: Dict[bytes, Path] = {}
        
        # TLS 上下文
        self.tls = TlsContext(is_client)
        
        # 连接状态
        self.is_client = is_client
        self.is_established = False
        
        # 传输实例
        self.transport = None
    
    async def handle_path_challenge(self, challenge_data: bytes):
        """处理 PATH_CHALLENGE 帧"""
        # 发送 PATH_RESPONSE
        await self.send_path_response(challenge_data)
        
    async def send_path_challenge(self, path: Path):
        """发送 PATH_CHALLENGE 帧"""
        challenge_data = os.urandom(8)
        self.pending_path_challenges[challenge_data] = path
        # TODO: 实际发送 PATH_CHALLENGE 帧
        
    async def handle_path_response(self, response_data: bytes):
        """处理 PATH_RESPONSE 帧"""
        if response_data in self.pending_path_challenges:
            path = self.pending_path_challenges.pop(response_data)
            path.is_validated = True
            logger.info(f"路径已验证: {path.peer_addr}") 
    
    async def start_handshake(self):
        """开始握手"""
        if not self.is_client:
            raise RuntimeError("只有客户端可以主动开始握手")
        
        # 创建 Initial 包
        header = Header(
            packet_type=PacketType.INITIAL,
            destination_connection_id=self.peer_connection_id or os.urandom(8),
            source_connection_id=self.connection_id
        )
        
        # 添加日志
        logger.info(f"Starting handshake with source CID: {self.connection_id.hex()}, "
                   f"destination CID: {header.destination_connection_id.hex()}")
        
        # 添加公钥
        public_key = self.tls.get_public_key()
        
        # 创建并发送 Initial 包
        packet = PacketProcessor.create_packet(header, [])
        
        # 通过活动路径发送
        if not self.active_path:
            raise RuntimeError("No active path available")
            
        # 记录日志
        logger.info(f"Sending Initial packet to {self.active_path.peer_addr}")
        
        # 发送数据包
        if self.transport:
            # 发送多次以防丢包
            for _ in range(3):
                self.transport.send_datagram(packet, self.active_path.peer_addr)
                await asyncio.sleep(0.1)
        else:
            logger.error("No transport available for sending")
        
        # 更新状态
        self.tls.state = TlsState.WAIT_HANDSHAKE
    
    async def handle_handshake(self, data: bytes):
        """处理握手数据"""
        if self.is_established:
            return
        
        # 提取对方的公钥
        # TODO: 实际应该从 Initial 包中提取
        peer_public_key = data[:32]
        
        # 计算共享密钥
        self.tls.compute_secrets(peer_public_key)
        
        if not self.is_client:
            # 服务端发送响应
            # TODO: 发送服务端的公钥
            pass
        
        self.is_established = True 
    
    async def validate_path(self, path: Path):
        """验证新路径"""
        challenge_data = os.urandom(8)
        self.pending_path_challenges[challenge_data] = path
        
        # 创建 PATH_CHALLENGE 帧
        frame = PathChallengeFrame(challenge_data)
        packet = PacketProcessor.create_packet(
            Header(
                PacketType.SHORT,
                self.peer_connection_id,
                self.connection_id
            ),
            [frame]
        )
        
        # 发送验证包
        if self.transport:
            self.transport.send_datagram(packet, path.peer_addr)
            logger.info(f"Sent PATH_CHALLENGE to {path.peer_addr}")
        else:
            logger.error("No transport available for sending PATH_CHALLENGE") 