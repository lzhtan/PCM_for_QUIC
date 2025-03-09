from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple, List
import asyncio
import logging
import os
from ..crypto.tls import TlsContext, TlsState
from ..packet.header import PacketType, Header
from ..packet.frame import Frame, PathChallengeFrame, PathResponseFrame
from ..packet.packet_processor import PacketProcessor
from ..congestion.cubic import CubicCongestionControl
import time

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
        self.paths: List[Path] = []
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
        
        # 添加拥塞控制
        self.congestion_control = CubicCongestionControl()
        
        # 添加 RTT 测量
        self.rtt_samples = []
        self.smoothed_rtt = 0.1  # 初始值 100ms
        self.rtt_variance = 0
        self.min_rtt = float('inf')
        self.latest_rtt = 0
        
        # 添加包序号跟踪
        self.next_packet_number = 0
        self.largest_acked_packet = 0
        self.sent_packets = {}  # packet_number -> (send_time, size)
        self.ack_queue = []  # 待确认的包序号队列
    
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
        self._send_packet(packet, self.active_path.peer_addr)
        
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
        logger.info(f"开始验证路径: {path.local_addr} -> {path.peer_addr}")
        
        # 添加新路径
        self.paths.append(path)
        
        # 切换到新路径
        old_path = self.active_path
        self.active_path = path
        
        # 发送路径验证包
        # 在实际实现中，应该发送 PATH_CHALLENGE 帧
        # 这里简化为发送一个 Short 包
        header = Header(
            packet_type=PacketType.SHORT,
            destination_connection_id=self.peer_connection_id,
            source_connection_id=self.connection_id
        )
        
        packet = PacketProcessor.create_packet(header, [])
        success = self._send_packet(packet, path.peer_addr)
        
        if success:
            logger.info(f"路径验证包已发送到 {path.peer_addr}")
            # 在实际实现中，应该等待 PATH_RESPONSE
            # 这里简化为直接标记路径为已验证
            path.is_validated = True
            return True
        else:
            logger.error(f"发送路径验证包失败")
            # 恢复到旧路径
            self.active_path = old_path
            return False

    def _send_packet(self, packet: bytes, addr: tuple):
        """发送数据包，考虑拥塞控制"""
        # 检查是否可以发送
        if not self.congestion_control.can_send_packet():
            logger.debug("拥塞控制阻止发送数据包")
            return False
        
        # 记录发送时间和大小
        packet_number = self.next_packet_number
        self.next_packet_number += 1
        self.sent_packets[packet_number] = (time.time(), len(packet))
        
        # 通知拥塞控制
        self.congestion_control.on_packet_sent(len(packet))
        
        # 实际发送数据包
        if self.transport:
            self.transport.send_datagram(packet, addr)
            return True
        return False
    
    def process_packet(self, packet: bytes, addr: Tuple[str, int]):
        """处理接收到的数据包"""
        # 解析数据包
        try:
            header, frames = PacketProcessor.parse_packet(packet)
            
            # 更新对端连接 ID
            if self.peer_connection_id is None and header.source_connection_id:
                self.peer_connection_id = header.source_connection_id
                logger.info(f"设置对端连接 ID: {self.peer_connection_id.hex()}")
            
            # 处理不同类型的数据包
            if header.packet_type == PacketType.INITIAL:
                self._handle_initial_packet(header, frames, addr)
            elif header.packet_type == PacketType.HANDSHAKE:
                self._handle_handshake_packet(header, frames, addr)
            elif header.packet_type == PacketType.SHORT:
                self._handle_short_packet(header, frames, addr)
            
            # 处理确认
            self._process_ack(packet)
            
            return header, frames
        except Exception as e:
            logger.error(f"处理数据包时出错: {e}")
            return None, []
    
    def _process_ack(self, packet: bytes):
        """处理确认信息"""
        # 这里简化处理，假设每个收到的包都会触发一个确认
        # 实际实现中，应该从包中提取确认信息
        
        # 生成一个随机的包序号作为被确认的包
        # 在实际实现中，这应该从包中提取
        if self.sent_packets:
            # 随机选择一个已发送但未确认的包进行确认
            # 实际中应该根据包中的确认信息
            packet_number = list(self.sent_packets.keys())[0]
            if packet_number in self.sent_packets:
                send_time, size = self.sent_packets.pop(packet_number)
                current_time = time.time()
                rtt = current_time - send_time
                
                # 确保 RTT 是正值且合理
                if rtt > 0.001:  # 至少 1ms
                    self._update_rtt(rtt)
                    logger.debug(f"测量 RTT: {rtt*1000:.2f} ms, 包序号: {packet_number}")
                else:
                    logger.warning(f"忽略异常 RTT 值: {rtt*1000:.2f} ms")
                    
                self.congestion_control.on_packet_acked(size, max(1, rtt * 1000))  # 确保至少 1ms
                
                # 更新最大确认包序号
                self.largest_acked_packet = max(self.largest_acked_packet, packet_number)
                
                # 丢包检测
                if len(self.sent_packets) > 20 and current_time - list(self.sent_packets.values())[0][0] > 1.0:
                    # 模拟丢包
                    old_packet = list(self.sent_packets.keys())[0]
                    self.on_packet_lost(old_packet)
    
    def on_packet_lost(self, packet_number: int):
        """处理丢包事件"""
        if packet_number in self.sent_packets:
            _, size = self.sent_packets.pop(packet_number)
            self.congestion_control.on_packet_lost(size)
            logger.info(f"检测到丢包: 包序号 {packet_number}")
    
    def _update_rtt(self, sample_rtt: float):
        """更新 RTT 估计"""
        if sample_rtt <= 0:
            logger.warning(f"忽略非法 RTT 样本: {sample_rtt}")
            return
        
        self.latest_rtt = sample_rtt
        
        # 更新最小 RTT
        if self.min_rtt == float('inf') or sample_rtt < self.min_rtt:
            self.min_rtt = sample_rtt
            logger.debug(f"更新最小 RTT: {self.min_rtt*1000:.2f} ms")
        
        # 初始化
        if self.smoothed_rtt == 0:
            self.smoothed_rtt = sample_rtt
            self.rtt_variance = sample_rtt / 2
            logger.info(f"初始化 RTT 估计: {self.smoothed_rtt*1000:.2f} ms")
        else:
            # 更新 RTT 变异性
            rtt_diff = abs(self.smoothed_rtt - sample_rtt)
            self.rtt_variance = 0.75 * self.rtt_variance + 0.25 * rtt_diff
            
            # 更新平滑 RTT
            self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * sample_rtt
            logger.debug(f"更新平滑 RTT: {self.smoothed_rtt*1000:.2f} ms")
        
        self.rtt_samples.append(sample_rtt)
        if len(self.rtt_samples) > 100:
            self.rtt_samples.pop(0)
    
    def _handle_initial_packet(self, header, frames, addr):
        """处理 Initial 包"""
        logger.info(f"收到 Initial 包，源连接 ID: {header.source_connection_id.hex()}")
        
        # 如果是服务器，需要响应握手
        if not self.is_client:
            # 设置对端连接 ID
            self.peer_connection_id = header.source_connection_id
            
            # 创建路径
            path = Path(
                self.transport.transport.get_extra_info('sockname'),
                addr
            )
            self.paths.append(path)
            self.active_path = path
            
            # 发送握手响应
            response_header = Header(
                packet_type=PacketType.HANDSHAKE,
                destination_connection_id=self.peer_connection_id,
                source_connection_id=self.connection_id
            )
            
            response_packet = PacketProcessor.create_packet(response_header, [])
            self._send_packet(response_packet, addr)
            logger.info(f"发送握手响应到 {addr}")
    
    def _handle_handshake_packet(self, header, frames, addr):
        """处理 Handshake 包"""
        logger.info(f"收到 Handshake 包，源连接 ID: {header.source_connection_id.hex()}")
        
        # 设置连接为已建立
        self.is_established = True
        
        # 如果是客户端，通知握手完成
        if self.is_client and self.transport and hasattr(self.transport, 'on_handshake_complete'):
            self.transport.on_handshake_complete()
    
    def _handle_short_packet(self, header, frames, addr):
        """处理 Short 包"""
        if not self.is_established:
            logger.warning("收到 Short 包，但连接尚未建立")
            return
        
        # 处理各种帧
        for frame in frames:
            # 根据帧类型处理
            frame_type = type(frame).__name__
            logger.debug(f"处理 {frame_type} 帧")
            
            # 后续这里应该添加对不同类型帧的处理，例如 PathChallengeFrame, PathResponseFrame 等
    
    def get_congestion_stats(self) -> dict:
        """获取拥塞控制统计信息"""
        stats = self.congestion_control.get_stats()
        stats.update({
            "smoothed_rtt_ms": self.smoothed_rtt * 1000,
            "min_rtt_ms": self.min_rtt * 1000 if self.min_rtt != float('inf') else 0,
            "latest_rtt_ms": self.latest_rtt * 1000,
            "rtt_variance_ms": self.rtt_variance * 1000,
            "next_packet_number": self.next_packet_number,
            "largest_acked_packet": self.largest_acked_packet,
            "packets_in_flight": len(self.sent_packets)
        })
        return stats