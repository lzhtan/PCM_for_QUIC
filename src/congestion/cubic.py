import time
import math
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger("quic.congestion.cubic")

class CongestionState(Enum):
    """拥塞控制状态"""
    SLOW_START = 0
    CONGESTION_AVOIDANCE = 1
    RECOVERY = 2

@dataclass
class CongestionEvent:
    """拥塞事件"""
    timestamp: float
    lost_packets: int
    rtt: float

class CubicCongestionControl:
    """CUBIC 拥塞控制算法实现"""
    
    # CUBIC 参数
    BETA_CUBIC = 0.7  # 乘性减小因子
    C = 0.4  # CUBIC 增长因子
    
    # 通用拥塞控制参数
    INITIAL_WINDOW = 10  # 初始窗口 (packets)
    MIN_WINDOW = 2  # 最小窗口 (packets)
    MAX_WINDOW = 1000  # 最大窗口 (packets)
    SLOW_START_THRESHOLD = 50  # 慢启动阈值 (packets)
    
    def __init__(self):
        # 拥塞窗口 (packets)
        self.cwnd = self.INITIAL_WINDOW
        # 慢启动阈值 (packets)
        self.ssthresh = self.SLOW_START_THRESHOLD
        # 当前状态
        self.state = CongestionState.SLOW_START
        # 最后一次拥塞事件时间
        self.last_congestion_time = 0
        # 最后一次拥塞事件前的窗口大小
        self.w_max = 0
        # 最后一次窗口更新时间
        self.last_update_time = time.time()
        # RTT 估计 (ms)
        self.rtt_estimate = 100  # 初始估计值
        # 已发送但未确认的数据包数量
        self.in_flight = 0
        
        logger.info("CUBIC 拥塞控制初始化完成")
    
    def on_packet_sent(self, packet_size: int):
        """发送数据包时调用"""
        self.in_flight += 1
    
    def on_packet_acked(self, packet_size: int, rtt: float):
        """确认数据包时调用"""
        self.in_flight -= 1
        self.rtt_estimate = 0.8 * self.rtt_estimate + 0.2 * rtt  # 简单 EWMA
        
        current_time = time.time()
        time_elapsed = current_time - self.last_update_time
        self.last_update_time = current_time
        
        if self.state == CongestionState.SLOW_START:
            # 慢启动阶段: 每个 ACK 增加一个 MSS
            self.cwnd += 1
            logger.debug(f"慢启动: cwnd = {self.cwnd}")
            
            # 检查是否应该退出慢启动
            if self.cwnd >= self.ssthresh:
                logger.info(f"退出慢启动: cwnd = {self.cwnd}, ssthresh = {self.ssthresh}")
                self.state = CongestionState.CONGESTION_AVOIDANCE
        
        elif self.state == CongestionState.CONGESTION_AVOIDANCE:
            # 拥塞避免阶段: 使用 CUBIC 算法
            self._cubic_update(current_time)
        
        elif self.state == CongestionState.RECOVERY:
            # 恢复阶段: 使用 CUBIC 算法
            self._cubic_update(current_time)
            
            # 如果所有丢失的包都已经重传并确认，退出恢复阶段
            if self.in_flight <= self.cwnd:
                logger.info(f"退出恢复阶段: cwnd = {self.cwnd}")
                self.state = CongestionState.CONGESTION_AVOIDANCE
    
    def on_packet_lost(self, packet_size: int):
        """丢包时调用"""
        # 记录当前最大窗口
        self.w_max = self.cwnd
        
        # 乘性减小
        self.cwnd = max(self.MIN_WINDOW, int(self.cwnd * self.BETA_CUBIC))
        self.ssthresh = self.cwnd
        
        # 更新状态和时间
        self.state = CongestionState.RECOVERY
        self.last_congestion_time = time.time()
        
        logger.info(f"检测到丢包: cwnd = {self.cwnd}, ssthresh = {self.ssthresh}")
    
    def _cubic_update(self, current_time: float):
        """CUBIC 窗口更新"""
        # CUBIC 公式: W(t) = C*(t-K)^3 + W_max
        # 其中 K = (W_max*beta/C)^(1/3)
        
        # 计算自上次拥塞事件以来的时间 (秒)
        t = current_time - self.last_congestion_time
        if t < 0.001:  # 避免除零错误
            return
        
        # 计算 K (时间偏移)
        k = pow(self.w_max * (1 - self.BETA_CUBIC) / self.C, 1/3)
        
        # 计算新的窗口大小
        w_cubic = self.C * pow(t - k, 3) + self.w_max
        
        # 确保窗口在合理范围内
        w_cubic = max(self.MIN_WINDOW, min(self.MAX_WINDOW, w_cubic))
        
        # 更新拥塞窗口
        if w_cubic > self.cwnd:
            # 增加窗口
            self.cwnd = min(self.MAX_WINDOW, int(w_cubic))
        
        logger.debug(f"CUBIC 更新: t = {t:.3f}, K = {k:.3f}, w_cubic = {w_cubic:.2f}, cwnd = {self.cwnd}")
    
    def can_send_packet(self) -> bool:
        """检查是否可以发送新的数据包"""
        return self.in_flight < self.cwnd
    
    def get_congestion_window(self) -> int:
        """获取当前拥塞窗口大小"""
        return self.cwnd
    
    def get_state(self) -> CongestionState:
        """获取当前拥塞控制状态"""
        return self.state
    
    def get_stats(self) -> dict:
        """获取拥塞控制统计信息"""
        return {
            "cwnd": self.cwnd,
            "ssthresh": self.ssthresh,
            "state": self.state.name,
            "rtt_ms": self.rtt_estimate,
            "in_flight": self.in_flight,
            "w_max": self.w_max
        } 