from typing import List, Optional
from .header import Header, PacketType
from .frame import Frame, FrameType, PathChallengeFrame, PathResponseFrame
import logging

logger = logging.getLogger("quic.packet")

class PacketProcessor:
    """QUIC 数据包处理器"""
    
    @staticmethod
    def parse_frames(data: bytes) -> List[Frame]:
        """解析数据包中的帧"""
        frames = []
        pos = 0
        
        while pos < len(data):
            frame_type = data[pos]
            pos += 1
            
            if frame_type == FrameType.PATH_CHALLENGE.value:
                if pos + 8 > len(data):
                    raise ValueError("PATH_CHALLENGE frame too short")
                challenge_data = data[pos:pos+8]
                frames.append(PathChallengeFrame(challenge_data))
                pos += 8
                
            elif frame_type == FrameType.PATH_RESPONSE.value:
                if pos + 8 > len(data):
                    raise ValueError("PATH_RESPONSE frame too short")
                response_data = data[pos:pos+8]
                frames.append(PathResponseFrame(response_data))
                pos += 8
                
            # TODO: 添加其他帧类型的处理
            
        return frames
    
    @staticmethod
    def create_packet(header: Header, frames: List[Frame]) -> bytes:
        """创建完整的数据包"""
        result = bytearray(header.to_bytes())
        
        # 添加所有帧的长度
        frames_length = sum(len(frame.to_bytes()) for frame in frames)
        result.extend(frames_length.to_bytes(2, "big"))
        
        # 添加所有帧
        for frame in frames:
            result.extend(frame.to_bytes())
        
        return bytes(result) 