from typing import List, Optional
from .header import Header, PacketType
from .frame import Frame, FrameType, PathChallengeFrame, PathResponseFrame, FileRequestFrame, FileResponseFrame, FileDataFrame
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
            
            if frame_type == FrameType.FILE_REQUEST.value:
                filename_length = int.from_bytes(data[pos:pos+2], 'big')
                pos += 2
                filename = data[pos:pos+filename_length].decode('utf-8')
                pos += filename_length
                frames.append(FileRequestFrame(filename))
                
            elif frame_type == FrameType.FILE_RESPONSE.value:
                file_size = int.from_bytes(data[pos:pos+8], 'big')
                chunk_size = int.from_bytes(data[pos+8:pos+12], 'big')
                pos += 12
                frames.append(FileResponseFrame(file_size, chunk_size))
                
            elif frame_type == FrameType.FILE_DATA.value:
                chunk_id = int.from_bytes(data[pos:pos+4], 'big')
                data_length = int.from_bytes(data[pos+4:pos+8], 'big')
                pos += 8
                chunk_data = data[pos:pos+data_length]
                pos += data_length
                frames.append(FileDataFrame(chunk_id, chunk_data))
                
            elif frame_type == FrameType.PATH_CHALLENGE.value:
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