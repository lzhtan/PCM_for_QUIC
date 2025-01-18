from enum import Enum
from dataclasses import dataclass
from typing import Optional

class FrameType(Enum):
    """QUIC 帧类型"""
    PADDING = 0x00
    PATH_CHALLENGE = 0x1a
    PATH_RESPONSE = 0x1b
    NEW_CONNECTION_ID = 0x18
    FILE_REQUEST = 0x1c
    FILE_RESPONSE = 0x1d
    FILE_DATA = 0x1e

@dataclass
class Frame:
    """QUIC 帧基类"""
    type: FrameType

@dataclass
class PathChallengeFrame(Frame):
    """PATH_CHALLENGE 帧"""
    data: bytes  # 8 字节的随机数据
    
    def __init__(self, data: bytes):
        super().__init__(FrameType.PATH_CHALLENGE)
        if len(data) != 8:
            raise ValueError("PATH_CHALLENGE 数据必须是 8 字节")
        self.data = data
    
    def to_bytes(self) -> bytes:
        return bytes([self.type.value]) + self.data

@dataclass
class PathResponseFrame(Frame):
    """PATH_RESPONSE 帧"""
    data: bytes  # 对应 PATH_CHALLENGE 的数据
    
    def __init__(self, data: bytes):
        super().__init__(FrameType.PATH_RESPONSE)
        if len(data) != 8:
            raise ValueError("PATH_RESPONSE 数据必须是 8 字节")
        self.data = data
    
    def to_bytes(self) -> bytes:
        return bytes([self.type.value]) + self.data

@dataclass
class NewConnectionIdFrame(Frame):
    """NEW_CONNECTION_ID 帧"""
    sequence_number: int
    connection_id: bytes
    
    def __init__(self, sequence_number: int, connection_id: bytes):
        super().__init__(FrameType.NEW_CONNECTION_ID)
        self.sequence_number = sequence_number
        self.connection_id = connection_id
    
    def to_bytes(self) -> bytes:
        result = bytearray([self.type.value])
        # 序列号
        result.extend(self.sequence_number.to_bytes(2, "big"))
        # 连接 ID
        result.append(len(self.connection_id))
        result.extend(self.connection_id)
        return bytes(result) 

@dataclass
class FileRequestFrame(Frame):
    """文件请求帧"""
    filename: str
    
    def __init__(self, filename: str):
        super().__init__(FrameType.FILE_REQUEST)
        self.filename = filename
    
    def to_bytes(self) -> bytes:
        filename_bytes = self.filename.encode('utf-8')
        return bytes([self.type.value]) + len(filename_bytes).to_bytes(2, 'big') + filename_bytes

@dataclass
class FileResponseFrame(Frame):
    """文件响应帧"""
    file_size: int
    chunk_size: int = 8192  # 默认块大小
    
    def __init__(self, file_size: int, chunk_size: int = 8192):
        super().__init__(FrameType.FILE_RESPONSE)
        self.file_size = file_size
        self.chunk_size = chunk_size
    
    def to_bytes(self) -> bytes:
        return bytes([self.type.value]) + self.file_size.to_bytes(8, 'big') + self.chunk_size.to_bytes(4, 'big')

@dataclass
class FileDataFrame(Frame):
    """文件数据帧"""
    chunk_id: int
    data: bytes
    
    def __init__(self, chunk_id: int, data: bytes):
        super().__init__(FrameType.FILE_DATA)
        self.chunk_id = chunk_id
        self.data = data
    
    def to_bytes(self) -> bytes:
        return bytes([self.type.value]) + self.chunk_id.to_bytes(4, 'big') + len(self.data).to_bytes(4, 'big') + self.data 