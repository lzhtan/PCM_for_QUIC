from typing import List
import struct

class PacketProcessor:
    @staticmethod
    def create_packet(header: Header, frames: List[Frame]) -> bytes:
        """创建数据包"""
        # 序列化帧
        frames_data = b''
        for frame in frames:
            frame_type = type(frame).__name__.encode()
            frame_data = frame.to_bytes()
            frames_data += struct.pack('>H', len(frame_type))  # 帧类型名称长度
            frames_data += frame_type  # 帧类型名称
            frames_data += struct.pack('>I', len(frame_data))  # 帧数据长度
            frames_data += frame_data  # 帧数据
            
        # 序列化头部
        header_data = header.to_bytes()
        
        # 组合数据包
        return header_data + frames_data
        
    @staticmethod
    def parse_packet(data: bytes) -> Packet:
        """解析数据包"""
        # 解析头部
        header = Header.from_bytes(data[:Header.SIZE])
        
        # 解析帧
        frames = []
        pos = Header.SIZE
        while pos < len(data):
            # 读取帧类型名称长度
            type_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            
            # 读取帧类型名称
            frame_type = data[pos:pos+type_len].decode()
            pos += type_len
            
            # 读取帧数据长度
            frame_len = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            
            # 读取帧数据
            frame_data = data[pos:pos+frame_len]
            pos += frame_len
            
            # 根据帧类型创建对应的帧对象
            frame_class = globals()[frame_type]
            frame = frame_class.from_bytes(frame_data)
            frames.append(frame)
            
        return Packet(header, frames) 