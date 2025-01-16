from enum import Enum
from dataclasses import dataclass
import os
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class PacketType(Enum):
    """QUIC 数据包类型"""
    INITIAL = 0x0
    HANDSHAKE = 0x2
    SHORT = 0x40

@dataclass
class Header:
    """QUIC 包头基类"""
    packet_type: PacketType
    destination_connection_id: bytes
    source_connection_id: bytes
    
    @staticmethod
    def generate_connection_id() -> bytes:
        """生成一个新的连接 ID"""
        cid = os.urandom(8)  # 使用 8 字节长度的 CID
        logger.info(f"Generated new Connection ID: {cid.hex()}")
        return cid

    @staticmethod
    def parse(data: bytes) -> Tuple['Header', int]:
        """从字节解析头部"""
        if len(data) < 2:
            raise ValueError("数据太短")
            
        packet_type = PacketType(data[0])
        pos = 1
        
        dcid_len = data[pos]
        pos += 1
        destination_connection_id = data[pos:pos+dcid_len]
        pos += dcid_len
        
        scid_len = data[pos]
        pos += 1
        source_connection_id = data[pos:pos+scid_len]
        pos += scid_len
        
        logger.debug(f"Parsed header with CIDs - Source: {source_connection_id.hex()}, "
                    f"Destination: {destination_connection_id.hex()}")
        
        return Header(packet_type, destination_connection_id, source_connection_id), pos

    def to_bytes(self) -> bytes:
        """将头部转换为字节"""
        result = bytearray()
        result.extend([self.packet_type.value])
        result.extend(len(self.destination_connection_id).to_bytes(1, "big"))
        result.extend(self.destination_connection_id)
        result.extend(len(self.source_connection_id).to_bytes(1, "big"))
        result.extend(self.source_connection_id)
        logger.debug(f"Serialized header with CIDs - Source: {self.source_connection_id.hex()}, "
                    f"Destination: {self.destination_connection_id.hex()}")
        return bytes(result) 