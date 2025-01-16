from dataclasses import dataclass
from enum import Enum
import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class TlsState(Enum):
    """TLS 状态"""
    INITIAL = 0
    WAIT_HANDSHAKE = 1
    CONNECTED = 2

@dataclass
class TlsContext:
    """TLS 上下文"""
    is_client: bool
    state: TlsState = TlsState.INITIAL
    
    # 密钥交换
    private_key: Optional[x25519.X25519PrivateKey] = None
    peer_public_key: Optional[x25519.X25519PublicKey] = None
    
    # 密钥
    traffic_secret: Optional[bytes] = None
    
    def __init__(self, is_client: bool):
        self.is_client = is_client
        self.state = TlsState.INITIAL
        self.private_key = x25519.X25519PrivateKey.generate()
    
    def get_public_key(self) -> bytes:
        """获取公钥字节"""
        return self.private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
    
    def compute_secrets(self, peer_public_key_bytes: bytes):
        """计算共享密钥"""
        self.peer_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_public_key_bytes)
        
        # 计算共享密钥
        shared_key = self.private_key.exchange(self.peer_public_key)
        
        # 使用 HKDF 派生密钥
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"quic key",
        )
        self.traffic_secret = hkdf.derive(shared_key) 