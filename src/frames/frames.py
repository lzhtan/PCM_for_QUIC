class FileResponseFrame:
    """文件响应帧"""
    def __init__(self, file_size: int, chunk_size: int, total_chunks: int = None):
        self.file_size = file_size
        self.chunk_size = chunk_size
        self.total_chunks = total_chunks or math.ceil(file_size / chunk_size)
        
    def to_bytes(self) -> bytes:
        return struct.pack('>QQI', self.file_size, self.chunk_size, self.total_chunks)
        
    @classmethod
    def from_bytes(cls, data: bytes) -> 'FileResponseFrame':
        file_size, chunk_size, total_chunks = struct.unpack('>QQI', data)
        return cls(file_size, chunk_size, total_chunks)

class FileDataFrame:
    """文件数据帧"""
    def __init__(self, chunk_id: int, data: bytes):
        self.chunk_id = chunk_id
        self.data = data
        
    def to_bytes(self) -> bytes:
        return struct.pack('>I', self.chunk_id) + self.data
        
    @classmethod
    def from_bytes(cls, data: bytes) -> 'FileDataFrame':
        chunk_id = struct.unpack('>I', data[:4])[0]
        return cls(chunk_id, data[4:]) 