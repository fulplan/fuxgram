
from typing import Dict, List


class DecoyServices:
    """
    Run real services to appear legitimate:
    - Legitimate web application (WordPress, Nextcloud)
    - SSH server (real, working)
    - FTP server
    - Mail server
    - DNS server
    """

    def __init__(self):
        self.services = [
            {
                "name": "WordPress",
                "port": 80,
                "protocol": "HTTP",
                "status": "running"
            },
            {
                "name": "SSH",
                "port": 22,
                "protocol": "SSH",
                "status": "running"
            },
            {
                "name": "SMTP",
                "port": 25,
                "protocol": "SMTP",
                "status": "running"
            },
            {
                "name": "POP3",
                "port": 110,
                "protocol": "POP3",
                "status": "running"
            },
            {
                "name": "IMAP",
                "port": 143,
                "protocol": "IMAP",
                "status": "running"
            }
        ]

    def setup_decoys(self) -> Dict:
        """
        WordPress on port 80
        SSH on port 22
        Mail on ports 25, 110, 143
        Real certificates
        Real data/users
        Working services

        C2 hidden in encrypted channel of legitimate service
        """
        decoy_config = {
            "services": self.services,
            "certificates": "Let's Encrypt",
            "dummy_users": [
                "admin@legit-site.com",
                "user@legit-site.com",
                "support@legit-site.com"
            ],
            "c2_channel": {
                "hidden_in": "HTTPS over port 443",
                "obfuscation": "TLS encrypted traffic"
            }
        }
        
        return decoy_config
