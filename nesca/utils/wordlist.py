import os
from typing import List, Set
from .logger import get_logger

logger = get_logger(__name__)

class WordlistManager:
    def __init__(self, data_dir: str = None):
        if data_dir is None:
            # Default to the data directory in the package
            current_dir = os.path.dirname(os.path.abspath(__file__))
            data_dir = os.path.join(os.path.dirname(current_dir), 'data')
        
        self.data_dir = data_dir
        self.ensure_data_dir()
    
    def ensure_data_dir(self):
        """Ensure the data directory exists"""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            logger.info(f"Created data directory: {self.data_dir}")
    
    def load_wordlist(self, filename: str, unique: bool = True) -> List[str]:
        """Load a wordlist from file"""
        filepath = os.path.join(self.data_dir, filename)
        
        if not os.path.exists(filepath):
            logger.warning(f"Wordlist file not found: {filepath}")
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            
            if unique:
                # Remove duplicates while preserving order
                seen = set()
                unique_words = []
                for word in words:
                    if word not in seen:
                        seen.add(word)
                        unique_words.append(word)
                words = unique_words
            
            logger.info(f"Loaded {len(words)} words from {filename}")
            return words
            
        except Exception as e:
            logger.error(f"Error loading wordlist {filename}: {str(e)}")
            return []
    
    def get_usernames(self, service: str = None) -> List[str]:
        """Get usernames for a specific service or general usernames"""
        if service:
            service_username_file = f"{service.lower()}_login.txt"
            if os.path.exists(os.path.join(self.data_dir, service_username_file)):
                return self.load_wordlist(service_username_file)
        
        # Try general usernames file
        return self.load_wordlist('ftplogin.txt')  # Using ftplogin.txt as general usernames
    
    def get_passwords(self, service: str = None) -> List[str]:
        """Get passwords for a specific service or general passwords"""
        if service:
            service_password_file = f"{service.lower()}pass.txt"
            if os.path.exists(os.path.join(self.data_dir, service_password_file)):
                return self.load_wordlist(service_password_file)
        
        # Try general passwords file
        return self.load_wordlist('pass.txt')
    
    def get_common_ports(self) -> List[int]:
        """Get list of common ports to scan"""
        return [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
        ]
    
    def get_service_ports(self) -> dict:
        """Get service to port mapping"""
        return {
            'FTP': 21,
            'SSH': 22,
            'Telnet': 23,
            'SMTP': 25,
            'DNS': 53,
            'HTTP': 80,
            'POP3': 110,
            'IMAP': 143,
            'HTTPS': 443,
            'MSSQL': 1433,
            'MySQL': 3306,
            'RDP': 3389,
            'PostgreSQL': 5432,
            'VNC': 5900,
            'Redis': 6379,
            'HTTP-Alt': 8080,
            'HTTPS-Alt': 8443,
            'Elasticsearch': 9200,
            'MongoDB': 27017
        }
    
    def create_default_wordlists(self):
        """Create default wordlist files if they don't exist"""
        default_passwords = [
            'admin', 'password', '123456', '1234', '12345', 'test', 'guest',
            'root', 'administrator', 'user', 'demo', 'default', 'pass',
            'password1', '123', '111111', 'qwerty', '000000', 'pwd',
            '123321', 'admin123', 'changeme', '123456789', '12345678',
            'abc123', 'password123', '654321', '1q2w3e4r', '123123',
            '888888', '555555', 'welcome', 'login', '123abc', 'letmein',
            'master', '666666', '999999', '11111111', '1234qwer', '123qwe',
            'qwer1234', '112233', 'password12', 'adminadmin', '1qaz2wsx'
        ]
        
        default_usernames = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest', 'demo',
            'ftp', 'anonymous', 'upload', 'download', 'file', 'data', 'backup',
            'service', 'system', 'manager', 'support', 'operator', 'monitor',
            'control', 'oracle', 'postgres', 'mysql', 'sa', 'tomcat'
        ]
        
        # Create password list
        pass_file = os.path.join(self.data_dir, 'pass.txt')
        if not os.path.exists(pass_file):
            with open(pass_file, 'w') as f:
                for password in default_passwords:
                    f.write(f"{password}\n")
            logger.info(f"Created default password list: {pass_file}")
        
        # Create username list
        username_file = os.path.join(self.data_dir, 'ftplogin.txt')
        if not os.path.exists(username_file):
            with open(username_file, 'w') as f:
                for username in default_usernames:
                    f.write(f"{username}\n")
            logger.info(f"Created default username list: {username_file}")

# Global wordlist manager
wordlist_manager = WordlistManager()