import os
import json
from typing import Dict, Any, List, Optional
from .logger import get_logger

logger = get_logger(__name__)

class Config:
    """Simple configuration manager for Nesca"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_file()
        self.config = self._load_config()
    
    def _get_default_config_file(self) -> str:
        """Get default config file path"""
        # Try current directory first, then home directory
        current_dir_config = os.path.join(os.getcwd(), 'nesca.conf')
        home_dir_config = os.path.join(os.path.expanduser('~'), '.nesca.conf')
        
        if os.path.exists(current_dir_config):
            return current_dir_config
        elif os.path.exists(home_dir_config):
            return home_dir_config
        else:
            # Create default config in home directory
            return home_dir_config
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or return defaults"""
        default_config = {
            "default_threads": 20,
            "default_timeout": 5.0,
            "default_delay": 0.1,
            "default_format": "json",
            "common_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
                         1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017],
            "quick_usernames": ['admin', 'administrator', 'root', 'user', 'guest'],
            "quick_passwords": ['admin', 'password', '123456', '1234', '12345', 'test', 'guest', 'root']
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                
                # Merge user config with defaults
                default_config.update(user_config)
                logger.info(f"Configuration loaded from: {self.config_file}")
                
            except Exception as e:
                logger.error(f"Failed to load config file {self.config_file}: {str(e)}")
                logger.info("Using default configuration")
        else:
            logger.info("Config file not found, using defaults")
            # Create default config file
            self._save_config(default_config)
        
        return default_config
    
    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Default configuration created at: {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to create config file: {str(e)}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def show_config(self):
        """Display current configuration"""
        print("Nesca Configuration:")
        print("=" * 50)
        print(json.dumps(self.config, indent=2, ensure_ascii=False))
        print("=" * 50)
        print(f"Config file location: {self.config_file}")

# Global configuration instance
config = Config()