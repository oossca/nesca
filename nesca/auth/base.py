from abc import ABC, abstractmethod
from typing import Tuple, Optional
import time

class AuthResult:
    def __init__(self, success: bool, username: str = "", password: str = "", 
                 message: str = "", response_time: float = 0.0):
        self.success = success
        self.username = username
        self.password = password
        self.message = message
        self.response_time = response_time
    
    def __str__(self):
        if self.success:
            return f"SUCCESS: {self.username}:{self.password} ({self.response_time:.2f}s)"
        else:
            return f"FAILED: {self.username}:{self.password} - {self.message}"

class BaseAuth(ABC):
    def __init__(self, target: str, port: int, timeout: float = 5.0):
        self.target = target
        self.port = port
        self.timeout = timeout
    
    @abstractmethod
    def test_credentials(self, username: str, password: str) -> AuthResult:
        """Test username and password combination"""
        pass
    
    @abstractmethod
    def get_service_name(self) -> str:
        """Get the service name for logging"""
        pass

class AuthModule:
    def __init__(self):
        self.modules = {}
    
    def register(self, service_name: str, auth_class):
        """Register an authentication module"""
        self.modules[service_name.lower()] = auth_class
    
    def get_module(self, service_name: str) -> Optional[BaseAuth]:
        """Get authentication module by service name"""
        auth_class = self.modules.get(service_name.lower())
        if auth_class:
            return auth_class
        return None
    
    def list_services(self) -> list:
        """List all supported services"""
        return list(self.modules.keys())

# Global auth module registry
auth_registry = AuthModule()