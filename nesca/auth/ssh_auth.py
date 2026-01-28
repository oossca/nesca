import paramiko
import socket
import time
from typing import Optional
from .base import BaseAuth, AuthResult, auth_registry

class SSHAuth(BaseAuth):
    def __init__(self, target: str, port: int = 22, timeout: float = 5.0):
        super().__init__(target, port, timeout)
    
    def test_credentials(self, username: str, password: str) -> AuthResult:
        start_time = time.time()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=self.target,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            response_time = time.time() - start_time
            ssh.close()
            
            return AuthResult(
                success=True,
                username=username,
                password=password,
                message="SSH login successful",
                response_time=response_time
            )
            
        except paramiko.AuthenticationException:
            response_time = time.time() - start_time
            return AuthResult(
                success=False,
                username=username,
                password=password,
                message="Authentication failed",
                response_time=response_time
            )
        except paramiko.SSHException as e:
            response_time = time.time() - start_time
            return AuthResult(
                success=False,
                username=username,
                password=password,
                message=f"SSH error: {str(e)}",
                response_time=response_time
            )
        except socket.timeout:
            response_time = time.time() - start_time
            return AuthResult(
                success=False,
                username=username,
                password=password,
                message="Connection timeout",
                response_time=response_time
            )
        except socket.error as e:
            response_time = time.time() - start_time
            return AuthResult(
                success=False,
                username=username,
                password=password,
                message=f"Connection error: {str(e)}",
                response_time=response_time
            )
        except Exception as e:
            response_time = time.time() - start_time
            return AuthResult(
                success=False,
                username=username,
                password=password,
                message=f"Unexpected error: {str(e)}",
                response_time=response_time
            )
        finally:
            try:
                ssh.close()
            except:
                pass
    
    def get_service_name(self) -> str:
        return "SSH"

# Register the module
auth_registry.register("SSH", SSHAuth)
auth_registry.register("ssh", SSHAuth)