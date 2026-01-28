import ftplib
import socket
import time
from typing import Optional
from .base import BaseAuth, AuthResult, auth_registry

class FTPAuth(BaseAuth):
    def __init__(self, target: str, port: int = 21, timeout: float = 5.0):
        super().__init__(target, port, timeout)
    
    def test_credentials(self, username: str, password: str) -> AuthResult:
        start_time = time.time()
        
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=self.timeout)
            
            try:
                ftp.login(username, password)
                response_time = time.time() - start_time
                ftp.quit()
                
                return AuthResult(
                    success=True,
                    username=username,
                    password=password,
                    message="Login successful",
                    response_time=response_time
                )
            except ftplib.error_perm as e:
                response_time = time.time() - start_time
                error_msg = str(e)
                
                if "530" in error_msg:
                    message = "Login incorrect"
                elif "530 Not logged in" in error_msg:
                    message = "Login incorrect"
                else:
                    message = f"Login failed: {error_msg}"
                
                return AuthResult(
                    success=False,
                    username=username,
                    password=password,
                    message=message,
                    response_time=response_time
                )
            finally:
                try:
                    ftp.close()
                except:
                    pass
                    
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
    
    def get_service_name(self) -> str:
        return "FTP"

# Register the module
auth_registry.register("FTP", FTPAuth)
auth_registry.register("ftpd", FTPAuth)