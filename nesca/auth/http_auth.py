import requests
import base64
import time
import urllib3
from typing import Optional, Dict, Any
from .base import BaseAuth, AuthResult, auth_registry

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPBasicAuth(BaseAuth):
    def __init__(self, target: str, port: int = 80, timeout: float = 5.0, use_ssl: bool = False):
        super().__init__(target, port, timeout)
        self.use_ssl = use_ssl
        self.protocol = "https" if use_ssl else "http"
    
    def _build_url(self, path: str = "/") -> str:
        return f"{self.protocol}://{self.target}:{self.port}{path}"
    
    def test_credentials(self, username: str, password: str) -> AuthResult:
        start_time = time.time()
        
        try:
            # Try basic authentication
            auth_string = f"{username}:{password}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'User-Agent': 'Nesca-Scanner/1.0'
            }
            
            url = self._build_url()
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                return AuthResult(
                    success=True,
                    username=username,
                    password=password,
                    message="HTTP Basic authentication successful",
                    response_time=response_time
                )
            elif response.status_code == 401:
                return AuthResult(
                    success=False,
                    username=username,
                    password=password,
                    message="HTTP Basic authentication failed",
                    response_time=response_time
                )
            elif response.status_code == 403:
                return AuthResult(
                    success=False,
                    username=username,
                    password=password,
                    message="Access forbidden",
                    response_time=response_time
                )
            else:
                return AuthResult(
                    success=False,
                    username=username,
                    password=password,
                    message=f"Unexpected status code: {response.status_code}",
                    response_time=response_time
                )
                
        except requests.exceptions.Timeout:
            response_time = time.time() - start_time
            return AuthResult(
                success=False,
                username=username,
                password=password,
                message="Request timeout",
                response_time=response_time
            )
        except requests.exceptions.ConnectionError as e:
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
        return f"HTTP{'S' if self.use_ssl else ''}"

class WebformAuth(BaseAuth):
    def __init__(self, target: str, port: int = 80, timeout: float = 5.0, 
                 use_ssl: bool = False, login_path: str = "/login"):
        super().__init__(target, port, timeout)
        self.use_ssl = use_ssl
        self.protocol = "https" if use_ssl else "http"
        self.login_path = login_path
        self.session = requests.Session()
        self.session.verify = False
    
    def _build_url(self, path: str = "/") -> str:
        return f"{self.protocol}://{self.target}:{self.port}{path}"
    
    def test_credentials(self, username: str, password: str) -> AuthResult:
        start_time = time.time()
        
        try:
            login_url = self._build_url(self.login_path)
            
            # First get the login page to check if it exists and get form fields
            response = self.session.get(login_url, timeout=self.timeout)
            
            if response.status_code not in [200, 302]:
                response_time = time.time() - start_time
                return AuthResult(
                    success=False,
                    username=username,
                    password=password,
                    message=f"Login page not accessible (status: {response.status_code})",
                    response_time=response_time
                )
            
            # Common form field names
            username_fields = ['username', 'user', 'login', 'email', 'user_name', 'uid']
            password_fields = ['password', 'pass', 'pwd', 'passwd', 'user_password']
            
            # Try to detect actual field names from the page
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            detected_username = None
            detected_password = None
            
            # Look for input fields
            for input_tag in soup.find_all('input', {'type': ['text', 'email']}):
                name = input_tag.get('name', '').lower()
                if any(field in name for field in username_fields):
                    detected_username = input_tag.get('name')
                    break
            
            for input_tag in soup.find_all('input', {'type': 'password'}):
                name = input_tag.get('name', '').lower()
                if any(field in name for field in password_fields):
                    detected_password = input_tag.get('name')
                    break
            
            # Use detected field names or fall back to common ones
            username_field = detected_username or username_fields[0]
            password_field = detected_password or password_fields[0]
            
            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }
            
            # Try to login
            login_response = self.session.post(
                login_url,
                data=login_data,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            response_time = time.time() - start_time
            
            # Check if login was successful (no redirect to login page and not 401)
            if (login_response.status_code in [200, 302] and 
                'login' not in login_response.url.lower() and
                'login' not in login_response.text.lower() and
                'invalid' not in login_response.text.lower() and
                'failed' not in login_response.text.lower()):
                
                return AuthResult(
                    success=True,
                    username=username,
                    password=password,
                    message="Webform authentication successful",
                    response_time=response_time
                )
            else:
                return AuthResult(
                    success=False,
                    username=username,
                    password=password,
                    message="Webform authentication failed",
                    response_time=response_time
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return AuthResult(
                success=False,
                username=username,
                password=password,
                message=f"Error during webform authentication: {str(e)}",
                response_time=response_time
            )
    
    def get_service_name(self) -> str:
        return "WebForm"

# Register the modules
auth_registry.register("HTTP", lambda t, p: HTTPBasicAuth(t, p, use_ssl=False))
auth_registry.register("HTTPS", lambda t, p: HTTPBasicAuth(t, p, use_ssl=True))
auth_registry.register("HTTP-Basic", lambda t, p: HTTPBasicAuth(t, p, use_ssl=False))
auth_registry.register("HTTPS-Basic", lambda t, p: HTTPBasicAuth(t, p, use_ssl=True))
auth_registry.register("WebForm", lambda t, p: WebformAuth(t, p, use_ssl=False))
auth_registry.register("WebForm-HTTPS", lambda t, p: WebformAuth(t, p, use_ssl=True))