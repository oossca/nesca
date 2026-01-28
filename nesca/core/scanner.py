import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import ipaddress
from ..utils.logger import get_logger

logger = get_logger(__name__)

class PortScanner:
    def __init__(self, timeout: float = 3.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = {}
        
    def scan_port(self, target: str, port: int) -> Tuple[str, int, bool, str]:
        """Scan a single port on a target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                service = self._get_service_name(port)
                return (target, port, True, service)
            else:
                return (target, port, False, "")
        except Exception as e:
            logger.debug(f"Error scanning {target}:{port} - {str(e)}")
            return (target, port, False, "")
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        common_ports = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        return common_ports.get(port, f"Unknown-{port}")
    
    def scan_target(self, target: str, ports: List[int]) -> Dict[str, List[Tuple[int, str]]]:
        """Scan multiple ports on a single target"""
        results = {target: []}
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, target, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                target_ip, port, is_open, service = future.result()
                if is_open:
                    results[target].append((port, service))
                    logger.info(f"Found open port: {target_ip}:{port} ({service})")
        
        return results
    
    def scan_range(self, ip_range: str, ports: List[int]) -> Dict[str, List[Tuple[int, str]]]:
        """Scan multiple targets in IP range"""
        results = {}
        
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        except ValueError:
            targets = [ip_range]
        
        logger.info(f"Scanning {len(targets)} targets, {len(ports)} ports each")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_target = {}
            
            for target in targets:
                for port in ports:
                    future = executor.submit(self.scan_port, target, port)
                    future_to_target[future] = (target, port)
            
            for future in as_completed(future_to_target):
                target, port = future_to_target[future]
                target_ip, scanned_port, is_open, service = future.result()
                
                if is_open:
                    if target_ip not in results:
                        results[target_ip] = []
                    results[target_ip].append((scanned_port, service))
                    logger.info(f"Found open port: {target_ip}:{scanned_port} ({service})")
        
        return results

class HostDiscovery:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
    
    def ping_host(self, target: str) -> bool:
        """Check if host is up using simple port scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, 80))
            sock.close()
            
            if result == 0:
                return True
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, 443))
            sock.close()
            
            return result == 0
        except Exception:
            return False
    
    def discover_hosts(self, ip_range: str) -> List[str]:
        """Discover active hosts in IP range"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        except ValueError:
            return [ip_range] if self.ping_host(ip_range) else []
        
        active_hosts = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_host = {executor.submit(self.ping_host, target): target for target in targets}
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                if future.result():
                    active_hosts.append(host)
                    logger.info(f"Active host found: {host}")
        
        return active_hosts