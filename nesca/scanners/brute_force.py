from typing import List, Dict, Tuple, Optional
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils.logger import get_logger
from ..utils.wordlist import wordlist_manager
from ..auth.base import auth_registry
from .multi_thread_scanner import BruteForceScanner, ScanResult

logger = get_logger(__name__)

class BruteForceEngine:
    def __init__(self, max_threads: int = 20, timeout: float = 5.0, delay: float = 0.1):
        self.scanner = BruteForceScanner(max_threads, timeout, delay)
        self.wordlist_manager = wordlist_manager
    
    def brute_force_service(self, targets: List[Tuple[str, int, str]], 
                           usernames: List[str] = None, 
                           passwords: List[str] = None,
                           stop_on_first: bool = True) -> Dict[str, List[ScanResult]]:
        """Brute force multiple targets for a specific service"""
        results = {}
        
        if not usernames:
            usernames = self.wordlist_manager.get_usernames()
        
        if not passwords:
            passwords = self.wordlist_manager.get_passwords()
        
        logger.info(f"Starting brute force with {len(usernames)} usernames and {len(passwords)} passwords")
        logger.info(f"Total combinations per target: {len(usernames) * len(passwords)}")
        
        return self.scanner.brute_force_multiple(
            targets, usernames, passwords, stop_on_first
        )
    
    def brute_force_single_target(self, target: str, port: int, service: str,
                                 usernames: List[str] = None, 
                                 passwords: List[str] = None,
                                 stop_on_first: bool = True) -> List[ScanResult]:
        """Brute force a single target"""
        if not usernames:
            usernames = self.wordlist_manager.get_usernames(service)
        
        if not passwords:
            passwords = self.wordlist_manager.get_passwords(service)
        
        # Get appropriate auth module
        auth_class = auth_registry.get_module(service)
        
        if not auth_class:
            logger.error(f"No auth module available for {service}")
            return []
        
        if callable(auth_class):
            auth_instance = auth_class(target, port)
        else:
            auth_instance = auth_class(target, port)
        
        results = self.scanner.brute_force_target(
            target, port, service, usernames, passwords, 
            auth_instance, stop_on_first
        )
        
        return [r for r in results if r.success]
    
    def quick_brute_force(self, target: str, port: int, service: str) -> Optional[Dict]:
        """Quick brute force with common credentials"""
        from ..utils.config import config
        quick_usernames = config.get('quick_usernames')
        quick_passwords = config.get('quick_passwords')
        
        results = self.brute_force_single_target(
            target, port, service, quick_usernames, quick_passwords, True
        )
        
        if results:
            return {
                'target': target,
                'port': port,
                'service': service,
                'credentials': [(r.data['username'], r.data['password']) for r in results],
                'response_time': results[0].response_time
            }
        
        return None

class ServiceEnumerator:
    def __init__(self):
        self.wordlist_manager = wordlist_manager
    
    def get_service_from_port(self, port: int) -> Optional[str]:
        """Get likely service name from port number"""
        service_ports = self.wordlist_manager.get_service_ports()
        
        for service, service_port in service_ports.items():
            if port == service_port:
                return service
        
        return None
    
    def filter_brute_force_targets(self, scan_results: Dict[str, List[Tuple[int, str]]]) -> List[Tuple[str, int, str]]:
        """Filter scan results to get targets suitable for brute force"""
        targets = []
        
        for target, ports in scan_results.items():
            for port, service in ports:
                if service.upper() in ['FTP', 'SSH', 'HTTP', 'HTTPS', 'TELNET']:
                    targets.append((target, port, service.upper()))
                else:
                    # Try to determine service from port
                    likely_service = self.get_service_from_port(port)
                    if likely_service and likely_service.upper() in ['FTP', 'SSH', 'HTTP', 'HTTPS', 'TELNET']:
                        targets.append((target, port, likely_service.upper()))
        
        return targets

class BruteForceManager:
    def __init__(self, max_threads: int = 20, timeout: float = 5.0, delay: float = 0.1):
        self.engine = BruteForceEngine(max_threads, timeout, delay)
        self.enumerator = ServiceEnumerator()
    
    def scan_and_brute_force(self, targets: List[str], ports: List[int] = None,
                           quick_scan: bool = False) -> Dict:
        """Scan targets and perform brute force on discovered services"""
        from ..core.scanner import PortScanner
        
        if ports is None:
            ports = self.engine.wordlist_manager.get_common_ports()
        
        # First, scan for open ports
        scanner = PortScanner()
        logger.info("Starting port scan...")
        
        scan_results = {}
        for target in targets:
            results = scanner.scan_target(target, ports)
            scan_results.update(results)
        
        logger.info(f"Port scan completed. Found {len(scan_results)} targets with open ports")
        
        # Filter targets for brute force
        brute_force_targets = self.enumerator.filter_brute_force_targets(scan_results)
        logger.info(f"Found {len(brute_force_targets)} targets for brute force")
        
        # Perform brute force
        if quick_scan:
            # Quick brute force for each target
            results = {}
            for target, port, service in brute_force_targets:
                logger.info(f"Quick brute forcing {target}:{port} ({service})")
                result = self.engine.quick_brute_force(target, port, service)
                if result:
                    key = f"{target}:{port}"
                    results[key] = result
            
            return {'scan_results': scan_results, 'brute_force_results': results}
        else:
            # Full brute force
            brute_force_results = self.engine.brute_force_service(brute_force_targets)
            
            # Format results
            formatted_results = {}
            for key, results in brute_force_results.items():
                if results:
                    formatted_results[key] = [{
                        'credentials': (r.data['username'], r.data['password']),
                        'response_time': r.response_time,
                        'message': r.message
                    } for r in results]
            
            return {'scan_results': scan_results, 'brute_force_results': formatted_results}