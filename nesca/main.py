#!/usr/bin/env python3
import argparse
import sys
import json
from typing import List

from .utils.logger import setup_logging, get_logger
from .utils.config import Config, config as default_config
from .core.scanner import PortScanner, HostDiscovery
from .scanners.brute_force import BruteForceManager
from .utils.wordlist import wordlist_manager

logger = get_logger(__name__)

def parse_targets(targets: List[str]) -> List[str]:
    """Parse target arguments into a list of IP addresses"""
    result = []
    for target in targets:
        if target.startswith('@') or target.startswith('-'):
            # Read targets from file
            filename = target.lstrip('@-')
            result.extend(load_targets_from_file(filename))
        elif ',' in target:
            result.extend([t.strip() for t in target.split(',')])
        else:
            result.append(target.strip())
    return result

def load_targets_from_file(filename: str) -> List[str]:
    """Load targets from file"""
    targets = []
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    targets.append(line)
        
        logger.info(f"Loaded {len(targets)} targets from {filename}")
        return targets
        
    except FileNotFoundError:
        logger.error(f"Target file not found: {filename}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading target file: {str(e)}")
        sys.exit(1)

def parse_ports(ports_arg: str) -> List[int]:
    """Parse port argument into a list of port numbers"""
    ports = []
    
    for part in ports_arg.split(','):
        part = part.strip()
        
        if '-' in part:
            # Port range
            try:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                logger.error(f"Invalid port range: {part}")
                sys.exit(1)
        else:
            # Single port
            try:
                ports.append(int(part))
            except ValueError:
                logger.error(f"Invalid port: {part}")
                sys.exit(1)
    
    return ports

def print_scan_results(results: dict):
    """Print port scan results in a readable format"""
    print("\n" + "="*60)
    print("PORT SCAN RESULTS")
    print("="*60)
    
    if not results:
        print("No open ports found.")
        return
    
    total_ports = 0
    for target, ports in results.items():
        total_ports += len(ports)
        print(f"\nTarget: {target}")
        print("-" * 40)
        for port, service in ports:
            print(f"  {port:>5}/tcp  {service}")
    
    print(f"\nTotal open ports found: {total_ports}")

def print_brute_force_results(results: dict):
    """Print brute force results in a readable format"""
    print("\n" + "="*60)
    print("BRUTE FORCE RESULTS")
    print("="*60)
    
    if not results:
        print("No valid credentials found.")
        return
    
    total_credentials = 0
    for target, target_results in results.items():
        if isinstance(target_results, list):
            credentials_count = len(target_results)
            total_credentials += credentials_count
            print(f"\nTarget: {target}")
            print("-" * 40)
            for result in target_results:
                if isinstance(result, dict):
                    username, password = result['credentials']
                    print(f"  Username: {username}")
                    print(f"  Password: {password}")
                    print(f"  Response Time: {result.get('response_time', 0):.2f}s")
                    print(f"  Message: {result.get('message', 'N/A')}")
                    print()
        else:
            # Single result format
            username, password = target_results['credentials'][0]
            total_credentials += 1
            print(f"\nTarget: {target}")
            print("-" * 40)
            print(f"  Username: {username}")
            print(f"  Password: {password}")
            print(f"  Response Time: {target_results['response_time']:.2f}s")
    
    print(f"\nTotal valid credentials found: {total_credentials}")

def save_results(results: dict, filename: str, format: str = 'json'):
    """Save results to file"""
    try:
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
        else:
            # Simple text format
            with open(filename, 'w') as f:
                f.write("Nesca Scan Results\n")
                f.write("=" * 40 + "\n\n")
                
                if 'scan_results' in results:
                    f.write("Port Scan Results:\n")
                    f.write("-" * 20 + "\n")
                    for target, ports in results['scan_results'].items():
                        f.write(f"{target}:\n")
                        for port, service in ports:
                            f.write(f"  {port} - {service}\n")
                        f.write("\n")
                
                if 'brute_force_results' in results:
                    f.write("Brute Force Results:\n")
                    f.write("-" * 20 + "\n")
                    for target, creds in results['brute_force_results'].items():
                        f.write(f"{target}:\n")
                        if isinstance(creds, list):
                            for cred in creds:
                                username, password = cred['credentials']
                                f.write(f"  {username}:{password}\n")
                        else:
                            username, password = creds['credentials'][0]
                            f.write(f"  {username}:{password}\n")
                        f.write("\n")
        
        logger.info(f"Results saved to {filename}")
        
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")

def main():
    # Initialize default configuration
    config = default_config
    
    parser = argparse.ArgumentParser(
        description="Nesca - The legendary netstalking NEtwork SCAnner (Python CLI version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nesca -t 192.168.1.1 -p 21,22,80,443 --mode scan
  nesca -t 192.168.1.0/24 -p 1-1000 --mode scan --output results.json
  nesca -t 192.168.1.1:21 --mode brute --service FTP
  nesca -t 192.168.1.1-192.168.1.10 --mode scan-and-brute --quick
  nesca -t @targets.txt -p 21,22,80,443 --mode scan  # Load targets from file
  nesca -t -targets.txt -p 21,22,80,443 --mode scan  # Alternative syntax
        """
    )
    
    # Target options
    parser.add_argument('-t', '--targets',
                       help='Target(s) - IP address, range, CIDR, or file path (comma-separated, prefix file with @ or -)')
    parser.add_argument('-p', '--ports', 
                       help='Port(s) to scan - single port, comma-separated, or range (e.g., 80,443 or 1-1000)')
    
    # Mode selection
    parser.add_argument('-m', '--mode', choices=['scan', 'brute', 'scan-and-brute', 'discover'],
                       help='Operation mode (default: scan)')
    
    # Brute force options
    parser.add_argument('-s', '--service', 
                       help='Service for brute force (FTP, SSH, HTTP, etc.)')
    parser.add_argument('-u', '--usernames', 
                       help='Username file or comma-separated usernames')
    parser.add_argument('-w', '--passwords', 
                       help='Password file or comma-separated passwords')
    parser.add_argument('--quick', action='store_true',
                       help='Quick brute force with common credentials')
    
    # Configuration-driven options - only use defaults when no argument provided
    parser.add_argument('--threads', type=int,
                       help=f'Number of threads (default from config: {config.get("default_threads")})')
    parser.add_argument('--timeout', type=float,
                       help=f'Connection timeout in seconds (default from config: {config.get("default_timeout")})')
    parser.add_argument('--delay', type=float,
                       help=f'Delay between requests (default from config: {config.get("default_delay")})')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--format', choices=['json', 'txt'], 
                       help=f'Output format (default from config: {config.get("default_format")})')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (errors only)')
    
    # Options
    parser.add_argument('--list-services', action='store_true',
                       help='List supported authentication services')
    parser.add_argument('--create-wordlists', action='store_true',
                       help='Create default wordlist files')
    parser.add_argument('--show-config', action='store_true',
                       help='Show current configuration')
    parser.add_argument('--config',
                       help='Specify configuration file path')
    
    args = parser.parse_args()
    
    # Load custom config if specified
    if args.config:
        config = Config(args.config)
    
    # Setup logging
    setup_logging(args.verbose, args.quiet)
    
    # Handle special commands
    if args.list_services:
        from .auth.base import auth_registry
        services = auth_registry.list_services()
        print("Supported authentication services:")
        for service in sorted(services):
            print(f"  - {service}")
        return
    
    if args.create_wordlists:
        wordlist_manager.create_default_wordlists()
        return
    
    if args.show_config:
        config.show_config()
        return
    
    # Set defaults from config if not provided by user
    timeout = args.timeout if args.timeout is not None else config.get('default_timeout')
    threads = args.threads if args.threads is not None else config.get('default_threads')
    delay = args.delay if args.delay is not None else config.get('default_delay')
    output_format = args.format if args.format is not None else config.get('default_format')
    
    # Check if targets are provided for regular operations
    if not args.targets:
        logger.error("Targets are required for this operation mode")
        sys.exit(1)
    
    # Parse targets
    targets = parse_targets([args.targets])
    
    # Initialize components
    if args.mode == 'discover':
        discovery = HostDiscovery(timeout=timeout)
        logger.info(f"Discovering active hosts in: {targets}")
        
        active_hosts = []
        for target in targets:
            hosts = discovery.discover_hosts(target)
            active_hosts.extend(hosts)
        
        print(f"\nFound {len(active_hosts)} active hosts:")
        for host in active_hosts:
            print(f"  {host}")
        
        if args.output:
            save_results({'active_hosts': active_hosts}, args.output, output_format)
        return
    
    # Parse ports
    if args.ports:
        ports = parse_ports(args.ports)
    elif args.mode in ['scan', 'scan-and-brute']:
        ports = config.get('common_ports')
        logger.info(f"Using common ports: {len(ports)} ports")
    else:
        ports = []
    
    # Scan mode
    if args.mode == 'scan':
        scanner = PortScanner(timeout=timeout, max_threads=threads)
        
        logger.info(f"Starting port scan on {len(targets)} targets")
        
        scan_results = {}
        for target in targets:
            if '-' in target and ':' not in target:
                # IP range
                results = scanner.scan_range(target, ports)
            else:
                # Single target
                results = scanner.scan_target(target, ports)
            scan_results.update(results)
        
        print_scan_results(scan_results)
        
        if args.output:
            save_results({'scan_results': scan_results}, args.output, output_format)
    
    # Brute force mode
    elif args.mode == 'brute':
        if not args.service:
            logger.error("Service is required for brute force mode")
            sys.exit(1)
        
        # Parse targets for brute force (expect format: IP:PORT)
        brute_targets = []
        for target in targets:
            if ':' in target:
                ip, port_str = target.rsplit(':', 1)
                try:
                    port = int(port_str)
                    brute_targets.append((ip, port, args.service.upper()))
                except ValueError:
                    logger.error(f"Invalid port in target: {target}")
                    sys.exit(1)
            else:
                logger.error("Brute force mode requires targets in format IP:PORT")
                sys.exit(1)
        
        # Setup brute force
        manager = BruteForceManager(
            max_threads=threads,
            timeout=timeout,
            delay=delay
        )
        
        # Parse usernames and passwords
        usernames = None
        passwords = None
        
        if args.usernames:
            if ',' in args.usernames:
                usernames = [u.strip() for u in args.usernames.split(',')]
            else:
                usernames = wordlist_manager.load_wordlist(args.usernames)
        
        if args.passwords:
            if ',' in args.passwords:
                passwords = [p.strip() for p in args.passwords.split(',')]
            else:
                passwords = wordlist_manager.load_wordlist(args.passwords)
        
        if args.quick:
            # Quick brute force using config file credentials
            quick_usernames = config.get('quick_usernames')
            quick_passwords = config.get('quick_passwords')
            results = {}
            
            for target, port, service in brute_targets:
                result = manager.engine.brute_force_single_target(
                    target, port, service, quick_usernames, quick_passwords, True
                )
                if result:
                    results[f"{target}:{port}"] = {
                        'target': target,
                        'port': port,
                        'service': service,
                        'credentials': [(r.data['username'], r.data['password']) for r in result],
                        'response_time': result[0].response_time if result else 0
                    }
            
            print_brute_force_results(results)
            
            if args.output:
                save_results({'brute_force_results': results}, args.output, output_format)
        else:
            # Full brute force
            results = manager.engine.brute_force_service(
                brute_targets, usernames, passwords, True
            )
            
            print_brute_force_results(results)
            
            if args.output:
                save_results({'brute_force_results': results}, args.output, output_format)
    
    # Scan and brute force mode
    elif args.mode == 'scan-and-brute':
        manager = BruteForceManager(
            max_threads=threads,
            timeout=timeout,
            delay=delay
        )
        
        results = manager.scan_and_brute_force(targets, ports, args.quick)
        
        print_scan_results(results.get('scan_results', {}))
        print_brute_force_results(results.get('brute_force_results', {}))
        
        if args.output:
            save_results(results, args.output, output_format)

if __name__ == '__main__':
    main()