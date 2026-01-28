import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable, Any, Optional
from dataclasses import dataclass
from tqdm import tqdm
import queue

from ..utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class ScanTask:
    id: str
    target: str
    port: int
    service: str
    data: Dict[str, Any] = None

@dataclass
class ScanResult:
    task_id: str
    target: str
    port: int
    service: str
    success: bool
    data: Dict[str, Any]
    message: str
    response_time: float

class MultiThreadScanner:
    def __init__(self, max_threads: int = 50, timeout: float = 5.0):
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
    def add_task(self, task: ScanTask):
        """Add a task to the scan queue (for future implementation)"""
        pass
    
    def scan_targets(self, tasks: List[ScanTask], 
                    scan_function: Callable[[ScanTask], ScanResult],
                    show_progress: bool = True) -> List[ScanResult]:
        """Execute multiple scan tasks in parallel"""
        results = []
        
        if show_progress:
            progress_bar = tqdm(total=len(tasks), desc="Scanning", unit="targets")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_task = {executor.submit(scan_function, task): task for task in tasks}
            
            for future in as_completed(future_to_task):
                if self.stop_event.is_set():
                    break
                    
                task = future_to_task[future]
                try:
                    result = future.result()
                    with self.lock:
                        results.append(result)
                        
                    if show_progress:
                        progress_bar.update(1)
                        if result.success:
                            progress_bar.set_postfix({"Found": f"{len([r for r in results if r.success])}"})
                        
                except Exception as e:
                    logger.error(f"Task {task.id} failed: {str(e)}")
                    if show_progress:
                        progress_bar.update(1)
        
        if show_progress:
            progress_bar.close()
            
        return results
    
    def stop(self):
        """Stop all scanning threads"""
        self.stop_event.set()
    
    def get_results(self) -> List[ScanResult]:
        """Get all scan results"""
        with self.lock:
            return self.results.copy()

class BruteForceScanner(MultiThreadScanner):
    def __init__(self, max_threads: int = 20, timeout: float = 5.0, delay: float = 0.1):
        super().__init__(max_threads, timeout)
        self.delay = delay
        self.success_found = threading.Event()
        
    def brute_force_target(self, target: str, port: int, service: str,
                          usernames: List[str], passwords: List[str],
                          auth_module, stop_on_first: bool = True) -> List[ScanResult]:
        """Brute force credentials for a single target"""
        tasks = []
        
        for username in usernames:
            for password in passwords:
                task_id = f"{target}:{port}:{username}:{password}"
                task = ScanTask(
                    id=task_id,
                    target=target,
                    port=port,
                    service=service,
                    data={"username": username, "password": password}
                )
                tasks.append(task)
        
        def brute_force_task(task: ScanTask) -> ScanResult:
            if stop_on_first and self.success_found.is_set():
                return ScanResult(
                    task_id=task.id,
                    target=task.target,
                    port=task.port,
                    service=task.service,
                    success=False,
                    data=task.data,
                    message="Skipped - success already found",
                    response_time=0.0
                )
            
            try:
                username = task.data["username"]
                password = task.data["password"]
                
                auth_result = auth_module.test_credentials(username, password)
                
                if auth_result.success and stop_on_first:
                    self.success_found.set()
                
                return ScanResult(
                    task_id=task.id,
                    target=task.target,
                    port=task.port,
                    service=task.service,
                    success=auth_result.success,
                    data={
                        **task.data,
                        "message": auth_result.message
                    },
                    message=auth_result.message,
                    response_time=auth_result.response_time
                )
                
            except Exception as e:
                return ScanResult(
                    task_id=task.id,
                    target=task.target,
                    port=task.port,
                    service=task.service,
                    success=False,
                    data=task.data,
                    message=f"Error: {str(e)}",
                    response_time=0.0
                )
        
        # Add delay between requests
        def delayed_task(task: ScanTask) -> ScanResult:
            time.sleep(self.delay)
            return brute_force_task(task)
        
        return self.scan_targets(tasks, delayed_task, show_progress=True)
    
    def brute_force_multiple(self, targets: List[tuple], 
                           usernames: List[str], passwords: List[str],
                           stop_on_first: bool = True) -> Dict[str, List[ScanResult]]:
        """Brute force multiple targets"""
        all_results = {}
        
        for target, port, service in targets:
            logger.info(f"Starting brute force for {target}:{port} ({service})")
            
            # Get appropriate auth module
            from ..auth.base import auth_registry
            auth_class = auth_registry.get_module(service)
            
            if not auth_class:
                logger.error(f"No auth module available for {service}")
                continue
            
            if callable(auth_class):
                auth_instance = auth_class(target, port)
            else:
                auth_instance = auth_class(target, port)
            
            results = self.brute_force_target(
                target, port, service, usernames, passwords, 
                auth_instance, stop_on_first
            )
            
            key = f"{target}:{port}"
            all_results[key] = [r for r in results if r.success]
            
            # Reset success flag for next target
            self.success_found.clear()
        
        return all_results