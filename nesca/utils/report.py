import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any
import os

from .logger import get_logger

logger = get_logger(__name__)

class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_json_report(self, results: Dict[str, Any], filename: str = None) -> str:
        """Generate JSON format report"""
        if filename is None:
            filename = f"nesca_report_{self.timestamp}.json"
        
        # Add metadata
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "scanner": "Nesca Python CLI",
                "version": "1.0.0"
            },
            "results": results
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {str(e)}")
            raise
    
    def generate_csv_report(self, results: Dict[str, Any], filename: str = None) -> str:
        """Generate CSV format report"""
        if filename is None:
            filename = f"nesca_report_{self.timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow(['Target', 'Port', 'Service', 'Username', 'Password', 'Response Time', 'Status'])
                
                # Write scan results
                if 'scan_results' in results:
                    for target, ports in results['scan_results'].items():
                        for port, service in ports:
                            writer.writerow([target, port, service, '', '', '', 'Open'])
                
                # Write brute force results
                if 'brute_force_results' in results:
                    for target, creds_data in results['brute_force_results'].items():
                        if isinstance(creds_data, list):
                            for cred in creds_data:
                                if isinstance(cred, dict):
                                    username, password = cred['credentials']
                                    response_time = cred.get('response_time', '')
                                    writer.writerow([target, '', '', username, password, response_time, 'Valid'])
                        else:
                            # Single result format
                            username, password = creds_data['credentials'][0]
                            response_time = creds_data.get('response_time', '')
                            writer.writerow([target, '', '', username, password, response_time, 'Valid'])
            
            logger.info(f"CSV report generated: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {str(e)}")
            raise
    
    def generate_html_report(self, results: Dict[str, Any], filename: str = None) -> str:
        """Generate HTML format report"""
        if filename is None:
            filename = f"nesca_report_{self.timestamp}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nesca Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            color: #333;
            border-bottom: 2px solid #007acc;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .section {{
            margin: 20px 0;
        }}
        .section h2 {{
            color: #007acc;
            border-left: 4px solid #007acc;
            padding-left: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #007acc;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .open-port {{
            color: #28a745;
            font-weight: bold;
        }}
        .valid-cred {{
            color: #dc3545;
            font-weight: bold;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }}
        .stat-box {{
            text-align: center;
            padding: 15px;
            background-color: #e9ecef;
            border-radius: 5px;
        }}
        .stat-number {{
            font-size: 24px;
            font-weight: bold;
            color: #007acc;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Nesca Network Scanner Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{len(results.get('scan_results', {}))}</div>
                <div>Targets Scanned</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{sum(len(ports) for ports in results.get('scan_results', {}).values())}</div>
                <div>Open Ports</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(results.get('brute_force_results', {}))}</div>
                <div>Valid Credentials</div>
            </div>
        </div>
        
        {self._generate_scan_results_html(results.get('scan_results', {}))}
        
        {self._generate_brute_force_html(results.get('brute_force_results', {}))}
        
        <div class="section">
            <h2>Scan Summary</h2>
            <p>This report was generated by Nesca Python CLI network scanner. 
            The scan was completed in {datetime.now().strftime('%H:%M:%S')}.</p>
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    def _generate_scan_results_html(self, scan_results: Dict) -> str:
        """Generate HTML for scan results"""
        if not scan_results:
            return ""
        
        html = """
        <div class="section">
            <h2>Port Scan Results</h2>
            <table>
                <tr>
                    <th>Target</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Status</th>
                </tr>
        """
        
        for target, ports in scan_results.items():
            for port, service in ports:
                html += f"""
                <tr>
                    <td>{target}</td>
                    <td>{port}</td>
                    <td>{service}</td>
                    <td class="open-port">Open</td>
                </tr>
                """
        
        html += """
            </table>
        </div>
        """
        
        return html
    
    def _generate_brute_force_html(self, brute_results: Dict) -> str:
        """Generate HTML for brute force results"""
        if not brute_results:
            return ""
        
        html = """
        <div class="section">
            <h2>Brute Force Results</h2>
            <table>
                <tr>
                    <th>Target</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Response Time</th>
                    <th>Status</th>
                </tr>
        """
        
        for target, creds_data in brute_results.items():
            if isinstance(creds_data, list):
                for cred in creds_data:
                    if isinstance(cred, dict):
                        username, password = cred['credentials']
                        response_time = cred.get('response_time', 0)
                        html += f"""
                        <tr>
                            <td>{target}</td>
                            <td>{username}</td>
                            <td>{password}</td>
                            <td>{response_time:.2f}s</td>
                            <td class="valid-cred">Valid</td>
                        </tr>
                        """
            else:
                # Single result format
                username, password = creds_data['credentials'][0]
                response_time = creds_data.get('response_time', 0)
                html += f"""
                <tr>
                    <td>{target}</td>
                    <td>{username}</td>
                    <td>{password}</td>
                    <td>{response_time:.2f}s</td>
                    <td class="valid-cred">Valid</td>
                </tr>
                """
        
        html += """
            </table>
        </div>
        """
        
        return html

class SessionManager:
    def __init__(self, session_dir: str = "sessions"):
        self.session_dir = session_dir
        self.ensure_session_dir()
    
    def ensure_session_dir(self):
        """Ensure session directory exists"""
        if not os.path.exists(self.session_dir):
            os.makedirs(self.session_dir)
            logger.info(f"Created session directory: {self.session_dir}")
    
    def save_session(self, data: Dict[str, Any], session_name: str = None) -> str:
        """Save scan session data"""
        if session_name is None:
            session_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        session_file = os.path.join(self.session_dir, session_name)
        
        session_data = {
            "session_info": {
                "created": datetime.now().isoformat(),
                "name": session_name.replace('.json', '')
            },
            "data": data
        }
        
        try:
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
            
            logger.info(f"Session saved: {session_file}")
            return session_file
            
        except Exception as e:
            logger.error(f"Failed to save session: {str(e)}")
            raise
    
    def load_session(self, session_name: str) -> Dict[str, Any]:
        """Load scan session data"""
        session_file = os.path.join(self.session_dir, session_name)
        
        if not os.path.exists(session_file):
            raise FileNotFoundError(f"Session file not found: {session_file}")
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            logger.info(f"Session loaded: {session_file}")
            return session_data
            
        except Exception as e:
            logger.error(f"Failed to load session: {str(e)}")
            raise
    
    def list_sessions(self) -> List[Dict[str, str]]:
        """List all available sessions"""
        sessions = []
        
        if not os.path.exists(self.session_dir):
            return sessions
        
        try:
            for filename in os.listdir(self.session_dir):
                if filename.endswith('.json'):
                    session_file = os.path.join(self.session_dir, filename)
                    
                    try:
                        with open(session_file, 'r', encoding='utf-8') as f:
                            session_data = json.load(f)
                        
                        session_info = session_data.get('session_info', {})
                        sessions.append({
                            'name': filename.replace('.json', ''),
                            'created': session_info.get('created', 'Unknown'),
                            'file': session_file
                        })
                    except:
                        continue
            
            return sorted(sessions, key=lambda x: x['created'], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to list sessions: {str(e)}")
            return []

# Global instances
report_generator = ReportGenerator()
session_manager = SessionManager()