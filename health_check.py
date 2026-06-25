import argparse
import socket
import json
import logging
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DeploymentHealthCheck:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.hostname
        self.port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
        self.results = {
            "target": self.target_url,
            "headers": {},
            "forms": [],
            "banner": None
        }

    def inspect_headers(self):
        logging.info(f"[*] Starting HTTP Header Inspection on {self.target_url}")
        try:
            # Use headers to act as a standard browser
            headers = {'User-Agent': 'HealthCheck/1.0'}
            response = requests.get(self.target_url, headers=headers, timeout=10)
            headers_to_check = [
                'X-Frame-Options', 
                'Content-Security-Policy', 
                'X-Content-Type-Options',
                'Strict-Transport-Security'
            ]
            
            for header in headers_to_check:
                if header in response.headers:
                    logging.info(f"[+] Found {header}: {response.headers[header]}")
                    self.results["headers"][header] = {"present": True, "value": response.headers[header]}
                else:
                    logging.warning(f"[!] Missing {header}")
                    self.results["headers"][header] = {"present": False, "value": None}
                    
            return response.text
        except requests.exceptions.RequestException as e:
            logging.error(f"[!!] Failed to connect for header inspection: {e}")
            return None

    def audit_forms(self, html_content):
        if not html_content:
            logging.warning("[!] No HTML content to parse for forms.")
            return

        logging.info("[*] Starting Form Compliance Audit")
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        
        logging.info(f"[*] Found {len(forms)} form(s) on the page.")
        
        csrf_tokens = ['_token', 'csrfmiddlewaretoken', 'csrf_token', 'authenticity_token']
        
        for index, form in enumerate(forms):
            form_action = form.get('action', 'Unknown action')
            form_method = form.get('method', 'GET').upper()
            
            has_csrf = False
            for input_tag in form.find_all('input'):
                if input_tag.get('name') in csrf_tokens:
                    has_csrf = True
                    break
            
            form_data = {
                "index": index,
                "action": form_action,
                "method": form_method,
                "has_csrf_token": has_csrf
            }
            self.results["forms"].append(form_data)
            
            if has_csrf:
                logging.info(f"[+] Form {index} (Action: {form_action}): CSRF token found.")
            else:
                if form_method == 'POST':
                    logging.warning(f"[!] Form {index} (Action: {form_action}, Method: POST): CSRF token missing.")
                else:
                    logging.info(f"[*] Form {index} (Action: {form_action}, Method: {form_method}): CSRF token missing (may be acceptable for GET).")

    def log_network_banner(self):
        logging.info(f"[*] Starting Network Banner Logger on {self.host}:{self.port}")
        if not self.host:
            logging.error("[!!] Invalid hostname for banner logging.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.host, self.port))
                
                # Send a simple HTTP HEAD request to prompt a server response
                request = f"HEAD / HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n"
                s.sendall(request.encode())
                
                response = s.recv(1024).decode(errors='ignore')
                
                # Extract the Server banner if present
                banner = "Unknown"
                for line in response.split('\r\n'):
                    if line.lower().startswith('server:'):
                        banner = line.split(':', 1)[1].strip()
                        break
                        
                logging.info(f"[+] Open port {self.port} detected. Server banner: {banner}")
                self.results["banner"] = {"port": self.port, "server": banner}
                
        except (socket.timeout, ConnectionRefusedError) as e:
            logging.error(f"[!!] Failed to connect to {self.host}:{self.port} - {e}")
            self.results["banner"] = {"port": self.port, "error": str(e)}
        except Exception as e:
            logging.error(f"[!!] Unexpected error during banner logging: {e}")
            self.results["banner"] = {"port": self.port, "error": str(e)}

    def run(self):
        html_content = self.inspect_headers()
        self.audit_forms(html_content)
        self.log_network_banner()
        return self.results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Deployment Health Check & Configuration Audit Script")
    parser.add_argument("url", help="Target URL to check (e.g., http://localhost:8000)")
    parser.add_argument("-o", "--output", help="Output JSON file for results", default="health_check_report.json")
    args = parser.parse_args()

    scanner = DeploymentHealthCheck(args.url)
    report = scanner.run()
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=4)
        
    logging.info(f"[*] Scan complete. Results saved to {args.output}")
