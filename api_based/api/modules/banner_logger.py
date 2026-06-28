import socket
import ssl
from urllib.parse import urlparse

from utils.logger import Logger
from utils.exceptions import ConnectionError, TimeoutError


class BannerLogger:
    SERVICE_PROBES = {
        21: b'',
        22: b'',
        80: b'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n',
        443: None,
        8080: b'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n',
        8443: None,
        3306: b'',
        5432: b'',
        6379: b'PING\r\n',
    }

    SERVICE_NAMES = {
        21: 'FTP',
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
    }

    def __init__(self, config):
        self.config = config
        self.target_url = config['target']['url']
        self.parsed_url = urlparse(self.target_url)
        self.host = self.parsed_url.hostname or 'localhost'
        self.port_timeout = config.get('ports', {}).get('timeout', 5)
        self.port_list = config.get('ports', {}).get('list', list(self.SERVICE_PROBES.keys()))
        self.results = []

    def _send_probe(self, sock, port):
        probe_template = self.SERVICE_PROBES.get(port, b'')
        if probe_template is None:
            return None
        if probe_template:
            probe = probe_template.replace(b'{host}', self.host.encode())
            try:
                sock.sendall(probe)
            except OSError:
                pass
        return b''

    def _recv_banner(self, sock):
        try:
            data = sock.recv(1024)
            return data
        except OSError:
            return b''

    def _identify_service(self, port, banner):
        if banner:
            banner_text = banner.decode('utf-8', errors='ignore')
            first_line = banner_text.split('\r\n')[0].split('\n')[0].strip()
            for line in banner_text.split('\r\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip(), banner_text[:200]
            if first_line:
                return first_line[:80], banner_text[:200]
        return self.SERVICE_NAMES.get(port, 'Unknown'), ''

    def _probe_port(self, port):
        is_ssl = port in (443, 8443)
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(self.port_timeout)
            raw_sock.connect((self.host, port))

            if is_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    sock = context.wrap_socket(raw_sock, server_hostname=self.host)
                except ssl.SSLError:
                    raw_sock.close()
                    return None
            else:
                sock = raw_sock
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return None
        except Exception as e:
            Logger.warning(f'Port {port}: Unexpected error during connect - {e}')
            return None

        banner_raw = b''
        try:
            probe_result = self._send_probe(sock, port)
            if probe_result is not None:
                banner_raw = self._recv_banner(sock)
            else:
                banner_raw = self._recv_banner(sock)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

        service_name, banner_text = self._identify_service(port, banner_raw)
        return {
            'port': port,
            'state': 'OPEN',
            'service': service_name,
            'banner': banner_text,
            'protocol': 'TCP'
        }

    def run(self):
        Logger.info(f'Starting Network Banner Logger on {self.host}')
        for port in self.port_list:
            Logger.info(f'Scanning port {port}...')
            result = self._probe_port(port)
            if result:
                self.results.append(result)
                Logger.safe(f'Port {port}: OPEN - {result["service"]}')
            else:
                Logger.info(f'Port {port}: CLOSED/FILTERED')

        total = len(self.port_list)
        open_ports = len(self.results)
        Logger.info(f'Port scan complete: {open_ports}/{total} ports open.')
        return self.results
