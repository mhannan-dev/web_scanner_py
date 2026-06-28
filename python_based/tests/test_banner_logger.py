import unittest
from unittest.mock import patch, MagicMock
from modules.banner_logger import BannerLogger


class TestBannerLogger(unittest.TestCase):

    def setUp(self):
        self.config = {
            'target': {'url': 'http://localhost:8000'},
            'ports': {
                'timeout': 2,
                'list': [80, 443],
            }
        }

    @patch('modules.banner_logger.socket.socket')
    def test_open_port_http(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_sock_instance.recv.return_value = b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n'
        mock_socket.return_value.__enter__.return_value = mock_sock_instance

        logger = BannerLogger(self.config)
        results = logger.run()

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['port'], 80)
        self.assertEqual(results[0]['state'], 'OPEN')

    @patch('modules.banner_logger.socket.socket')
    @patch('modules.banner_logger.ssl.create_default_context')
    def test_closed_port(self, mock_ssl_context, mock_socket):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError
        mock_socket.return_value = mock_sock

        mock_ssl_context.return_value.wrap_socket.side_effect = ConnectionRefusedError

        logger = BannerLogger(self.config)
        results = logger.run()

        self.assertEqual(len(results), 0)

    @patch('modules.banner_logger.socket.socket')
    @patch('modules.banner_logger.ssl.create_default_context')
    def test_open_port_https(self, mock_ssl_context, mock_socket):
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.recv.return_value = b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n'
        mock_ssl_context.return_value.wrap_socket.return_value = mock_ssl_sock

        mock_raw_sock = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_raw_sock

        logger = BannerLogger(self.config)

        results = logger.run()

        self.assertEqual(len(results), 2)

    def test_service_identification(self):
        logger = BannerLogger(self.config)
        service, banner = logger._identify_service(80, b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n')
        self.assertIn('Apache', service)

    def test_unknown_banner(self):
        logger = BannerLogger(self.config)
        service, banner = logger._identify_service(3306, b'')
        self.assertEqual(service, 'MySQL')


if __name__ == '__main__':
    unittest.main()
