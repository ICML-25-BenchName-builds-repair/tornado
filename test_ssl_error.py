import os
import socket
import ssl
import sys
import unittest
import logging
from tornado.iostream import SSLIOStream
from tornado.log import gen_log
from tornado.testing import AsyncTestCase, gen_test, ExpectLog

class TestSSLError(AsyncTestCase):
    def setUp(self):
        super().setUp()
        # Create a self-signed certificate
        self.cert_file = os.path.join(os.path.dirname(__file__), "tornado/test/test.crt")
        self.key_file = os.path.join(os.path.dirname(__file__), "tornado/test/test.key")
        
        # Create SSL context
        self.client_ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.client_ssl_ctx.load_verify_locations(self.cert_file)
        
        # Set up a simple socket server
        self.server_socket = socket.socket()
        self.server_socket.bind(('127.0.0.1', 0))
        self.server_socket.listen(1)
        self.port = self.server_socket.getsockname()[1]
        
        # Accept connections in the background
        self.io_loop.add_callback(self.accept_connection)
    
    def tearDown(self):
        self.server_socket.close()
        super().tearDown()
    
    async def accept_connection(self):
        try:
            connection, address = self.server_socket.accept()
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(self.cert_file, self.key_file)
            ssl_connection = ssl_ctx.wrap_socket(
                connection,
                server_side=True,
                do_handshake_on_connect=False,
            )
            SSLIOStream(ssl_connection)
        except Exception as e:
            print(f"Error accepting connection: {e}")
    
    @gen_test
    async def test_ssl_error_message(self):
        """Test that SSL errors are logged with the expected message."""
        stream = SSLIOStream(socket.socket(), ssl_options=self.client_ssl_ctx)
        
        # Print the platform for debugging
        print(f"Platform: {sys.platform}")
        
        # Try with different log patterns for different platforms
        if sys.platform.startswith('win'):
            log_pattern = ".*certificate.*"
        else:
            log_pattern = ".*alert bad certificate.*"
        
        with ExpectLog(gen_log, log_pattern, level=logging.WARNING):
            with self.assertRaises(ssl.SSLCertVerificationError):
                await stream.connect(
                    ("127.0.0.1", self.port),
                    server_hostname="bar.example.com",
                )

if __name__ == "__main__":
    unittest.main()