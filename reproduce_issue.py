import asyncio
import logging
import os
import socket
import ssl
from tornado.iostream import SSLIOStream
from tornado.log import gen_log
from tornado.testing import AsyncTestCase, gen_test, ExpectLog

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class TestSSLCertificateError(AsyncTestCase):
    def setUp(self):
        super().setUp()
        # Create a self-signed certificate
        self.cert_path = os.path.join(os.path.dirname(__file__), "tornado/test/test.crt")
        self.key_path = os.path.join(os.path.dirname(__file__), "tornado/test/test.key")
        
        # Set up server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('127.0.0.1', 0))
        self.server_socket.listen(1)
        self.port = self.server_socket.getsockname()[1]
        
        # Set up SSL context for client
        self.client_ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.client_ssl_ctx.load_verify_locations(self.cert_path)
        
        # Start server in a separate task
        asyncio.ensure_future(self.run_server())
    
    async def run_server(self):
        while True:
            try:
                connection, address = self.server_socket.accept()
                ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_ctx.load_cert_chain(self.cert_path, self.key_path)
                ssl_connection = ssl_ctx.wrap_socket(
                    connection,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                SSLIOStream(ssl_connection)
            except Exception as e:
                print(f"Server error: {e}")
                break
    
    def tearDown(self):
        self.server_socket.close()
        super().tearDown()
    
    @gen_test
    async def test_certificate_error(self):
        # This test tries to connect with a mismatched hostname
        stream = SSLIOStream(socket.socket(), ssl_options=self.client_ssl_ctx)
        
        # This should log a warning about certificate verification failure
        with ExpectLog(gen_log, ".*alert bad certificate", level=logging.WARNING):
            with self.assertRaises(ssl.SSLCertVerificationError):
                await stream.connect(
                    ("127.0.0.1", self.port),
                    server_hostname="bar.example.com",
                )

if __name__ == "__main__":
    import unittest
    unittest.main()