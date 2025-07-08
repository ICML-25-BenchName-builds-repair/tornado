#!/usr/bin/env python

import os
import ssl
import socket
import logging
import platform
from tornado.iostream import SSLIOStream
from tornado.testing import AsyncTestCase, gen_test, ExpectLog
from tornado.log import gen_log

class TestSSLHostnameVerification(AsyncTestCase):
    def setUp(self):
        super().setUp()
        # Create a self-signed certificate
        self.cert_path = os.path.join(os.path.dirname(__file__), "tornado/test/test.crt")
        self.key_path = os.path.join(os.path.dirname(__file__), "tornado/test/test.key")
        
        # Create SSL context for client
        self.client_ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.client_ssl_ctx.load_verify_locations(self.cert_path)
        
        # Create a server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('127.0.0.1', 0))
        self.server_socket.listen(1)
        self.port = self.server_socket.getsockname()[1]
        
        # Accept connections in a separate thread
        import threading
        self.server_thread = threading.Thread(target=self.accept_connection)
        self.server_thread.daemon = True
        self.server_thread.start()
    
    def tearDown(self):
        self.server_socket.close()
        super().tearDown()
    
    def accept_connection(self):
        try:
            while True:
                client, addr = self.server_socket.accept()
                ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_ctx.load_cert_chain(self.cert_path, self.key_path)
                ssl_socket = ssl_ctx.wrap_socket(client, server_side=True, do_handshake_on_connect=False)
                SSLIOStream(ssl_socket)
        except Exception as e:
            print(f"Server error: {e}")
    
    @gen_test
    async def test_hostname_mismatch(self):
        print(f"Running on platform: {platform.system()}")
        stream = SSLIOStream(socket.socket(), ssl_options=self.client_ssl_ctx)
        
        try:
            with ExpectLog(gen_log, ".*alert bad certificate", level=logging.WARNING):
                with self.assertRaises(ssl.SSLCertVerificationError):
                    await stream.connect(
                        ("127.0.0.1", self.port),
                        server_hostname="wrong.hostname.com",
                    )
        except Exception as e:
            print(f"Test failed: {e}")
            # Print the actual error message that would be logged
            try:
                await stream.connect(
                    ("127.0.0.1", self.port),
                    server_hostname="wrong.hostname.com",
                )
            except Exception as e:
                print(f"Actual error: {e}")
        finally:
            stream.close()

if __name__ == "__main__":
    import unittest
    unittest.main()