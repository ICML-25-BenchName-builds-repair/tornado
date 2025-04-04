import asyncio
import logging
import os
import socket
import ssl
from tornado.iostream import SSLIOStream
from tornado.log import gen_log
from tornado.testing import ExpectLog, AsyncTestCase, gen_test
import unittest

class TestReproduction(AsyncTestCase):
    def setUp(self):
        super().setUp()
        # Setup similar to TestIOStreamCheckHostname
        self.listener = socket.create_server(('127.0.0.1', 0), backlog=1, reuse_port=False)
        self.port = self.listener.getsockname()[1]
        
        # Create SSL context for server
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(
            os.path.join(os.path.dirname(__file__), "tornado/test/test.crt"),
            os.path.join(os.path.dirname(__file__), "tornado/test/test.key"),
        )
        
        # Accept connections
        def accept_callback():
            try:
                connection, address = self.listener.accept()
                connection = ssl_ctx.wrap_socket(
                    connection,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                SSLIOStream(connection)
            except Exception as e:
                print(f"Accept error: {e}")
        
        # Start accept in a separate task
        self.accept_task = asyncio.create_task(self.io_loop.run_in_executor(None, accept_callback))
        
        # Client SSL context
        self.client_ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.client_ssl_ctx.load_verify_locations(
            os.path.join(os.path.dirname(__file__), "tornado/test/test.crt")
        )

    def tearDown(self):
        self.listener.close()
        if hasattr(self, 'accept_task'):
            self.accept_task.cancel()
        super().tearDown()

    @gen_test
    async def test_no_match(self):
        # Configure logging to see what's happening
        logging.basicConfig(level=logging.DEBUG)
        
        # Create client stream
        stream = SSLIOStream(socket.socket(), ssl_options=self.client_ssl_ctx)
        
        # This is the test that's failing on Windows
        with ExpectLog(gen_log, ".*alert bad certificate", level=logging.WARNING):
            with self.assertRaises(ssl.SSLCertVerificationError):
                with ExpectLog(
                    gen_log,
                    ".*(certificate verify failed: Hostname mismatch)",
                    level=logging.WARNING,
                ):
                    await stream.connect(
                        ("127.0.0.1", self.port),
                        server_hostname="bar.example.com",
                    )

if __name__ == "__main__":
    unittest.main()