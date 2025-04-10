import asyncio
import logging
import os
import socket
import ssl
import re
from tornado.iostream import SSLIOStream
from tornado.log import gen_log
from tornado.testing import AsyncTestCase, gen_test, bind_unused_port
from tornado import netutil

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class CustomExpectLog(logging.Filter):
    def __init__(self, logger, regex, required=True, level=None):
        super().__init__()
        self.logger = logger
        self.regex = re.compile(regex)
        self.required = required
        self.level = level
        self.matched = 0
        
    def filter(self, record):
        message = record.getMessage()
        print(f"Filter called with message: {message!r}")
        if self.level is None or record.levelno == self.level:
            match = bool(self.regex.match(message))
            print(f"  Match result: {match}")
            if match:
                self.matched += 1
                print(f"  Matched count: {self.matched}")
        return True  # Always let the message through for debugging
        
    def __enter__(self):
        self.logger.addFilter(self)
        return self
        
    def __exit__(self, typ, val, tb):
        self.logger.removeFilter(self)
        if not typ and self.required and not self.matched:
            print("ERROR: did not get expected log message")
            # Don't raise an exception for testing
        return False

class TestSSLCertVerification(AsyncTestCase):
    def setUp(self):
        super().setUp()
        self.listener, self.port = bind_unused_port()

        def accept_callback(connection, address):
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(
                os.path.join(os.path.dirname(__file__), "tornado/test/test.crt"),
                os.path.join(os.path.dirname(__file__), "tornado/test/test.key"),
            )
            connection = ssl_ctx.wrap_socket(
                connection,
                server_side=True,
                do_handshake_on_connect=False,
            )
            SSLIOStream(connection)

        netutil.add_accept_handler(self.listener, accept_callback)

        # Our self-signed cert is its own CA.  We have to pass the CA check before
        # the hostname check will be performed.
        self.client_ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.client_ssl_ctx.load_verify_locations(
            os.path.join(os.path.dirname(__file__), "tornado/test/test.crt")
        )

    def tearDown(self):
        self.io_loop.remove_handler(self.listener.fileno())
        self.listener.close()
        super().tearDown()

    @gen_test
    async def test_no_match(self):
        stream = SSLIOStream(socket.socket(), ssl_options=self.client_ssl_ctx)
        with CustomExpectLog(gen_log, ".*alert bad certificate", level=logging.WARNING):
            try:
                await stream.connect(
                    ("127.0.0.1", self.port),
                    server_hostname="bar.example.com",
                )
            except Exception as e:
                print(f"Got expected exception: {e}")

if __name__ == "__main__":
    test = TestSSLCertVerification("test_no_match")
    test.setUp()
    asyncio.run(test.test_no_match())
    test.tearDown()