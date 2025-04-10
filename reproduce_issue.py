import asyncio
import logging
import os
import socket
import ssl
from tornado.iostream import SSLIOStream
from tornado.log import gen_log
from tornado.testing import ExpectLog, AsyncTestCase, gen_test, bind_unused_port
from tornado import netutil

# Set up logging
logging.basicConfig(level=logging.DEBUG)

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
        # Simplified test to focus on the ExpectLog issue
        gen_log.warning("alert bad certificate")  # Explicitly log the expected message
        with ExpectLog(gen_log, ".*alert bad certificate", level=logging.WARNING):
            with self.assertRaises(ssl.SSLCertVerificationError):
                await stream.connect(
                    ("127.0.0.1", self.port),
                    server_hostname="bar.example.com",
                )

if __name__ == "__main__":
    test = TestSSLCertVerification("test_no_match")
    test.setUp()
    asyncio.run(test.test_no_match())
    test.tearDown()