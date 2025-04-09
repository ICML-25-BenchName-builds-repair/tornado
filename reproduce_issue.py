import sys
import ssl
import logging
from tornado.iostream import SSLIOStream
from tornado.log import gen_log

# Let's directly examine the SSL error handling in SSLIOStream
print(f"Running on platform: {sys.platform}")

# Configure logging to see what's happening
logging.basicConfig(level=logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
gen_log.addHandler(handler)
gen_log.setLevel(logging.DEBUG)

# Let's look at the _is_connreset method in SSLIOStream
print("\nExamining SSLIOStream._is_connreset method:")
print(SSLIOStream._is_connreset.__code__.co_varnames)
print(SSLIOStream._is_connreset.__code__.co_consts)

# Let's look at how SSL errors are handled
print("\nSSL error handling in SSLIOStream:")
print("SSL_ERROR_EOF:", ssl.SSL_ERROR_EOF)

# Let's check if there are platform-specific differences in SSL error codes
print("\nSSL error codes:")
for name in dir(ssl):
    if name.startswith("SSL_ERROR_"):
        value = getattr(ssl, name)
        print(f"{name}: {value}")

# Let's check if there are platform-specific differences in SSL error messages
print("\nTesting SSL error messages:")
try:
    # Create an invalid SSL context to trigger an error
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    # This will fail with a certificate verification error
    sock = ssl.create_connection(("example.com", 443))
    ssl_sock = context.wrap_socket(sock, server_hostname="example.com")
except ssl.SSLError as e:
    print(f"SSL error: {type(e).__name__}: {e}")
    print(f"Error args: {e.args}")
except Exception as e:
    print(f"Other error: {type(e).__name__}: {e}")