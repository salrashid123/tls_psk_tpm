import socket
import hmac
import hashlib

from OpenSSL.SSL import Context, Connection, TLSv1_METHOD, TLSv1_2_METHOD, TLS_METHOD, SSLv23_METHOD, TLS1_2_VERSION, TLS1_3_VERSION, TLS_CLIENT_METHOD
from OpenSSL import SSL
from openssl_psk import patch_context
patch_context()

def client_callback(conn, identity_hint):
    print(identity_hint.decode())

    h = hmac.new( bytes.fromhex('6368616e676520746869732070617373776f726420746f206120736563726574'), "pre master secret".encode('utf-8') +  conn.client_random() +  conn.server_random(), hashlib.sha256 )
    print("calculated PSK: " + h.digest().hex())
    return (b'Client1',bytes.fromhex(h.digest().hex()))

ctx = Context(TLSv1_2_METHOD)
ctx.set_min_proto_version(TLS1_2_VERSION)

ctx.set_psk_client_callback(client_callback)
client = Connection(ctx)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = SSL.Connection(ctx, sock)
ssl_sock.connect(('localhost', 8081))
print(ssl_sock.get_protocol_version_name())

ssl_sock.send(b'Hello, server!')

response = ssl_sock.recv(1024)
print(response.decode('utf-8'))
ssl_sock.close()

