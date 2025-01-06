import socket

from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey

from OpenSSL.SSL import Context, Connection, TLSv1_METHOD, TLSv1_2_METHOD, TLS1_2_VERSION, TLS1_3_VERSION, TLS_METHOD, TLS_SERVER_METHOD, SSLv23_METHOD
from OpenSSL import SSL

from openssl_psk import patch_context
patch_context()

def server_callback(conn, client_identity):
    print(client_identity.decode())

    ectx = ESAPI(tcti="swtpm:port=2321")
    ectx.startup(TPM2_SU.CLEAR)

    _parent_ecc_template = TPMT_PUBLIC(
        type=TPM2_ALG.ECC,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=TPMA_OBJECT.USERWITHAUTH
        | TPMA_OBJECT.RESTRICTED
        | TPMA_OBJECT.DECRYPT
        | TPMA_OBJECT.NODA
        | TPMA_OBJECT.FIXEDTPM
        | TPMA_OBJECT.FIXEDPARENT
        | TPMA_OBJECT.SENSITIVEDATAORIGIN,
        authPolicy=b"",
        parameters=TPMU_PUBLIC_PARMS(
            eccDetail=TPMS_ECC_PARMS(
                symmetric=TPMT_SYM_DEF_OBJECT(
                    algorithm=TPM2_ALG.AES,
                    keyBits=TPMU_SYM_KEY_BITS(aes=128),
                    mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
                ),
                scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                curveID=TPM2_ECC.NIST_P256,
                kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
            ),
        ),
    )
    inSensitive = TPM2B_SENSITIVE_CREATE()
    primary1, _, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

    f = open("../keys/private.pem", "r")
    k = TSSPrivKey.from_pem(f.read().encode("utf-8"))

    hmacKeyHandle = ectx.load(primary1, k.private, k.public)
    ectx.flush_context(primary1)

    thmac = ectx.hmac(hmacKeyHandle, "pre master secret".encode('utf-8') +  conn.client_random() +  conn.server_random(), TPM2_ALG.SHA256)

    print("calculated PSK: " + thmac.buffer.hex())
    ectx.flush_context(hmacKeyHandle)
    ectx.close()

    return thmac.buffer.tobytes()


ctx = Context(TLSv1_2_METHOD)
ctx.set_min_proto_version(TLS1_2_VERSION)

ctx.use_psk_identity_hint(b'Client1')
ctx.set_psk_server_callback(server_callback)

server = Connection(ctx,socket.socket(socket.AF_INET, socket.SOCK_STREAM))

HOST = '127.0.0.1'
PORT = 8081
server.bind((HOST, PORT))
server.listen(5)

while True:
    conn, addr = server.accept()
    ssl_conn = SSL.Connection(ctx, conn)
    ssl_conn.set_accept_state()
    print(ssl_conn.get_protocol_version_name()) 
    try:
        data = ssl_conn.recv(1024)
        print("Received:", data.decode())
        ssl_conn.send(b"Hello from the server!")
    except SSL.Error as e:
        print("SSL Error:", e)
    finally:
        ssl_conn.shutdown()
        ssl_conn.close()
