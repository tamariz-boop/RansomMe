from http.server import HTTPServer, BaseHTTPRequestHandler
import struct
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def get_privatekey():
    """
    Parse a BCRYPT_RSAFULLPRIVATE_BLOB and convert it to an RSA private key.
    """
    with open("private.bin", "rb") as f:
        blob  = f.read()
    
    offset = 0
    
    # the header is in little-endian: magic number, and length of parameters
    magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2 = struct.unpack_from('<IIIIII', blob, offset)
    
    # this is optional too, check the magic number for 'RSA3' in big-endian
    if magic != 0x33415352:
        raise ValueError("Invalid RSA key magic number")
    
    # each I is 4 bytes, we retrieved 6 for a total of 24 bytes
    offset += 24
    
    # extract each parameter, the size is in bytes for all parameters except for the BitLength
    # the parameters are in big-endian
    
    # public exponent (e)
    public_exponent = blob[offset:offset + cbPublicExp]
    offset += cbPublicExp
    
    # modulus (n)
    modulus = blob[offset:offset + cbModulus]
    offset += cbModulus
    
    # prime (p)
    prime1 = blob[offset:offset + cbPrime1]
    offset += cbPrime1
    
    # prime (q)
    prime2 = blob[offset:offset + cbPrime2]
    offset += cbPrime2
    
    # d % (p - 1)
    exponent1 = blob[offset:offset + cbPrime1]
    offset += cbPrime1
    
    # d % (q - 1)
    exponent2 = blob[offset:offset + cbPrime2]
    offset += cbPrime2
    
    # 1/ (q mod p)
    coefficient = blob[offset:offset + cbPrime1]
    offset += cbPrime1
    
    # private exponent (d)
    private_exponent = blob[offset:offset + cbModulus]
    offset += cbModulus
    
    # Reconstruct the RSA private key
    private_numbers = rsa.RSAPrivateNumbers(
     p=int.from_bytes(prime1, "big"),
     q=int.from_bytes(prime2, "big"),
     d=int.from_bytes(private_exponent, "big"),
     dmp1=int.from_bytes(exponent1, "big"),
     dmq1=int.from_bytes(exponent2, "big"),
     iqmp=int.from_bytes(coefficient, "big"),
     public_numbers=rsa.RSAPublicNumbers(
         e=int.from_bytes(public_exponent, "big"),
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
    # Decrypt the key using PKCS1v15 as padding (this is insecure, I will switch to OAEP later)
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the decrypted symmetric key to a file
    with open("key.bin", "wb") as output_file:
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