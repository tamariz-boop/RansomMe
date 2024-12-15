#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define PEM_PRIVATE_HEADER "-----BEGIN PRIVATE KEY-----\n"
#define PEM_PRIVATE_FOOTER "\n-----END PRIVATE KEY-----\n"
#define PEM_PUBLIC_HEADER "-----BEGIN PUBLIC KEY-----\n"
#define PEM_PUBLIC_FOOTER "\n-----END PUBLIC KEY-----\n"

#define RSA_2048 0x08000000

// Base64 encoding function
BOOL Base64Encode(const BYTE* data, DWORD dataLen, char** encoded) {
    DWORD encodedLen = 0;

    if (!CryptBinaryToStringA(data, dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedLen)) {
        printf("Base64 length calculation failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    *encoded = (char*)malloc(encodedLen);
    if (*encoded == NULL) {
        printf("Memory allocation failed.\n");
        return FALSE;
    }

    if (!CryptBinaryToStringA(data, dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *encoded, &encodedLen)) {
        printf("Base64 encoding failed. Error: %lu\n", GetLastError());
        free(*encoded);
        return FALSE;
    }

    return TRUE;
}

// Write PEM file
BOOL WritePEMFile(const char* filename, const char* header, const char* footer, const char* base64Data) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        printf("Failed to open file %s for writing.\n", filename);
        return FALSE;
    }

    fprintf(file, "%s%s%s", header, base64Data, footer);
    fclose(file);
    return TRUE;
}

// Export key in PEM format
BOOL ExportKeyToPEM(HCRYPTKEY hKey, DWORD blobType, const char* header, const char* footer, const char* filename) {
    DWORD blobLen = 0;

    // Get required size for the key blob
    if (!CryptExportKey(hKey, 0, blobType, 0, NULL, &blobLen)) {
        printf("Failed to get blob size. Error: %lu\n", GetLastError());
        return FALSE;
    }

    BYTE* blob = (BYTE*)malloc(blobLen);
    if (blob == NULL) {
        printf("Memory allocation failed for blob.\n");
        return FALSE;
    }

    // Export the key to a blob
    if (!CryptExportKey(hKey, 0, blobType, 0, blob, &blobLen)) {
        printf("Failed to export key. Error: %lu\n", GetLastError());
        free(blob);
        return FALSE;
    }

    // Encode blob to Base64
    char* base64Data = NULL;
    if (!Base64Encode(blob, blobLen, &base64Data)) {
        printf("Base64 encoding failed.\n");
        free(blob);
        return FALSE;
    }

    // Write Base64 data to PEM file
    if (!WritePEMFile(filename, header, footer, base64Data)) {
        printf("Failed to write PEM file %s.\n", filename);
        free(blob);
        free(base64Data);
        return FALSE;
    }

    free(blob);
    free(base64Data);
    printf("Successfully exported key to %s\n", filename);
    return TRUE;
}

int main() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;

    // Acquire context and generate key pair
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
        if (GetLastError() == NTE_EXISTS) {
            if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
                printf("Failed to acquire existing context. Error: %lu\n", GetLastError());
                return 1;
            }
        }
        else {
            printf("Failed to acquire context. Error: %lu\n", GetLastError());
            return 1;
        }
    }

    // Generate public/private key pair with RSA 2048 bit for key length
    if (!CryptGenKey(hProv, AT_KEYEXCHANGE, RSA_2048 | CRYPT_EXPORTABLE, &hKey)) {
        printf("Failed to generate key pair. Error: %lu\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        return 1;
    }

    // Export private key
    if (!ExportKeyToPEM(hKey, PRIVATEKEYBLOB, PEM_PRIVATE_HEADER, PEM_PRIVATE_FOOTER, "private_key.pem")) {
        printf("Failed to export private key.\n");
    }

    // Export public key
    if (!ExportKeyToPEM(hKey, PUBLICKEYBLOB, PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER, "public_key.pem")) {
        printf("Failed to export public key.\n");
    }

    // Cleanup
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    printf("Key export process completed.\n");
    return 0;
}