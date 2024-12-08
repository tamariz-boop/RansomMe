#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "Advapi32.lib")


#define CHUNK_SIZE 4096


HCRYPTKEY LoadKeyFromFile(HCRYPTPROV hCryptProv, const char* keyFileName) {
    HCRYPTKEY hKey = 0;     // the handler to the key
    DWORD fileSize = 0;     // the key size
    DWORD bytesRead = 0;    // number of bytes read from the key file
    BYTE* keyBlob = NULL;   // pointer to the key bytes

    // open the key file
    HANDLE hFile = CreateFileA(keyFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Unable to open key file %s. Error Code: %lu\n", keyFileName, GetLastError());
        return 0;
    }

    // Get the size of the key blob
    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Error: Failed to get file size. Error Code: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 0;
    }

    // Read the key blob into memory
    keyBlob = (BYTE*)malloc(fileSize);
    if (!keyBlob) {
        printf("Error: Memory allocation failed.\n");
        CloseHandle(hFile);
        return 0;
    }

    // read the key file and store the byste in keyBlob
    if (!ReadFile(hFile, keyBlob, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("Error: Failed to read key file. Error Code: %lu\n", GetLastError());
        free(keyBlob);
        CloseHandle(hFile);
        return 0;
    }

    CloseHandle(hFile);

    // Import the key into the cryptographic provider
    if (!CryptImportKey(hCryptProv, keyBlob, fileSize, 0, 0, &hKey)) {
        printf("Error: CryptImportKey failed. Error Code: %lu\n", GetLastError());
        free(keyBlob);
        return 0;
    }

    free(keyBlob);
    return hKey;
}

BOOL DecryptFile(const char* inputFileName, const char* cryptoFileExt, HCRYPTKEY hKey) {
    HANDLE hInputFile = INVALID_HANDLE_VALUE;                   // input file handler
    HANDLE hOutputFile = INVALID_HANDLE_VALUE;                  // output file handler

    BYTE buffer[CHUNK_SIZE];                                    // buffer to read from file, encrypt and write into file
    DWORD bytesRead = 0, bytesWritten = 0;                      // number of bytes read/written return by CreateFile and CryptEncrypt
    BOOL finalChunk = FALSE;                                    // flag to tell CryptEncrypt that it is the final chunk (smaller than the rest)
    BOOL success = FALSE;                                       // flag to return success/failure

    char outputFileName[MAX_PATH] = "";                         // output file name
    const char* inputFileExt = strrchr(inputFileName, '.');     // this will point to the last '.' of inputFileName, where the crypted extension begins

    // if the input file does not contain the crypted extension, skip the decryption
    if (strcmp(inputFileExt, cryptoFileExt)) { goto cleanup; }
    else {
        // The outputFileName will be the inputFileName without the cryptoFileExt
        strncpy(outputFileName, inputFileName, inputFileExt - inputFileName);

        // Open the input file
        hInputFile = CreateFileA(inputFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hInputFile == INVALID_HANDLE_VALUE) {
            printf("Error: Could not open input file. Error Code: %lu\n", GetLastError());
            goto cleanup;
        }

        // Open the output file
        hOutputFile = CreateFileA(outputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutputFile == INVALID_HANDLE_VALUE) {
            printf("Error: Could not open output file. Error Code: %lu\n", GetLastError());
            goto cleanup;
        }

        // Encrypt and write the file data in chunks
        while (ReadFile(hInputFile, buffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
            finalChunk = (bytesRead < CHUNK_SIZE);  // the final chunk will be smaller thant CHUNK_SIZE

            // Encrypt the chunk
            if (!CryptDecrypt(hKey, 0, finalChunk, 0, buffer, &bytesRead)) {
                printf("Error: CryptEncrypt failed. Error Code: %lu\n", GetLastError());
                goto cleanup;
            }

            // Write the encrypted chunk to the output file
            if (!WriteFile(hOutputFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
                printf("Error: WriteFile failed. Error Code: %lu\n", GetLastError());
                goto cleanup;
            }
        }
    }

    success = TRUE;
    printf("File decrypted successfully.\n");

cleanup:
    if (hInputFile != INVALID_HANDLE_VALUE) CloseHandle(hInputFile);
    if (hOutputFile != INVALID_HANDLE_VALUE) CloseHandle(hOutputFile);

    // Delete the input file only if the decryption was successful
    if (success == TRUE) {
        if (!DeleteFileA(inputFileName)) {
            printf("Error: Could not delete input file. Error Code: %lu\n", GetLastError());
        }
    }

    return success;
}

size_t DecryptAllFiles(char* targetDir, const char* cryptoFileExt, HCRYPTKEY hKey) {
    WIN32_FIND_DATAA foundFileData;          // WIN32_FIND_DATA containing the file/directory info
    HANDLE hFind = INVALID_HANDLE_VALUE;    // search handle to be used with findNextFile
    size_t fileCount = 0;                   // number of files found
    char targetSubDir[MAX_PATH] = "";      // temporary variable to store the subdir
    char findTargetDir[MAX_PATH] = "";     // just to add an asterisk to the end of the targetDir but without affecting the original string
    char fullFileName[MAX_PATH] = "";      // the full file name with path to pass to EncryptFile

    // if targetDir does not end with \ we will add it as it will be more convinient later
    if (targetDir[strlen(targetDir)] != '\\') {
        strcat_s(targetDir, MAX_PATH, "\\");
    }
    // creating a copy of the dir and adding * to the end to pass it to the FindFirstFile function
    strcpy_s(findTargetDir, MAX_PATH, targetDir);
    strcat_s(findTargetDir, MAX_PATH, "*");

    // Find the first file in the directory.
    hFind = FindFirstFileA(findTargetDir, &foundFileData);

    if (INVALID_HANDLE_VALUE == hFind) {
        printf("Error: FindFirstFile failed. Error Code: %lu\n", GetLastError());
        return fileCount;
    }

    do {
        // check if it is a directory
        if (foundFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Skip "." and ".." directories
            if (strcmp(foundFileData.cFileName, ".") == 0 || strcmp(foundFileData.cFileName, "..") == 0) {
                continue;
            }
            // If it's a directory, append the folder name to the original target dir
            strcpy_s(targetSubDir, MAX_PATH, targetDir);
            strcat_s(targetSubDir, MAX_PATH, foundFileData.cFileName);

            // recursively call with every subfolder and add the number to the total files
            fileCount += DecryptAllFiles(targetSubDir, cryptoFileExt, hKey);
        }
        else {
            // If it's a file, encrypt it
            // let's create the full file name (with the full path)
            strcpy_s(fullFileName, MAX_PATH, targetDir);
            strcat_s(fullFileName, MAX_PATH, foundFileData.cFileName);
            // now encrypt the file
            DecryptFile(fullFileName, cryptoFileExt, hKey);
            fileCount++;        // let's count the number of encrypted files, why no?
        }
    } while (FindNextFileA(hFind, &foundFileData) != 0);

    // Close the search handle
    FindClose(hFind);
    return fileCount;
}

int main() {
//    char inputFileName[MAX_PATH] = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\akg.txt.enc";
//    char inputFileName[MAX_PATH] = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\test.txt.enc";
    char targetDir[MAX_PATH] = "C:\\Users\\Tamariz\\Desktop\\Test";
    const char* cryptoFileExt = ".enc";
    const char* keyFile = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\key.bin";
    size_t fileNumber = 0;      // number of encrypted files

    /*** Initialize the crypto environment. Acquire context and generate a key ***/
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;

    // Acquire a cryptographic provider context to use AES symmetric encryption
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed. Error Code: %lu\n", GetLastError());
        return FALSE;
    }

    // load the key from a file
    hKey = LoadKeyFromFile(hCryptProv, keyFile);

//    DecryptFile(inputFileName, cryptoFileExt, hKey);
    // decrypt a file
    fileNumber = DecryptAllFiles(targetDir, cryptoFileExt, hKey);
    printf("%d files decrypted.\n", fileNumber);

    /*** Release the crypt handlers ***/
    // Release the session key. 
    if (hKey) {
        if (!(CryptDestroyKey(hKey))) {
            printf("Error during CryptDestroyKey!. Error code: %lu\n", GetLastError());
        }
    }
    // Release the provider handle. 
    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0))) {
            printf("Error during CryptReleaseContext!. Error code: %lu\n", GetLastError());
        }
    }

    return 0;
}