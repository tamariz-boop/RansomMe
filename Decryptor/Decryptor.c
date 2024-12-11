#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <strsafe.h>

#pragma comment(lib, "Advapi32.lib")

// Constants
#define CHUNK_SIZE 4096         // files will be decrypted in chunks of this size
#define MAX_THREADS 8           // max number of threads
#define MIN_THREADS 1           // min number of threads

// Struct with all the parameters to be passed to the FileDecryptWorker callback function
typedef struct {
    char filePath[MAX_PATH];            // path of the file to be decrypted
    const char* cryptoFileExt;          // extension that is appended to the encrypted file
    HCRYPTKEY hKey;                     // encryption key
    HANDLE available;                   // signal to tell the WaitForSingleObject function that the struct is available (not being used by other thread)
    BOOL success;                       // true if the file was successfully decrypted
} FileDecryptTask;


// The callback function to be called by CreateThreadpoolWork when a new work sent to the pool
VOID CALLBACK FileDecryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work) {
    UNREFERENCED_PARAMETER(instance);                               // instance will not be used
    UNREFERENCED_PARAMETER(work);                                   // work will not be used
    FileDecryptTask* taskParam = (FileDecryptTask*)parameter;       // taskParam will point to the FileDecryptTask struct

    //--------------- the decryptmyfile code
    HANDLE hInputFile = INVALID_HANDLE_VALUE;                           // input file handler
    HANDLE hOutputFile = INVALID_HANDLE_VALUE;                          // output file handler

    BYTE buffer[CHUNK_SIZE];                                            // buffer to read from file, decrypt and write into file
    DWORD bytesRead = 0, bytesWritten = 0;                              // number of bytes read/written return by CreateFile and CryptDecrypt
    BOOL finalChunk = FALSE;                                            // flag to tell CryptDecrypt that it is the final chunk (smaller than the rest)

    char outputFileName[MAX_PATH] = "";                                 // output file name
    const char* inputFileExt = strrchr(taskParam->filePath, '.');       // this will point to the last '.' of taskParam->filePath, where the crypted extension begins

    // if the input file does not contain the crypted extension, skip the decryption
    if (strcmp(inputFileExt, taskParam->cryptoFileExt)) { goto cleanup; }
    else {
        // The outputFileName will be the inputFileName without the cryptoFileExt
        strncpy(outputFileName, taskParam->filePath, inputFileExt - taskParam->filePath);

        // Open the input file
        hInputFile = CreateFileA(taskParam->filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

        // Decrypt and write the file data in chunks
        while (ReadFile(hInputFile, buffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
            finalChunk = (bytesRead < CHUNK_SIZE);  // the final chunk will be smaller thant CHUNK_SIZE

            // Decrypt the chunk
            if (!CryptDecrypt(taskParam->hKey, 0, finalChunk, 0, buffer, &bytesRead)) {
                printf("Error: CryptDecrypt failed. Error Code: %lu\n", GetLastError());
                goto cleanup;
            }

            // Write the decrypted chunk to the output file
            if (!WriteFile(hOutputFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
                printf("Error: WriteFile failed. Error Code: %lu\n", GetLastError());
                goto cleanup;
            }
        }
    }

    // set success to true because the decryption went ok
    taskParam->success = TRUE;
    //    printf("\rFile %s decrypted successfully.", inputFileName);
    //    fflush(stdout);

cleanup:
    if (hInputFile != INVALID_HANDLE_VALUE) CloseHandle(hInputFile);
    if (hOutputFile != INVALID_HANDLE_VALUE) CloseHandle(hOutputFile);

    // Delete the input file only if the decryption was successful
    if (taskParam->success == TRUE) {
        if (!DeleteFileA(taskParam->filePath)) {
            printf("Error: Could not delete input file. Error Code: %lu\n", GetLastError());
        }
    }
// ------------------------------------------------------
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

// Initialize the crypto environment, hCryptProv will point to the crypt provider and hKey to the key handler
BOOL InitCrypto(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey, const char* keyFile) {
    // Acquire a cryptographic provider context to use AES symmetric encryption
    if (!CryptAcquireContext(hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed. Error Code: %lu\n", GetLastError());
        return FALSE;
    }
    // load the key from a file
    *hKey = LoadKeyFromFile(*hCryptProv, keyFile);

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
void GetTime(ULARGE_INTEGER* time) {
    FILETIME fTime;

    // Get the time
    GetSystemTimeAsFileTime(&fTime);
    time->LowPart = fTime.dwLowDateTime;
    time->HighPart = fTime.dwHighDateTime;

    return;
}

// given a target directory this will crawl into it and call DecryptMyFile for every file found on it and its subdirectories
size_t DecryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, FileDecryptTask* taskPool) {
    WIN32_FIND_DATAA foundFileData;          // WIN32_FIND_DATA containing the file/directory info
    HANDLE hFind = INVALID_HANDLE_VALUE;     // search handle to be used with findNextFile

    size_t fileCount = 0;                    // number of files found

    char targetSubDir[MAX_PATH] = "";        // temporary variable to store the subdir
    char findTargetDir[MAX_PATH] = "";       // just to add an asterisk to the end of the targetDir but without affecting the original string
    char fullFileName[MAX_PATH] = "";        // the full file name with path to pass to DecryptMyFile

    PTP_WORK work = NULL;
    FileDecryptTask* task = NULL;

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
            fileCount += DecryptAllFiles(targetSubDir, cryptoFileExt, decryptedFileNumber, hKey, poolEnv, taskPool);
        }
        else {
            // If it's a file, decrypt it
            // Point the next available struct to task. A round robin is used with fileCount % MAX_THREADS
            task = &taskPool[fileCount % MAX_THREADS];
            // Block until the event is signaled
            WaitForSingleObject(task->available, INFINITE);

            // Add 1 to the decrypted file count if the previous one returned success
            if (task->success) { (*decryptedFileNumber)++; }

            // Mark the task as in-use by resetting the event
            ResetEvent(task->available);

            // Copy the current dir and append the found file name to task->filePath
            strcpy_s(task->filePath, MAX_PATH, targetDir);
            if (my_strcat_s(task->filePath, MAX_PATH, foundFileData.cFileName) != 0) {
                printf("Skipping file %s in dir %s. Name might be too long.\n", foundFileData.cFileName, targetDir);
                continue;
            }

            // Submit the task to the thread pool
            work = CreateThreadpoolWork(FileDecryptWorker, task, poolEnv);
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

// this will initialize the FileDecryptTask structs and call DecryptAllFiles. Finally it will securely close the thread handlers and finish up the decrypted files count
size_t startDecryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup) {
    size_t fileCount = 0;
    HCRYPTKEY* hKeys = NULL;
    FileDecryptTask* taskPool = NULL;

    // Allocate memory for the array of FileDecryptTask structs
    taskPool = (FileDecryptTask*)malloc(MAX_THREADS * sizeof(FileDecryptTask));
    if (taskPool == NULL) {
        printf("Failed to allocate memory for FileEncryptTask struct array.\n");
        return fileCount;
    }

    // Allocate memory for the array of HCRYPTKEY handles
    hKeys = (HCRYPTKEY*)malloc(MAX_THREADS * sizeof(HCRYPTKEY));
    if (hKeys == NULL) {
        printf("Failed to allocate memory for HCRYPTKEY array.\n");
        return fileCount;
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        taskPool[i].filePath[0] = '\0';                                 // initialize file path as empty
        taskPool[i].cryptoFileExt = cryptoFileExt;                      // the crypto extension
        CryptDuplicateKey(hKey, NULL, 0, &hKeys[i]);                    // duplicate the key for each thread - CryptDecrypt is not thread-safe according to MS
        taskPool[i].hKey = hKeys[i];                                    // the encryption key for each thread will be a copy of the key
        taskPool[i].success = FALSE;                                    // initialize success as false, this will be used to count the total decrypted files

        // Setup an event to tell WaitForSingleObject when a struct is available
        taskPool[i].available = CreateEventA(NULL, TRUE, TRUE, NULL);    // Manual reset, initially signaled
        if (!taskPool[i].available) {
            printf("Error: Failed to create event for task pool. Error Code: %lu\n", GetLastError());
            return 0;
        }
    }

    fileCount = DecryptAllFiles(targetDir, cryptoFileExt, decryptedFileNumber, hKey, poolEnv, taskPool);

    // Clean up the thread pool, this will wait for all callbacks to finish, even those that are waiting to start
    if (cleanupgroup) {
        CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
    }

    // Add the results from the last task of each thread
    for (int i = 0; i < MAX_THREADS; i++) {
        if (taskPool[i].success) { (*decryptedFileNumber)++; }
    }

    // Cleanup the key copies
    for (int i = 0; i < MAX_THREADS; i++) {
        if (hKeys[i] != NULL) {
            CryptDestroyKey(hKeys[i]);
        }
    }

    // free allocated memory
    free(hKeys);
    free(taskPool);

    return fileCount;
}


int main() {
    // this will be command parameters later
    char targetDir[MAX_PATH] = "C:\\Users\\Tamariz\\Desktop\\Test\\a";
    //    char inputFileName[MAX_PATH] = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\test.txt";
    //    char targetDir[MAX_PATH] = "C:\\Users\\Tamariz\\Desktop\\Test";
    const char* cryptoFileExt = ".enc";
    const char* keyFile = "C:\\Users\\Tamariz\\source\\repos\\RansomMe\\x64\\Debug\\key.bin";

    //------------- LOCAL VARIABLES -------------------------------------------------
        // general purpose variables
    size_t totalFileNumber = 0;                     // number of files found
    size_t decryptedFileNumber = 0;                 // number of decrypted files
    ULARGE_INTEGER start, end;                      // start time and end time to measure performance

    // thread pool variables
    TP_CALLBACK_ENVIRON poolEnv;                    // a pool environment struct to handle the thread pool
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
    if (!InitCrypto(&hCryptProv, &hKey, keyFile)) {
        printf("Could not initialize the crypto environment. Error code: %lu\n", GetLastError());
        return 0;
    }

    // start the timer
    GetTime(&start);

    totalFileNumber = startDecryptionWithThreads(targetDir, cryptoFileExt, &decryptedFileNumber, hKey, &poolEnv, cleanupgroup);

    // end the time    
    GetTime(&end);

    printf("%zd files found.\n", totalFileNumber);
    printf("%zd files decrypted.\n", decryptedFileNumber);

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
