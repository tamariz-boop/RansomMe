#define _CRT_SECURE_NO_WARNINGS

#include "..\RansomMe\RansomMe.h"

int main(int argc, char* argv[]) {
    const char* defaultCryptoFileExt = ".enc";
    const char* defaultKeyFileName = "\\key.bin";

    char* parsed = NULL;

    char targetDir[MAX_PATH] = "\0";
    char cryptoFileExt[MAX_EXT] = "\0";
    char keyFile[MAX_PATH] = "\0";

    DWORD procNum = 1;
    DWORD threadNum = 1;

    // Get the number of processors to set the maximum number of threads
    if (!getNumberOfProcessors(&procNum)) {
        threadNum = procNum;
    }
    else {
        printf("WARNING: Could not retrieve the processors number. The software will run on a sigle thread\n");
    }

    //-------------------------------- Check for input parameters --------------------------------------------------//
    for (size_t i = 0; i < argc; i++) {
        if (i == 0) { continue; }                   // skip the app name

        parsed = strchr(argv[i], ':');              // parse the argument value
        parsed = parsed + 1;                        // remove the ':' character

        if (argv[i][0] == '/') {                    // parse arguments in the following format /t:argument

            switch (argv[i][1]) {
                // target directory
                case 't':
                    // targetDir must not be longer than MAX_PATH (Windows constant)
                    if (strlen(parsed) > MAX_PATH) {
                        printf("Error: targetDir is longer than %d characters\n", MAX_PATH);
                        return 0;
                    }
                    else {
                        // Copy the target dir to targetDir
                        strcpy_s(targetDir, MAX_PATH, parsed);
                    }
                    break;
                // encrypted extension
                case 'e':
                    // cryptoFileExt must not be longer than MAX_EXT - 1 (the '.' is included in the max length)
                    if (strlen(parsed) >= (MAX_EXT - 1)) {
                        printf("Error: cryptoExtension cannot be longer than %d characters (including the prepended '.')\n", MAX_EXT);
                        return 0;
                    }
                    else {
                        // Copy the target dir to targetDir and prepend the '.'
                        sprintf_s(cryptoFileExt, MAX_EXT, ".%s", parsed);
                    }
                    break;
                // key file
                case 'k':
                    // keyFile file must not be longer than MAX_PATH
                    if (strlen(parsed) > MAX_PATH) {
                        printf("Error: keyFile cannot be longer than %d characters\n", MAX_PATH);
                        return 0;
                    }
                    else {
                        // Copy the target dir to targetDir and prepend the '.'
                        strcpy_s(keyFile, MAX_PATH, parsed);
                    }
                    break;
                // number of threads
                case 'n':
                    threadNum = atoi(parsed);
                    if (threadNum > procNum) {
                        printf("Error: threadNum cannot be bigger than %d\n", procNum);
                        return 0;
                    }
                    break;
            }
        }
        else {
            printf("Error: unrecognized option %s\n", argv[i]);
            printf("Usage: .%s\n\t/t:<targetDir> (mandatory)\n\t/e:<cryptoExtension> (default=enc)\n\t/k:<keyFile> (default:.\\key.bin)\n\t/n:<threadNum> (default=number of processors)\n", strrchr(argv[0], '\\'));
            return 0;
        }
    }
    // set the default values, targetDir is mandatory
    if (targetDir[0] == '\0') {
        printf("Error: missing mandatory option /t:<targetDir>\n");
        printf("Usage: .%s\n\t/t:<targetDir> (mandatory)\n\t/e:<cryptoExtension> (default=enc)\n\t/k:<keyFile> (default:.\\key.bin)\n\t/n:<threadNum> (default=number of processors)\n", strrchr(argv[0], '\\'));
        return 0;
    }
    // set the default crypto extension
    if (cryptoFileExt[0] == '\0') {
        strcpy_s(cryptoFileExt, MAX_EXT, defaultCryptoFileExt);
    }
    // set the default key file
    if (keyFile[0] == '\0') {
        // Get the current directory to import the key from there
        if (!GetCurrentDirectoryA(MAX_PATH, keyFile)) {
            printf("Error getting the current directory. Error code: %lu\n", GetLastError());
            return 0;
        }
        // Append the default key file name
        my_strcat_s(keyFile, MAX_PATH, defaultKeyFileName);
    }
    // the default threads number is the number of logical processors detected or 1 if that failed

    //------------- LOCAL VARIABLES -------------------------------------------------
        // general purpose variables
    size_t totalFileNumber = 0;                     // number of files found
    size_t decryptedFileNumber = 0;                 // number of decrypted files
    ULARGE_INTEGER start, end;                      // start time and end time to measure performance
    NTSTATUS status = 0;                            // status code returned from BCRYPT functions

    // thread pool variables
    TP_CALLBACK_ENVIRON poolEnv;                    // a pool environment struct to handle the thread pool
    PTP_CLEANUP_GROUP cleanupgroup = NULL;          // a cleanup group handle to safely close all the threads in the pool

    // encryption variables
    BCRYPT_ALG_HANDLE hAlgProv = 0;                      // handler for the crypto provider
    BCRYPT_KEY_HANDLE hKey = 0;                             // handler for the encryption key

    //------------- INIT AND EXECUTE --------------------------------------------------
    // Initialize the thread pool. This will create a thread pool and a cleanup group
    //   and will link them to the same pool environment handler
    if (!InitThreadPool(&poolEnv, &cleanupgroup, threadNum)) {
        printf("Could not initialize the thread pool. Error code: %lu\n", GetLastError());
        goto cleanup;
    }

    // Initialize the crypto environment. This will acquire a context and generate a key
    if (!initDeCrypto(&hAlgProv, &hKey, keyFile)) {
        fprintf(stderr, "Could not initialize the crypto environment. Error code: %lu\n", GetLastError());
        goto cleanup;
    }

    // start the timer
    GetTime(&start);

    totalFileNumber = startDecryptionWithThreads(targetDir, cryptoFileExt, &decryptedFileNumber, hKey, &poolEnv, cleanupgroup, threadNum);

    // end the time    
    GetTime(&end);

    printf("%zd files found.\n", totalFileNumber);
    printf("%zd files decrypted.\n", decryptedFileNumber);

    // Calculate the elapsed time in seconds
    ULONGLONG elapsedMilliseconds = (end.QuadPart - start.QuadPart) / 10000000;
    printf("Elapsed Time: %llu seconds\n", elapsedMilliseconds);

    //------------- CLEAN UP --------------------------------------------------------
cleanup:

    if (hKey) { BCryptDestroyKey(hKey); }
    if (hAlgProv) { BCryptCloseAlgorithmProvider(hAlgProv, 0); }

    return 0;
}
