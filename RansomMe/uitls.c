#include "RansomMe.h"

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