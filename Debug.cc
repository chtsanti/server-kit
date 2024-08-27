#include "Debug.h"
#include <iostream>

int __DEBUG_LEVEL = 0;
int __DEBUG_STDOUT = 0;
int __DEBUG_MAX_LEVEL = 0;
std::string DEBUG_PATH;
std::ofstream *__DebugFile = nullptr;

bool DebugInit()
{
    __DEBUG_MAX_LEVEL = std::max(__DEBUG_LEVEL, __DEBUG_STDOUT);

    if (__DEBUG_LEVEL > 0 && !DEBUG_PATH.empty()) {
        __DebugFile = new std::ofstream;
        __DebugFile->rdbuf()->pubsetbuf(0, 0);
        __DebugFile->open(DEBUG_PATH.c_str(), std::ofstream::app);
        if (!__DebugFile->is_open()) {
            std::cerr << "Error opening File " << DEBUG_PATH << " for writting";
            return false;
        }
    }
    return true;
}

void DebugClose()
{
    if (__DebugFile)
        __DebugFile->close();
    delete __DebugFile;
}
