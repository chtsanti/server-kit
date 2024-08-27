#include "AccessLog.h"
#include "Debug.h"
#include "EventLoop.h"
#include "mem.h"

#include <ctime>
#include <sstream>
#include <atomic>

std::vector<Log::LogFile> Log::LogFiles;
bool Log::AddLogFile(std::string &logpath, std::string &fmt)
{
    if (logpath.empty())
        return false; // nothing to do
    FILE *fout = fopen(logpath.c_str(), "a+");
    if (fout)
        setvbuf(fout, NULL, _IONBF, 0);

    LogFile f = {logpath, fout, fmt};
    LogFiles.push_back(f);
    return true;
}

void Log::CloseLogFiles(std::vector<Log::LogFile> &logFiles)
{
    for (auto &f: logFiles) {
        assert(f.file);
        fclose(f.file);
        f.file = nullptr;
    }
}
