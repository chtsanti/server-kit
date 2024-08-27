#ifndef __DEBUG_H
#define __DEBUG_H

#include <fstream>
#include <sstream>

extern int __DEBUG_LEVEL;
extern int __DEBUG_STDOUT;
extern int __DEBUG_MAX_LEVEL;
extern int MyPid;
extern std::ofstream *__DebugFile;
#define DEBUG(i, msg) {if ( i <= __DEBUG_MAX_LEVEL) {std::ostringstream oss; oss << CurrentTime() << " " << MyPid << " " << __FILE__ << ":" << __func__ << ":" << msg << "\n"; if (i <= __DEBUG_STDOUT) std::cerr << oss.str() << std::flush; if (i <= __DEBUG_LEVEL && __DebugFile) (*__DebugFile) << oss.str() << std::flush; }}

#define FAIL(msg) DEBUG(0, msg)
bool DebugInit();
void DebugClose();

#endif
