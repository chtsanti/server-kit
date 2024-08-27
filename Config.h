#ifndef __CONFIG_H
#define __CONFIG_H

#include <string>
#include <vector>

class CfgParameter {
public:
    CfgParameter(const char *d): directive(d){}
    virtual bool set(const std::vector<std::string> &args) = 0;
    const char *directive;
};

template<class TYPE> class CfgParameterT: public CfgParameter {
public:
    CfgParameterT(const char *directive, TYPE &param, const char *shortMsg = nullptr):
        CfgParameter(directive),
        parameter(&param),
        msg(shortMsg) {}
    virtual bool set(const std::vector<std::string> &args) final {
        return false;
    }
private:
    TYPE *parameter;
    const char *msg;
};


extern int READ_TIMEOUT;
extern int WRITE_TIMEOUT;
extern int CONNECT_TIMEOUT;
extern int KEEPALIVE_TIMEOUT;
extern int PEEK_TIMEOUT; // Not implemented

extern bool DAEMON;
extern std::string PID_FILE;
extern std::string CTL_FILE;
extern std::string RUN_USER;
extern std::string RUN_GROUP;
extern int WORKERS;
// static bool SHUTDOWN = false; // Declared in EventLoop
extern int PORT;
extern std::string DEBUG_PATH;
extern std::string SessionLogPath;
extern std::string SessionLogFmt;
extern std::string AccessLogPath;
extern std::string AccessLogFmt;
extern int DnsResolverThreads;
extern int DnsResolverCacheTTL;
extern bool TLS_NEGOTIATE_SHUTDOWN;
extern bool EventLibMemPools;

extern std::string DBHost;
extern std::string DBpw;
extern int DBPort;
extern std::string DBName;
extern std::string TlsSignCertPath;
extern std::string TlsSignKeyPath;
//Tunneler:
extern std::string ServerTlsCertPath;
extern std::string ServerTlsKeyPath;

bool loadConfiguration(const std::string &configFile);

#endif
