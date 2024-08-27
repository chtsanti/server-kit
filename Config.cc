#include "Config.h"
#include "Debug.h"
#include "mem.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>

#include <cerrno>
#include <cstring>
#include <netinet/in.h>

bool DAEMON = false;
std::string PID_FILE = "/var/run/re-encryptor.pid";
std::string CTL_FILE = "/var/run/re-encryptor.ctl";
std::string RUN_USER;
std::string RUN_GROUP;
int WORKERS = 0;
std::string SessionLogPath;
std::string SessionLogFmt;
std::string AccessLogPath;
std::string AccessLogFmt;
bool TLS_NEGOTIATE_SHUTDOWN = true;
bool BoringSSLMemPools = true;
bool EventLibMemPools = true;

std::string DBHost = "127.0.0.1";
std::string DBpw;
int DBPort = 6379;
std::string DBName;

std::string TlsSignCertPath("/etc/re-encryptor/cert.pem");
std::string TlsSignKeyPath("/etc/re-encryptor/key.pem");

//DnsResolver
// int DnsResolverThreads; //Declared in DnsResolver.cc

template<> bool CfgParameterT<int>::set(const std::vector<std::string> &args)
{
    char *end = nullptr;
    errno = 0;
    int val = strtoll(args[0].c_str(), &end, 10);
    if ((val == 0 && errno != 0))
        return false;
    *parameter = val;
    return true;
}

template<> bool CfgParameterT<bool>::set(const std::vector<std::string> &args)
{
    if (strcasecmp(args[0].c_str(), "on") == 0)
        *parameter = true;
    else if (strcasecmp(args[0].c_str(), "off") == 0)
        *parameter = false;
    else
        return false;
    return true;
}

template<> bool CfgParameterT<std::string>::set(const std::vector<std::string> &args)
{
    *parameter = args[0];
    return true;
 }

std::vector<struct sockaddr_storage> *host_get_address(const char *servername);
template <> bool CfgParameterT<std::vector<struct sockaddr_storage> >::set(const std::vector<std::string> &args)
{
    assert(parameter);
    for (auto name: args) {
        if (std::vector<struct sockaddr_storage> *addrs = host_get_address(name.c_str())) {
            parameter->insert(parameter->end(), addrs->begin(), addrs->end());
            delete addrs;
        } else {
            // A message?
            return false;
        }
    }
    return true;
}

extern std::vector<struct sockaddr_storage> TcpOutgoingAddresses;

#define parameter(type, label, variable)     new CfgParameterT<type>(label, variable)
std::vector<CfgParameter *> ConfTable =
{
    parameter(int, "Port", PORT),
    parameter(int, "Workers", WORKERS),
    parameter(std::string, "PidFile", PID_FILE),
    parameter(std::string, "CommandsSocket", CTL_FILE),
    parameter(std::string, "User", RUN_USER),
    parameter(std::string, "Group", RUN_GROUP),
    parameter(std::string, "User", RUN_USER),
    parameter(std::string, "ServerLog", DEBUG_PATH),
    parameter(int, "DebugLevel", __DEBUG_LEVEL),
    parameter(std::string, "SessionLog", SessionLogPath),
    parameter(std::string, "SessionLogFormat", SessionLogFmt),
    parameter(std::string, "AccessLog", AccessLogPath),
    parameter(std::string, "AccessLogFormat", AccessLogFmt),
    parameter(std::string, "Cert", ServerTlsCertPath),
    parameter(std::string, "PKey", ServerTlsKeyPath),
    parameter(std::string, "SignCert", TlsSignCertPath),
    parameter(std::string, "SignKey", TlsSignKeyPath),
    parameter(int, "ReadTimeout", READ_TIMEOUT),
    parameter(int, "WriteTimeout", WRITE_TIMEOUT),
    parameter(int, "ConnectTimeout", CONNECT_TIMEOUT),
    parameter(int, "KeepAliveTimeout", KEEPALIVE_TIMEOUT),
    parameter(bool, "TlsNegotiatedShutdown", TLS_NEGOTIATE_SHUTDOWN),// Not implemented
    parameter(bool, "EventLibMemPools", EventLibMemPools),
    parameter(bool, "ZeroMemBeforeRelease", ZeroMemBeforeRelease),
    parameter(bool,"CheckDuplicateFrees", CheckDuplicateFrees),
    parameter(std::vector<struct sockaddr_storage>, "TcpOutgoingAddress", TcpOutgoingAddresses),
    //
    parameter(std::string, "DBHost", DBHost),
    parameter(std::string, "DBPassword", DBpw),
    parameter(int, "DBPort", DBPort),
    parameter(std::string, "DBName", DBName),
    //
    parameter(int, "DnsResolverThreads.Threads", DnsResolverThreads),
    parameter(int, "DnsResolver.Threads", DnsResolverThreads),
    parameter(int , "DnsResolver.CacheTTL", DnsResolverCacheTTL),
    //
};

std::unique_ptr<std::vector<std::unique_ptr<CfgParameter> > > __ConfTableDeletor = [] {
    std::unique_ptr<std::vector<std::unique_ptr<CfgParameter>>> ret(new std::vector<std::unique_ptr<CfgParameter>>);
    for (std::vector<CfgParameter *>::iterator p = ConfTable.begin(); p != ConfTable.end(); ++p)
        ret->push_back(std::unique_ptr<CfgParameter>(*p));
    return ret;
}();

void read_param(const std::string &s, char delim, std::string &param, std::vector<std::string> &args)
{
    std::istringstream iss(s);
    std::string item;
    args.clear();
    std::getline(iss, param, delim);
    if (param.empty())
        return;
    while (std::getline(iss, item, delim)) {
        args.push_back(item);
    }
}

void trim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
}

void trim_config_line(std::string &s)
{
    size_t c = s.find('#');
    if (c != std::string::npos)
        s.erase(c, std::string::npos);
    trim(s);
}

bool loadConfiguration(const std::string &configFile)
{
    std::ifstream *file = new std::ifstream(configFile.c_str());
    std::string line;
    while(!file->eof()) {
        line.clear();
        std::getline(*file, line);
        trim_config_line(line);
        if (!line.empty()) {
            std::string param;
            std::vector<std::string> args;
            read_param(line, ' ', param, args);
            if (!param.empty()) {
                for(auto &cfg: ConfTable) {
                    if (strcasecmp(cfg->directive, param.c_str()) == 0) {
                        cfg->set(args);
                    }
                }
            }
        }
    }
    delete file;
    return true;
}
