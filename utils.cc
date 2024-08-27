#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <cstdio>
#include <cassert>
#include <climits>

#include "utils.h"


thread_local char strerror_buf[256];
const char *print_errno(int errcode)
{
    strerror_buf[0] = '\0';
#if (_POSIX_C_SOURCE >= 200112L) && !  _GNU_SOURCE
    if (strerror_r(errcode,  strerror_buf, sizeof(strerror_buf)) != 0)
        snprintf(strerror_buf, sizeof(strerror_buf), "unknown errcode: %d", errcode);
    return strerror_buf;
#else
    return strerror_r(errcode,  strerror_buf, sizeof(strerror_buf));
#endif
}

thread_local char straddr_buf[256];
const char *print_sockaddr_storage(const struct sockaddr_storage *addr)
{
    if (!addr->ss_family)
        return "none";

    if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6)
        return "unknown-address-family";

    const void *sa = addr->ss_family == AF_INET ? static_cast<const void *>(&((struct sockaddr_in *)addr)->sin_addr) : static_cast<const void *>(&((struct sockaddr_in6 *)addr)->sin6_addr);
    return inet_ntop(addr->ss_family, sa, straddr_buf, sizeof(straddr_buf));
}

static const char *days[] = {
    "Sun",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat"
};

static const char *months[] = {
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
};

void to_strntime_rfc822(char *buf, size_t size, const time_t *tm)
{
    assert(size > 0);
    struct tm br_tm;
    gmtime_r(tm, &br_tm);
    snprintf(buf, size, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT",
             days[br_tm.tm_wday],
             br_tm.tm_mday,
             months[br_tm.tm_mon],
             br_tm.tm_year + 1900, br_tm.tm_hour, br_tm.tm_min, br_tm.tm_sec);
}

void strntime_rfc822(char *buf, size_t size)
{
    time_t tm;
    time(&tm);
    to_strntime_rfc822(buf, size, &tm);
}

bool parse_remote_tcp_port(const std::string &url, std::string &remoteServer, int &remoteServerPort, const int defaultPortIfNone)
{
    size_t sep = url.find(':');
    if (sep == std::string::npos) {
        remoteServer = url;
        remoteServerPort = defaultPortIfNone;
        return true;
    }
    remoteServer.assign(url, 0, sep);
    remoteServerPort = atoi(url.c_str() + sep + 1);
    return (remoteServerPort != 0);
}

static const char *atol_err_erange = "ERANGE";
static const char *atol_err_conversion = "CONVERSION_ERROR";
static const char *atol_err_nonumber = "NO_DIGITS_ERROR";
long int _atol_ext(const char *str, const char **error)
{
    char *e;
    long int val;
    int base = 10;
    errno = 0;
    if (str[0] == '0' && str[1] == 'x') {
        str +=2;
        base = 16;
    }
    val = strtol(str, &e, base);
    if (error) {
        *error = NULL;
        if (errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
            *error = atol_err_erange;
        else if (errno != 0 && val == 0)
            *error = atol_err_conversion;
        else if (e == str)
            *error = atol_err_nonumber;

        if (*error)
            return 0;
    }
    return val;
}
