#ifndef __UTILS_H
#define __UTILS_H

#include <string>

const char *print_errno(int errcode);
struct sockaddr_storage;
const char *print_sockaddr_storage(const struct sockaddr_storage *addr);

#define CLOCK_TIME_DIFF(tsstop, tsstart) ((tsstop.tv_sec - tsstart.tv_sec) * 1000) + ((tsstop.tv_nsec - tsstart.tv_nsec + 500000) / 1000000)

void to_strntime_rfc822(char *buf, size_t size, const time_t *tm);
void strntime_rfc822(char *buf, size_t size);

bool parse_remote_tcp_port(const std::string &url, std::string &host, int &port, const int defaultPortIfNone);

long int _atol_ext(const char *str, const char **error);

#endif
