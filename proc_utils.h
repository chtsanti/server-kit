#ifndef __PROC_UTILS_H
#define __PROC_UTILS_H

void run_as_daemon();
int store_pid(const char *pidfile);
int clear_pid(const char *pidfile);
int is_myself_running(const char *pidfile);
int set_running_permissions(const char *user, const char *group);

#endif
