#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <fcntl.h>

#include <cstring>
#include "EventLoop.h"

void run_as_daemon()
{
    int fd;
    int pid, sid;
    pid = fork();
    if (pid < 0) {
        FAIL("Unable to fork. exiting...");
        exit(-1);
    }
    if (pid > 0)
        exit(0);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        FAIL("Unable to create a new SID for the main process. exiting...");
        exit(-1);
    }
    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        FAIL("Unable to change the working directory. exiting...");
        exit(-1);
    }

    /* Direct standard file descriptors to "/dev/null"*/
    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        FAIL("Unable to open '/dev/null'. exiting...");
        exit(-1);
    }

    if (dup2(fd, STDIN_FILENO) < 0) {
        FAIL("Unable to set stdin to '/dev/null'. exiting...");
        exit(-1);
    }

    if (dup2(fd, STDOUT_FILENO) < 0) {
        FAIL("Unable to set stdout to '/dev/null'. exiting...");
        exit(-1);
    }

    if (dup2(fd, STDERR_FILENO) < 0) {
        FAIL("Unable to set stderr to '/dev/null'. exiting...");
        exit(-1);
    }
    close(fd);
}

int store_pid(const char *pidfile)
{
    int fd;
    pid_t pid;
    char strPid[30];           /*30 must be enough for storing pids on a string */
    pid = getpid();

    if ((fd = open(pidfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) < 0) {
        FAIL("Cannot open the pid file: " << pidfile);
        return 0;
    }
    snprintf(strPid, sizeof(strPid), "%d", pid);
    size_t bytes = write(fd, strPid, strlen(strPid));
    if (bytes != strlen(strPid)) {
        FAIL("Cannot write to the pid file: " << pidfile);
    }
    close(fd);
    return 1;
}

int clear_pid(const char *pidfile)
{
    if (0 != remove(pidfile)) {
        FAIL("Cannot delete the pid file: " << pidfile << " Error: " << errno);
        return 0;
    }
    return 1;
}

int is_myself_running(const char *pidfile)
{
    int fd, ret;
    pid_t pid;
    char strPid[30];           /*30 must be enough for storing pids on a string */
    if ((fd = open(pidfile, O_RDONLY, 0644)) < 0) {
        return 0;
    }
    size_t bytes = read(fd, strPid, sizeof(strPid));
    close(fd);

    if (bytes < 0)
        return 0;

    if (bytes < sizeof(strPid) - 1)
        strPid[bytes] = '\0';
    else
        strPid[sizeof(strPid) - 1] = '\0';    /*Maybe check for errors? */
    pid = strtol(strPid, NULL, 10);
    if (pid <= 0)               /*garbage */
        return 0;
    ret = kill(pid, 0);
    if (ret < 0)
        return 0;

    return 1;
}

int set_running_permissions(const char *user, const char *group)
{
    unsigned int uid, gid;
    char *pend;
    struct passwd *pwd;
    struct group *grp;

    if (group && *group) {               /*Configuration request to change ours group id */
        errno = 0;
        gid = strtol(group, &pend, 10);
        if (*pend != '\0' || gid < 0 || errno != 0) {  /*string "group" does not contains a clear number */
            if ((grp = getgrnam(group)) == NULL) {
                FAIL("There is no group" << group << " in password file!");
                return 0;
            }
            gid = grp->gr_gid;
        } else if (getgrgid(gid) == NULL) {
            FAIL("There is no group with id=" << gid << " in password file!");
            return 0;
        }
//#if HAVE_SETGROUPS
        if (setgroups(1, &gid) != 0) {
            FAIL( "setggroups to " << gid << " failed!!!!");
            perror("setgroups failure");
            return 0;
        }
//#endif

        if (setgid(gid) != 0) {
            FAIL( "setgid to " << gid << " failed!!!!");
            perror("setgid failure");
            return 0;
        }
    }

    if (user && *user) {                /*Gonfiguration request to change ours user id */
        errno = 0;
        uid = strtol(user, &pend, 10);
        if (*pend != '\0' || uid < 0 || errno != 0) {  /*string "user" does not contain a clear number */
            if ((pwd = getpwnam(user)) == NULL) {
                FAIL("There is no user " << user << " in password file!");
                return 0;
            }
            uid = pwd->pw_uid;
        } else if (getpwuid(uid) == NULL) {
            FAIL("There is no user with id=" << uid << " in password file!");
            return 0;
        }

        if (setuid(uid) != 0) {
            FAIL( "setuid to " << uid << " failed!!!!\n");
            return 0;
        }
    }
    return 1;
}
