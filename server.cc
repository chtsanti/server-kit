#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <poll.h>

#include <iostream>
#include <fstream>
#include <list>
#include <map>
#include <atomic>

#include "Config.h"
#include "EventLoop.h"
#include "openssl/TLSutils.h"
#include "ConnectionOpener.h"
#include "AccessLog.h"
#include "proc_utils.h"
#include "mem.h"

// static bool SHUTDOWN = false; // Declared in EventLoop

int MyPid = -1;
struct Worker{
    pid_t pid = -1;
    int pipefd = -1;
};

ci_buffers_histo *tls_memory_histo = nullptr;
ci_buffers_histo *event_memory_histo = nullptr;

#if 0
static void sighup_handler_main()
{
}
#endif

static void term_handler_monitor(int signal)
{
    SHUTDOWN = true;
}

void implement_signals()
{
    signal(SIGPIPE, SIG_IGN);
//    signal(SIGINT, SIG_IGN);
//    signal(SIGTERM, term_handler_child);
    signal(SIGHUP, SIG_IGN);
}

void implement_monitor_signals()
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, term_handler_monitor);
    signal(SIGTERM, term_handler_monitor);
}


bool pwload(const char *file)
{
  std::ifstream pwfile(file);
  if (pwfile && std::getline(pwfile, DBpw))
    return true;
  return false;
}

int ci_named_pipe_create(const char *name)
{
    int status, pipe;
    errno = 0;
    status = mkfifo(name, S_IRUSR | S_IWUSR | S_IWGRP);
    if (status < 0 && errno != EEXIST)
        return -1;
    pipe = open(name, O_RDWR | O_NONBLOCK);
    return pipe;
}

int ci_named_pipe_open(const char *name)
{
    int pipe;
    pipe = open(name, O_RDWR | O_NONBLOCK);
    return pipe;
}

void ci_named_pipe_close(int pipe_fd)
{
    close(pipe_fd);
}

int MonitorWaitForCommands(int ctl_fd, char *buf, size_t bufSize, int secs)
{
    int ret = 0;
    struct pollfd pfds[1];
    memset(buf, 0, bufSize);
    int msecs = secs > 0 ? secs * 1000 : -1;
    pfds[0].fd = ctl_fd;
    pfds[0].events = POLLIN;
    if ((ret = poll(pfds, 1, msecs)) > 0) {
        if (pfds[0].revents & (POLLERR | POLLNVAL))
            ret = -1;
    }

    if (ret <= 0)
        return ret;

    int bytes = 0;
    do {
        bytes = read(ctl_fd, buf, bufSize - 1);
    } while (bytes == -1 && errno == EINTR);

    if (bytes < 0 && errno == EAGAIN) {
        return 0; // command read expired
    }

    if (bytes > 0) {
        assert(bytes < (int)bufSize);
        buf[bytes] = '\0';
        return bytes;
    }

    return -1; // else an error;
}

void test_command(const char *cmd, void *data)
{
    DEBUG(0, "test_command: \"" << cmd << "\", data pointer: [" << data << "]");
}

void mem_stats_command(const char *cmd, void *data)
{
//    DEBUG(1, "Sessions: " << SessionLog::SessionsCounter.load() << ", HttpRequests: " << Http1Proxy::ReqCounter.load());
    ci_buffer_dump_stats();
    ci_object_pools_dump_stats();
}

void buffers_user_stats_command(const char *cmd, void *data)
{
    if  (tls_memory_histo)
        tls_memory_histo->dump();
    if (event_memory_histo)
        event_memory_histo->dump();
    DEBUG(1, "IO_BUFFER/ci_buffers " << IOBUFFER_ALLOCATE_SIZE << " allocs/frees:" << IOBUFFER_allocs << "/" << IOBUFFER_frees);
}

void dns_stats_command(const char *cmd, void *data)
{
    DnsResolver::DumpDebugInfo();
}

typedef void CMD_FUNC(const char *cmd, void *data);
struct Cmd {
    CMD_FUNC *monitor_handler = nullptr;
    CMD_FUNC *kid_handler = nullptr;
};
std::map<std::string, Cmd> RegisteredCommands = {
    {"test", {test_command, test_command}},
    {"mem_stats", {nullptr, mem_stats_command}},
    {"buffers_user_stats", {nullptr, buffers_user_stats_command}},
    {"dns_stats", {nullptr, dns_stats_command}},
};

void MonitorHandleCommand(const char *command, const std::list<Worker> &workers)
{
    auto cmd = RegisteredCommands.find(command);
    if (cmd == RegisteredCommands.end()) {
        DEBUG(1, "Monitor process received an unknown command: " << command);
        return;
    }
    if (cmd->second.monitor_handler)
        cmd->second.monitor_handler(command, nullptr);
    if (cmd->second.kid_handler) {
        for (auto pi = workers.begin(); pi != workers.end(); ++pi) {
            if (pi->pipefd > 0) {
                int bytes = write(pi->pipefd, command, strlen(command));
                assert(bytes == (int)strlen(command));
            }
        }
    }
}

void kid_handle_command_event(evutil_socket_t eFD, short event, void *arg)
{
    char buf[1024];
    ssize_t ret = 0;
    do {
        errno = 0;
        ret = read(eFD, buf, sizeof(buf) - 1);
    } while(ret == -1 && errno == EINTR);
    if (ret > 0) {
        assert(ret < (ssize_t)sizeof(buf));
        buf[ret] = '\0';
        auto cmd = RegisteredCommands.find(buf);
        DEBUG(4, "Kid process received " << (cmd == RegisteredCommands.end() ? "an unknown " : "")  << "command: " << buf);
        if (cmd != RegisteredCommands.end() && cmd->second.kid_handler)
            cmd->second.kid_handler(buf, nullptr);
    }
}

void ListenForCommands_Worker(int fd)
{
    EventLoopRegisterPersistentFD(fd, kid_handle_command_event);
}

void runWorker(int commandsFd)
{
    MyPid = getpid();
    EventLoopInit();
    DnsResolver::Init();
    ListenForCommands_Worker(commandsFd);
    EventLoopRun();
    DEBUG(5, "Event Loop is finished, I am going down");
    DnsResolver::Shutdown();
    tlsDown();
//    SessionLog::CloseLogs();
    DebugClose();
}

int handleTerminatedWorkers(std::list<Worker> &running_workers)
{
    int status;
    pid_t pid;
    int num = 0;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        DEBUG(2, "Child " << pid << " died ...\n");
        if (!WIFEXITED(status)) {
            FAIL("Child " << pid << " did not exit normally");
//            exit_with_error = 1;
            if (WIFSIGNALED(status))
                FAIL("signaled with signal: " << WTERMSIG(status));
        }
        running_workers.remove_if([pid](Worker w) {return w.pid == pid;});
        num++;
    }
    if (pid < 0 && running_workers.size() > 0) {
        FAIL("Fatal error waiting for a child to exit .....");
    }
    return num;
}

void *tls_memory_alloc(size_t size)
{
    if (tls_memory_histo && size)
        tls_memory_histo->updateAlloc(size);
    return ci_buffer_alloc(size);
}

void tls_memory_free(void *ptr)
{
    if (!ptr) // Ignore nils
        return;
    if (ZeroMemBeforeRelease) {
        // The mem.cc subsystem will zero memory before store
        // no need to do it.
    } else if (size_t size = ci_buffer_size(ptr)) {
        memset(ptr, 0, size); // To avoid private info stay in ram
    }
    size_t memSize = 0;
    ci_buffer_free2(ptr, &memSize);
    if (tls_memory_histo)
        tls_memory_histo->updateFree(memSize);
}

size_t tls_memory_get_size(void *ptr)
{
    return ptr ? ci_buffer_size(ptr) : 0;
}

static void *event_memory_alloc(size_t sz)
{
    if (event_memory_histo)
        event_memory_histo->updateAlloc(sz);
    return ci_buffer_alloc(sz);
}

static void *event_memory_realloc(void *ptr, size_t sz)
{
    if (event_memory_histo) {
        size_t oldSize;
        void *newPtr = ci_buffer_realloc3(ptr, sz, &oldSize);
        if (newPtr != ptr) {
            if (oldSize)
                event_memory_histo->updateFree(oldSize);
            event_memory_histo->updateAlloc(sz);
        }
        return newPtr;
    } else
        return ci_buffer_realloc(ptr, sz);
}

static void event_memory_free(void *ptr)
{
    size_t memSize;
    ci_buffer_free2(ptr, &memSize);
    if (event_memory_histo)
        event_memory_histo->updateFree(memSize);
}

void MemoryPoolsInit()
{
    if (EventLibMemPools) {
        event_memory_histo = new  ci_buffers_histo("eventlib");
        event_set_mem_functions(event_memory_alloc, event_memory_realloc, event_memory_free);
    }

#if __BORINGSSL_TECHLOQ_EXTENSIONS>= 3
    if (BoringSSLMemPools) {
        tls_memory_histo = new  ci_buffers_histo("BoringSSL");
        BORINGSSL_set_mem_functions(
            tls_memory_alloc,
            tls_memory_free,
            tls_memory_get_size
            );
    }
#endif
}

static const char *MYNAME = "-";
void usage()
{
    std::cout << "Usage:\n";
    std::cout << "\t" << MYNAME << " [-h | --help] [-d stderr-debug-level][-D] [-f config-file] [-p listen-port] [-c certificate] [-k certificate-key] [--db-server server] [--db-port port] [--db-name db] [--db-pw-file path] [--db-pw pw] [--tls-ext-permute] [--no-ipv6] [--workers number]\n\n";
}

int main(int argc, char *argv[])
{
    std::string configFile;
    MYNAME = argv[0];
    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"db-server", required_argument, 0, 0},
        {"db-port", required_argument, 0, 1},
        {"db-name", required_argument, 0, 2},
        {"db-pw-file", required_argument, 0, 3},
        {"db-pw", required_argument, 0, 4},
        {"no-ipv6", no_argument, 0, 6},
        {"workers", required_argument, 0, 10},
        {0, 0, 0, 0}
    };
    while (1) {
        option_index = 0;
        opt = getopt_long(argc, argv, "hf:Dd:p:c:k:", long_options, &option_index);
        if (opt < 0)
            break;
        switch (opt) {
        case 0:
            DBHost = optarg;
            break;
        case 1:
            DBPort = strtol(optarg, NULL, 10);
            break;
        case 2:
            DBName = optarg;
            break;
        case 3:
            if (!pwload(optarg)) {
                std::cerr << MYNAME << ": can not load pw from file '" << optarg << "'\n";
                exit(-1);
            }
          break;
        case 4:
            DBpw = optarg;
            // change the argument to contain 'x..' value so the
            // password is not appeared in a `ps -ef` not in
            // '/proc/pid/cmdline' file
            for (char *sp = optarg; *sp !='\0'; ++sp) *sp = 'x';
            break;
        case 6:
            ConnectionOpener::NO_IPV6 = true;
            break;
        case 10:
            WORKERS = strtol(optarg, NULL, 10);
            if (WORKERS > 256 || WORKERS < 0)  {
                std::cerr << MYNAME << " wrong workers number: " << WORKERS;
                exit(-1);
            }
            break;
        case 47:
            // This is the maximum long option which can be used.
            break;
        case 'd':
            __DEBUG_STDOUT = strtol(optarg, NULL, 10);
            if (__DEBUG_STDOUT > 10 || __DEBUG_STDOUT <= 0) {
                std::cerr << MYNAME << " wrong debug level ('-d' option)\n";
                exit(-1);
            }
            break;
        case 'D':
            DAEMON = true;
            break;
        case 'f':
            configFile = optarg;
            if (!loadConfiguration(configFile)) {
                std::cerr << "Error loading configuration file, abort";
                exit(-1);
            }
            break;
        case 'p':
            PORT = strtol(optarg, NULL, 10);
            break;
        case 'c':
            ServerTlsCertPath = optarg;
            break;
        case 'k':
            ServerTlsKeyPath = optarg;
            break;
        case 'h':
            usage();
            exit(0);
        case '?':
            // wrong long option, an error message already printed
            break;
        default:
            std::cerr << MYNAME << ": wrong argument: " << (char)opt << "\n";
            usage();
            exit(-1);
        }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!DebugInit()) {
        return -1;
    }
    ci_mem_init();
    MemoryPoolsInit();
    if (ServerTlsCertPath.empty()) {
        ServerTlsCertPath = TlsSignCertPath;
        ServerTlsKeyPath = TlsSignKeyPath;
    }
    tlsInit();

    if (!AccessLogPath.empty()) {
        bool ret = Log::AddLogFile(AccessLogPath, AccessLogFmt);
        if (!ret)
            return -1;
    }

    if (!PID_FILE.empty() && is_myself_running(PID_FILE.c_str())) {
        FAIL( MYNAME << " already running!\n");
        exit(-1);
    }
    if (DAEMON)
        run_as_daemon();
    MyPid = getpid();
    if (!set_running_permissions(RUN_USER.c_str(), RUN_GROUP.c_str()))
        exit(-1);
    if (!PID_FILE.empty())
        store_pid(PID_FILE.c_str());

    int CtlFd = -1;
    if (!CTL_FILE.empty()) {
        CtlFd = ci_named_pipe_create(CTL_FILE.c_str());
    }

    std::list<Worker> workers;
    if (WORKERS <= 1) {
        implement_signals();
        runWorker(CtlFd);
    } else {
        implement_monitor_signals();
        // be a monitor process starting and handling kids
        do {
            // Start workers up to max-workers.
            for (int i = workers.size(); i < WORKERS; i++) {
                int pfd[2];
                if (pipe(pfd) < 0) {
                    FAIL(MYNAME << "Error creating pipe for communication with child. Will not fork");
                    continue;
                }
                if (fcntl(pfd[0], F_SETFL, O_NONBLOCK) < 0
                    || fcntl(pfd[1], F_SETFL, O_NONBLOCK) < 0) {
                    FAIL(MYNAME << "Error making the child pipe non-blocking. Will not fork");
                    close(pfd[0]);
                    close(pfd[1]);
                    continue;
                }
                pid_t pid = fork();
                if (pid  < 0) {
                    FAIL("Unable to fork a worker process!");
                } else if (pid == 0) {
                    close(pfd[1]);
                    implement_signals();
                    runWorker(pfd[0]);
                    ci_mem_exit();
                    exit(0);
                } else {
                    close(pfd[0]);
                    // I am the monitor process
                    workers.push_back({pid, pfd[1]});
                }
            }
            if (CtlFd > 0) {
                char cmd[512];
                int ret = MonitorWaitForCommands(CtlFd, cmd, sizeof(cmd), 1);
                if (ret < 0) {
                    close(CtlFd);
                    CtlFd = ci_named_pipe_open(CTL_FILE.c_str());
                    if (CtlFd < 0) {
                        FAIL( "Can not open " << CTL_FILE.c_str() << " socket, can not accept more control commands");
                    }
                }
                if (ret > 0)
                    MonitorHandleCommand(cmd, workers);
            } else {
                usleep(500000);
            }
            handleTerminatedWorkers(workers);
        } while (!SHUTDOWN);

        int tries = 0;
        do {
            for (auto pi = workers.begin(); pi != workers.end(); ++pi) {
                kill(pi->pid, SIGTERM);
            }
            usleep(1000000);
            handleTerminatedWorkers(workers);
            tries++;
        } while(!workers.empty() && tries < 10);
    }
    clear_pid(PID_FILE.c_str());
    ci_mem_exit();
    return 0;
}
