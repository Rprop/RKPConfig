#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <syscall.h>
#include <stdio.h> // NOLINT(*-deprecated-headers)

int main(const int argc, char **args) {
    int fd = syscall(__NR_openat, AT_FDCWD, "/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0) {
        syscall(__NR_setns, fd, CLONE_NEWNS);
        syscall(__NR_close, fd);
    }
    if (argc < 2 || argc >= 127) {
        fprintf(stderr, "%s failed\n", "arg");
        return -2;
    }
    char *argv[128] = {};
    for (int index = 1; index < argc; ++index) {
        argv[index - 1] = args[index];
    }
    syscall(__NR_execve, args[1], argv, environ);
    fprintf(stderr, "%s failed\n", "execve");
    return -1;
}
