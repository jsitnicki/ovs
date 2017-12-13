#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
fatal(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
    va_end(args);

    exit(EXIT_FAILURE);
}

static int
lock_pidfile(FILE *file, struct flock *lock)
{
    int err;

    lock->l_type = F_WRLCK;
    lock->l_whence = SEEK_SET;
    lock->l_start = 0;
    lock->l_len = 0;
    lock->l_pid = 0;

    do {
        err = fcntl(fileno(file), F_GETLK, lock) == -1 ? errno : 0;
    } while (err == EINTR);

    return err;
}

static pid_t
read_pidfile(const char *pidfile)
{
    struct flock lock = { 0 };
    FILE *file;
    int err;

    file = fopen(pidfile, "r+");
    if (!file)
        fatal("%s: open failed: %s", pidfile, strerror(errno));

    err = lock_pidfile(file, &lock);
    if (err)
        fatal("%s: lock failed: %s", pidfile, strerror(err));

    if (lock.l_type == F_UNLCK)
        fatal("%s: file is unlocked", pidfile);

    fclose(file);
    return lock.l_pid;
}

int
main(int argc, char **argv)
{
    const char *pidfile;
    pid_t pid;

    if (argc != 2)
        fatal("Usage: %s <pid file>", argv[0]);

    pidfile = argv[1];
    pid = read_pidfile(pidfile);

    printf("PID file locked by %ld\n", (long int) pid);

    exit(EXIT_SUCCESS);
}
