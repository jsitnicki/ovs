#!/usr/bin/env python

import fcntl
import os
import sys


pidfile_dev = None
pidfile_ino = None


def fatal(msg):
    sys.stderr.write("%s\n" % msg)
    sys.exit(1)


def make_pidfile(pidfile):
    pid = os.getpid()

    tmpfile = "%s.tmp%d" % (pidfile, pid)
    try:
        global fh

        fh = open(tmpfile, "w")
    except IOError as e:
        fatal("%s: create failed (%s)" % (tmpfile, e.strerror))

    try:
        s = os.fstat(fh.fileno())
    except IOError as e:
        fatal("%s: fstat failed (%s)" % (tmpfile, e.strerror))

    try:
        fh.write("%s\n" % pid)
        fh.flush()
    except OSError as e:
        fatal("%s: write failed (%s)" % (tmpfile, e.strerror))

    try:
        fcntl.lockf(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError as e:
        fatal("%s: lockf failed (%s)" % (tmpfile, e.strerror))

    try:
        os.link(tmpfile, pidfile)
    except OSError as e:
        fatal("%s: link to \"%s\" failed (%s)" % (tmpfile, pidfile, e.strerror))

    try:
        os.unlink(tmpfile)
    except OSError as e:
        fatal("%s: unlink failed (%s)" % (tmpfile, e.strerror))

    global pidfile_dev
    global pidfile_ino

    pidfile_dev, pidfile_ino = s.st_dev, s.st_ino


def delete_pidfile(pidfile):
    try:
        os.unlink(pidfile)
    except IOError as e:
        fatal("%s: failed to delete pidfile (%s)" % (pidfile, e.strerror))


def main():
    if len(sys.argv) != 2:
        fatal("Usage: %s <pid file>" % sys.argv[0])

    pidfile = sys.argv[1]
    make_pidfile(pidfile)

    try:
        raw_input("Press enter to exit...")
    except EOFError as e:
        pass

    delete_pidfile(pidfile)

    sys.exit(0)


if __name__ == "__main__":
    main()
