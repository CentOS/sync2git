#! /usr/bin/python

from __future__ import print_function

import os
import sys

import errno
import random
import time

# Cache for at least 6 hours...
conf_default_duration_min = 60 * 60 * 6

# Cache for at most 4 days...
conf_default_duration_max = 60 * 60 * 24 * 4

# Output for testing...
_conf_debug = False

_tm_d = {'d' : 60*60*24, 'h' : 60*60, 'm' : 60, 's' : 1,
         'w' : 60*60*24*7,
         'q' : 60*60*24*7*13}
def parse_time(seconds):
    if seconds is None:
        return None
    if seconds.isdigit():
        return int(seconds)

    parts = seconds.split(':')
    if len(parts) > 1: # Parse time like 1:10:4:3
        if False in [x.isdigit() for x in parts]:
            dbg("!digits", parts)
            return None
        parts = [int(x) for x in parts]
        ret = parts.pop()
        if parts:
            ret += _tm_d['m']*parts.pop()
        if parts:
            ret += _tm_d['h']*parts.pop()
        if parts:
            ret += _tm_d['d']*parts.pop()
        if parts:
            ret += _tm_d['w']*parts.pop()
        if parts:
            ret += _tm_d['q']*parts.pop()
        return ret

    ret = 0
    for mark in ('q', 'w', 'd', 'h', 'm', 's'):
        pos = seconds.find(mark)
        if pos == -1:
            continue
        val = seconds[:pos]
        seconds = seconds[pos+1:]
        if not val.isdigit():
            dbg("!isdigit", val)
            return None
        ret += _tm_d[mark]*int(val)
    if seconds.isdigit():
        ret += int(seconds)
    elif seconds != '':
        dbg("!empty", seconds)
        return None

    return ret

def _add_dur(dur, ret, nummod, suffix, static=False):
    mod = dur % nummod
    dur = dur // nummod
    if mod > 0 or (static and dur > 0):
        ret.append(suffix)
        if static and dur > 0:
            ret.append("%0*d" % (len(str(nummod)), mod))
        else:
            ret.append(str(mod))
    return dur

def format_duration(seconds, static=False):
    if seconds is None:
        seconds = 0
    dur = int(seconds)

    ret = []
    dur = _add_dur(dur, ret, 60, "s", static=static)
    dur = _add_dur(dur, ret, 60, "m", static=static)
    dur = _add_dur(dur, ret, 24, "h", static=static)
    dur = _add_dur(dur, ret,  7, "d", static=static)
    dur = _add_dur(dur, ret, 13, "w", static=static)
    if dur > 0:
        ret.append("q")
        ret.append(str(dur))
    return "".join(reversed(ret))

def format_time(seconds, use_hours=True):
    if seconds is None:
        seconds = 0
    if seconds is None or seconds < 0:
        if use_hours: return '--:--:--'
        else:         return '--:--'
    elif seconds == float('inf'):
        return 'Infinite'

    seconds = int(seconds)
    minutes = seconds // 60
    seconds = seconds % 60
    if not use_hours:
        return '%02i:%02i' % (minutes, seconds)

    hours = minutes // 60
    minutes = minutes % 60
    return '%02i:%02i:%02i' % (hours, minutes, seconds)

def unlink_f(filename):
    """ Call os.unlink, but don't die if the file isn't there. This is the main
        difference between "rm -f" and plain "rm". """
    try:
        os.unlink(filename)
        return True
    except OSError as e:
        if e.errno not in (errno.ENOENT, errno.EPERM, errno.EACCES,errno.EROFS):
            raise
    return False

def dbg(*data, **kwargs):
    if not _conf_debug:
        return

    print("DBG:", *data, **kwargs)

def fcached(fname, expire_min=None, expire_max=None):

    if expire_min is None:
        expire_min = conf_default_duration_min
    if expire_max is None:
        expire_max = conf_default_duration_max

    if expire_min > expire_max:
        dbg("BAD: expire_min > expire_max")
        return False

    if not os.path.exists(fname):
        dbg("!os.path.exists")
        return False

    # -1 is special and should never get refreshed
    if expire_max == -1:
        dbg("expire_max == -1")
        return True

    now = time.time()

    st = os.stat(fname)
    mtime = st[8]

    # WE ARE FROM THE FUTURE!!!!
    if mtime > now:
        dbg("mtime > now", mtime, now)
        return False

    if mtime + expire_max < now: # Max amount of time allowed so no cache.
        tm = format_duration(now - (mtime + expire_max))
        dbg("mtime + expire_max < now", "| for:", tm)
        return False

    if mtime + expire_min > now: # Not hit minimum, so always keep it.
        tm = format_duration((mtime + expire_min) - now)
        dbg("mtime + expire_min > now", "| for:", tm)
        return True

    if expire_min == expire_max: # All or nothing caching.
        dbg("expire_min == expire_max")
        return False

    #  Between min and max cache sizes, so we keep the cache with a probability
    # based on the difference. This means if you get 100 things at once then
    # they don't all expire at the same time.

    # Number of seconds between min and max...
    sec_range = expire_max - expire_min
    secs = now - mtime
    pc = float(secs) / sec_range
    rand = random.random()
    if _conf_debug:
        dbg("range:", format_duration(sec_range))
        dbg("  now:", format_duration(secs, static=True))
        dbg("percent chance:", pc)
        dbg("          rand:", rand)
        dbg("pc > rand:", pc > rand)
    if pc > rand:
        return False

    return True

def ftouch(fname, data=None, makedirs=True):
    try:
        if data is None:
            fo = open(fname, 'a') # w+ to trunc file as well...
        else:
            fo = open(fname, 'w+') # w+ to trunc file as well...
    except IOError:
        if not makedirs:
            raise
        os.makedirs(os.path.dirname(fname))
        return ftouch(fname, data=data, makedirs=False)
    if data is not None:
        fo.write(str(data))
    fo.close()

def userhomedir():
    home = os.getenv("HOME")
    if home is None:
        home = os.path.expanduser("~")
    return home

def usercachedir():
    if sys.platform == "darwin":
        home = userhomedir()
        d = "/Library/Caches/"
        return home + d

    # Who cares about Windows :)
    cd = os.getenv('XDG_CACHE_HOME')
    if cd is None:
        home = userhomedir()
        d = "/.cache/"
        return home + d
    return cd

def userappcachedir(app):
    cd = usercachedir()
    return cd + app + "/"

# This is problematic with recursive dirs ... eh.
def cache_dir(dname, min=None, max=None):
    for fname in os.listdir(dname):
        c = Cache(dname + '/' + fname, min, max)
        yield c

def clean_dir(dname, min=None, max=None):
    if not os.path.exists(dname):
        return

    for c in cache_dir(dname, min=min, max=max):
        c.cached()

class Cache(object):
    def __init__(self, path, min=None, max=None):
        self.path = path

        self._cached = None

        self._min = min
        self._max = max

    def __eq__(self, o):
        return self.path == o.path
    def __ge__(self, o):
        return self.path >= o.path
    def __gt__(self, o):
        return self.path > o.path
    def __le__(self, o):
        return self.path <= o.path
    def __lt__(self, o):
        return self.path < o.path

    def cached(self, autocleanup=True):
        """ Can we use the cached file. """
        if self._cached is None:
            self._cached = fcached(self.path, self._min, self._max)
            if not self._cached and autocleanup: # Assumes files...
                self.unlink()

        return self._cached

    def read(self):
        """ Read the contents. """
        return open(self.path).read()

    def unlink(self):
        """ Read the contents. """
        unlink_f(self.path)

    def touch(self, data=None):
        """ Touch the file, possibly with data. """
        ftouch(self.path, data=data)
        self._cached = None

def main():
    global _conf_debug
    from optparse import OptionParser

    parser = OptionParser()
    parser.usage = """\
%prog [options] <cmd> [arg]

Commands:
    help
    cached     <path>
    cached-dir <path>
    read       <path>
    touch      <path>
    write      data <path>

    dur        <secs>
    durs       <secs>
    secs       <time>
    time       <secs>

    userappcachedir"""

    parser.add_option("-a", "--autocleanup",
                      help="Automatically remove non-cache files", default=False, action="store_true")
    parser.add_option("", "--debug",
                      help="Debug output", default=_conf_debug, action="store_true")
    parser.add_option("", "--max",
                      help="Maximum seconds to cache for", default=None)
    parser.add_option("", "--min",
                      help="Minimum seconds to cache for", default=None)

    (options, args) = parser.parse_args()

    if options.debug:
        _conf_debug = True

    if len(args) < 1:
        parser.error("No command specified")

    options.min = parse_time(options.min)
    options.max = parse_time(options.max)

    cmd = args[0]

    if False: pass
    elif cmd == "help":
        parser.print_usage()
    elif cmd == "time":
        if len(args) < 2:
            parser.error("No time specified")
        print("time:", format_time(int(args[1])))
    elif cmd == "dur":
        if len(args) < 2:
            parser.error("No time specified")
        print("dur:", format_duration(int(args[1])))
    elif cmd == "durs":
        if len(args) < 2:
            parser.error("No time specified")
        print("dur:", format_duration(int(args[1]), static=True))
    elif cmd == "secs":
        if len(args) < 2:
            parser.error("No time specified")
        print("secs:", parse_time(args[1]))
    elif cmd == "userappcachedir":
        print("user:", userappcachedir("<app>"))
    elif cmd == "cached":
        if len(args) < 2:
            parser.error("No path specified")

        c = Cache(args[1], options.min, options.max)
        print("cached:", c.cached(options.autocleanup))
    elif cmd == "cached-dir":
        if len(args) < 2:
            parser.error("No path specified")

        for c in cache_dir(args[1], options.min, options.max):
            print("name:", os.path.basename(c.path))
            print("cached:", c.cached(options.autocleanup))
    elif cmd == "read":
        if len(args) < 2:
            parser.error("No path specified")

        c = Cache(args[1], options.min, options.max)
        print("cached:", c.cached(options.autocleanup))
        if c.cached():
            print("data:", c.read())
    elif cmd == "touch":
        if len(args) < 2:
            parser.error("No path specified")

        c = Cache(args[1], options.min, options.max)
        print("touch")
        c.touch()
        print("cached:", c.cached(autocleanup=False))
    elif cmd == "write":
        if len(args) < 3:
            parser.error("No data/path specified")

        c = Cache(args[2], options.min, options.max)
        print("touch")
        c.touch(args[1])
        print("cached:", c.cached(autocleanup=False))
        print("data:", c.read())
    else:
        parser.error("invalid command: " + cmd)


if __name__ == '__main__':
    main()
