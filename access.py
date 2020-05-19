#! /usr/bin/python

# Stupid python3
from __future__ import print_function

import calendar
import os
import subprocess
import sys
import time
import urllib

import json

burl="http://centos-cve-checker-centos-cve-checker.cloud.paas.psi.redhat.com/"

use_multithreading = False

sleep_beg = 0.1
sleep_end = 8
sleep_err = 20*60 # Kernel can take a _long_ time.

def _data_url(url):
    try:
        response = urllib.urlopen(url)
    except IOError: # Py2
        return ""
    except OSError: # Py3+
        return ""
    data = response.read()
    return data

def _json_url(url):
    data = _data_url(url)
    try:
        data = json.loads(data)
    except ValueError:
        return None
    return data

def _read_lines(fname):
    ret = []
    for line in open(fname):
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            continue

        ret.append(line)
    return ret

def seconds_to_ui_time(seconds):
    """Return a human-readable string representation of the length of
    a time interval given in seconds.

    :param seconds: the length of the time interval in seconds
    :return: a human-readable string representation of the length of
    the time interval
    """
    if seconds >= 60 * 60 * 24:
        return "%d day(s) %d:%02d:%02d" % (seconds / (60 * 60 * 24),
                                           (seconds / (60 * 60)) % 24,
                                           (seconds / 60) % 60,
                                           seconds % 60)
    if seconds >= 60 * 60:
        return "%d:%02d:%02d" % (seconds / (60 * 60), (seconds / 60) % 60,
                                 (seconds % 60))
    return "%02d:%02d" % ((seconds / 60), seconds % 60)

def log4id(checkid):
    url = burl + 'log/' + checkid
    data = _data_url(url)
    # This is direct opposite of app.py so no &amp; and it's not guaranteed
    # to be the original, but should be close.
    return data.replace("<br>", "\n").replace("&lt;", "<").replace("&gt;", ">")

def hist(name, version=None, release=None, done=False):
    full = False
    url = burl + 'history/' + name
    nvr = name
    if version is not None:
        url += '/' + version
        nvr += '-' + version
        if release is not None:
            url += '/' + release
            nvr += '-' + release
            full = True

    his_data = _json_url(url)
    if his_data is None:
        return None

    ret = []
    for req in his_data:
        if full and req['nvr'] != nvr:
            continue
        if not full and not req['nvr'].startswith(nvr):
            continue
        if not done and req['state'] != "done":
            continue
        ret.append(req)
    return ret

# Given a JSON time convert it to a real time.
# 2020-04-24 02:05:47
def tm(jstm):
    return calendar.timegm(time.strptime(jstm, '%Y-%m-%d %H:%M:%S'))


class NvrInfo:
    def __init__(self, n, v, r):
        self.name = n
        self.version = v
        self.release = r

        nvr = "%s-%s-%s" % (n, v, r)
        self.nvr = nvr

        self.req_done = False
        self.res_done = False
        self.res_allow = False

        self._his_data = None
        self._req_data = None
        self._res_data = None
        self._req_id = 0
        self._res_state = '?'

        self._sleep_init()

    # Note that this isn't rpmvercmp accurate ... meh.
    def __eq__(self, o):
        if self.nvr != o.nvr:
            return False
        if self._req_id != o._req_id:
            return False
        return True

    # Note that this isn't rpmvercmp accurate ... meh.
    def __gt__(self, o):
        if self.name > o.name:
            return True
        if self.name != o.name:
            return False

        if self.version > o.version:
            return True
        if self.version != o.version:
            return False

        if self.release > o.release:
            return True

        return False

    # Note that this isn't rpmvercmp accurate ... meh.
    def __lt__(self, o):
        if self.name < o.name:
            return True
        if self.name != o.name:
            return False

        if self.version < o.version:
            return True
        if self.version != o.version:
            return False

        if self.release < o.release:
            return True

        return False

    # Note that this isn't rpmvercmp accurate ... meh.
    def __ge__(self, o):
        return not self.__lt__(o)
    # Note that this isn't rpmvercmp accurate ... meh.
    def __le__(self, o):
        return not self.__gt__(o)

    def __str__(self):
        if not self.req_done:
            return self.nvr
        if not self.res_done:
            return "%s: (%d)=?" % (self.nvr, self._req_id)
        if self._res_state not in ('done', 'init', 'running'):
            return "%s: (%d)=!%s!" % (self.nvr, self._req_id, self._res_state)
        if self._res_state == 'running':
            return "%s: (%d)=running" % (self.nvr, self._req_id)
        return "%s: (%d)=%s" % (self.nvr, self._req_id, self.allow())

    def _sleep_init(self):
        self._sleep_beg = time.time()
        self._sleep_for = sleep_beg

    def _sleep(self, fail=True):
        if fail and (time.time() - self._sleep_beg) > sleep_err:
            return False
        time.sleep(self._sleep_for)
        if self._sleep_for < sleep_end:
            self._sleep_for *= 2
        return True

    def _sleep_reset(self):
        self._sleep_init()

    def hist_precache(self):
        if self._his_data is not None:
            return self._his_data

        data = hist(self.name, self.version, self.release, done=True)
        if data is None:
            self._res_state = 'Bad history response'
            return []
        if len(data) < 1:
            return []

        # Always use the most recent match, they are printed earliest first...
        req = data[0]
        if req['result'] != 'allow':
            return []

        # This is the optimization...
        self._res_state = 'done'
        self.req_done = True
        self.res_done = True
        self.res_allow = True

        self._his_data = data
        return data

    def req(self):
        if self.req_done:
            return
        self.req_done = True

        url = burl + 'check/' + self.nvr
        self._req_data = _json_url(url)
        if self._req_data is None:
            self.res_done = True
            self._res_data = {'state' : 'error', 'result' : 'deny'}
            self._res_state = 'Bad check response'
            return
        self._req_id = self._req_data['taskId']
        self._res_state = 'q'

    def done(self):
        if not self.req_done:
            self.req()
        if self.res_done:
            return True

        url = burl + 'info/' + str(self._req_id)
        self._res_data = _json_url(url)
        if self._res_data is None:
            self.res_done = True
            self._res_data = {'state' : 'error', 'result' : 'deny'}
            self._res_state = 'Bad info response'
            return
        # print("DBG:", self, '=', self._res_data)

        # The server states are: init, running, done, error
        self._res_state = self._res_data['state']
        self.res_done = self._res_state in ("done", "error")
        self.res_allow = self._res_data['result'] == "allow"

        return self.res_done

    def allow(self, fail=True):
        while not self.done():
            if self._sleep(fail):
                continue
            self.res_done = True
            self._res_state = 'Timeout'
            return False
        self._sleep_reset()
        return self.res_allow

def local_lookup(name):
    d = subprocess.check_output(["rpm", "--nodigest", "--nosignature", "--qf", "%{name}-%{version}-%{release}\n", "-q", name])
    if ' ' in d:
        print("Couldn't find local pkg:", name)
        return []
    reqs = []
    for line in d.split('\n'):
        if line == "": continue
        n, v, r = line.rsplit('-', 2)
        reqs.append(NvrInfo(n, v, r))
    return reqs

def maybe_local_lookup(arg):
    fail = False
    try:
        n, v, r = arg.rsplit('-', 2)
    except:
        fail = True
    if not fail:
        return [NvrInfo(n, v, r)]
    return local_lookup(arg)


def _usage(ec=1):
    print('access [-h] nvr|file-nvr|allow|history|log arg [args...]')
    print('       -h       Use history data')
    print('')
    print('       nvr      NVR|name [args...]')
    print('       file-nvr filename [args...]')
    print('       allow    NVR|name [args...]')
    print('       history  name[-version[-release]] [args...]')
    print('       log      ID [args...]')
    sys.exit(ec)

def main():
    reqs = []
    hist_opt = False

    if len(sys.argv) < 2:
        _usage()

    if sys.argv[1] == '-h': # Do history lookups...
        hist_opt = True
        sys.argv[1:] = sys.argv[2:]

    def noprnt(*args):
        pass
    def prnt(*args):
        done = False
        out = ""
        for arg in args:
            if done:
                out += " "
            done = True
            out += str(arg)
        print(out)

    if sys.argv[1] in ('allow', 'allow-nvrs', 'allow-nvr'):
        prnt = noprnt
    if sys.argv[1] in ('allow-file', 'allow-file-nvrs', 'allow-file-nvr'):
        prnt = noprnt

    if False: pass
    elif sys.argv[1] in ('logs', 'log'):
        for arg in sys.argv[2:]:
            print("=" * 78)
            print("Log:", arg)
            print("-" * 78)
            print(log4id(arg))
            print("-" * 78)
        sys.exit(0)
    elif sys.argv[1] in ('hist', 'history'):
        for arg in sys.argv[2:]:
            n, v, r = '', None, None
            if '-' in arg:
                n, arg = arg.rsplit('-', 1)
            else:
                n = arg
            if '-' in arg:
                v, r = arg.rsplit('-', 1)
            print("=" * 78)
            print("History:", arg, "(%s, %s, %s)" % (n, v, r))
            print("-" * 78)
            done = False
            for h in hist(n, v, r):
                if 'nvr' not in h:
                    continue # Report?
                if done:
                    print('')
                done = True
                i = "NVR"
                print("%s: %s" % (i, h[i.lower()]))
                # Skip safe_nvr
                for i in ("state", "result"):
                    print("  %-6s: %s" % (i, h.get(i, '')))

                if 'start' not in h:
                    continue
                i = "start"
                b = tm(h[i])
                sui = seconds_to_ui_time
                print("  %-6s: %s (%s ago)" % (i, h[i], sui(time.time() - b)))

                if 'end' not in h:
                    continue
                i = "end"
                e = tm(h[i])
                print("  %-6s: %s (%s taken)" % (i, h[i], sui(e - b)))
        sys.exit(0)
    elif sys.argv[1] in ('nvr', 'nvrs', 'allow', 'allow-nvrs', 'allow-nvr'):
        for arg in sys.argv[2:]:
            for req in maybe_local_lookup(arg):
                prnt("Adding:", req)
                reqs.append(req)
    elif sys.argv[1] in ('name', 'names'):
        for arg in sys.argv[2:]:
            for req in local_lookup(arg):
                print("Adding:", req)
                reqs.append(req)
    elif sys.argv[1] in ('file-nvr', 'file-nvrs', 'allow-file', 'allow-file-nvrs', 'allow-file-nvr'):
        for fname in sys.argv[2:]:
            for arg in _read_lines(fname):
                if arg.startswith('gpg-pubkey-'): # rpm -qa
                    continue
                for req in maybe_local_lookup(arg):
                    prnt("Adding:", req)
                    reqs.append(req)
    else:
        _usage()
        try:
            n, v, r = data.rsplit(2, '-')
        except:
            n = data

    if use_multithreading:
        from multiprocessing.dummy import Pool
        p = Pool(8)
        # Start the reqs...
        def _req(x):
            x.req()
            prnt(x)
            return str(x)
        p.map(_req, reqs)
        # Print the first result of reqs...
        prnt('---- try ----')
        def _res1(x):
            x.done()
            prnt(x)
        p.map(_res1, reqs)
        prnt('---- wait ----')
        def _res(x):
            val = x.allow()
            if not val:
                sys.exit(6)
            prnt(x)
        p.map(_res, reqs)
    else:
        if hist_opt:
            for req in sorted(reqs):
                prnt('Hist:', req, len(req.hist_precache()))
        # Print the first result of reqs...
        # Start the reqs...
        for req in reqs:
            prnt('Req:', req)
            req.req()
        # Print the first result of reqs...
        prnt('---- hope ----')
        for req in reqs:
            prnt('Ask:', req)
            if req.done():
                prnt('Res:', req)
        prnt('---- wait ----')
        for req in sorted(reqs):
            prnt('Ask:', req)
            val = req.allow()
            if sys.argv[1] in ('allow', 'allow-nvrs', 'allow-nvr', 'allow-file', 'allow-file-nvrs', 'allow-file-nvr'):
                if not val:
                    sys.exit(6)
            prnt('Res:', req)

if __name__ == '__main__':
    main()
