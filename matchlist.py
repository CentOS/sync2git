""" Simple match packages class. """

import fnmatch

def _read_lines(fname):
    """ Read the lines from a file, removeing extra whitespace and comments. """
    ret = []
    for line in open(fname):
        line = line.strip()
        if not line:
            continue
        if line.startswith('#'):
            continue

        ret.append(line)
    return ret

class Matchlist(object):
    def __init__(self):

        self._n = set()
        self._n_globs = set()

        self._nvr = set()
        self._nvr_globs = set()

        self._ver = set()
        self._ver_globs = set()
        self._rel = set()
        self._rel_globs = set()

        self.all = False

    def load(self, fname):
        for line in _read_lines(fname):

            d = self._n
            g = self._n_globs
            if False: pass
            elif line.startswith("nvr="):
                line = line[len("nvr="):].strip()
                d = self._nvr
                g = self._nvr_globs
            elif line.startswith("ver="):
                line = line[len("ver="):].strip()
                d = self._ver
                g = self._ver_globs
            elif line.startswith("rel="):
                line = line[len("rel="):].strip()
                d = self._rel
                g = self._rel_globs
            elif line.startswith("name="):
                line = line[len("name="):].strip()

            if '*' == line:
                self.all = True
            elif '*' not in line:
                d.add(line)
            else:
                g.add(line)

    def _match(self, data, direct, globs):
        if self.all:
            return True
        if data in direct:
            return True
        for glob in globs:
            if fnmatch.fnmatch(data, glob):
                return True
        return False

    def nvr(self, name, version, release):
        if self.name(name):
            return True
        if self.version(version):
            return True
        if self.release(release):
            return True
        return self._match("%s-%s-%s" % (name, version, release), 
                            self._nvr, self._nvr_globs)
    
    def name(self, name):
        return self._match(name, self._n, self._n_globs)
    def version(self, version):
        return self._match(version, self._ver, self._ver_globs)
    def release(self, release):
        return self._match(release, self._rel, self._rel_globs)
