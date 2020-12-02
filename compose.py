#! /usr/bin/python

from __future__ import print_function

import os
import sys
import json
import time
import urllib
import spkg

class Module(object):
    __slots__ = ['name', 'fullname',
                 'stream', 'version', 'context']

    def __eq__(self, other):
        return self.fullname == other.fullname

    def __gt__(self, o):
        if self.name > o.name:
            return True
        if self.name != o.name:
            return False

        if self.stream > o.stream:
            return True
        if self.stream != o.stream:
            return False

        if self.version > o.version:
            return True
        if self.version != o.version:
            return False

        if self.context > o.context:
            return True

        return False

    def __lt__(self, o):
        if self.name < o.name:
            return True
        if self.name != o.name:
            return False

        if self.stream < o.stream:
            return True
        if self.stream != o.stream:
            return False

        if self.version < o.version:
            return True
        if self.version != o.version:
            return False

        if self.context < o.context:
            return True

        return False

    def __ge__(self, o):
        return not self.__lt__(o)
    def __le__(self, o):
        return not self.__gt__(o)

    def nsvc(self):
        return '%s-%s-%s' % (self.name, self.stream, self.vc())
    def vc(self):
        return '%s.%s' % (self.version, self.context)


def packages_from_compose(rjson):
    srpms = []

    for variant in rjson['payload']['rpms'].keys():
        for arch in rjson['payload']['rpms'][variant].keys():
            srpms.extend(rjson['payload']['rpms'][variant][arch].keys())

    packages = []
    for srpm in set(srpms):
        if 'module+' in srpm:
            continue
        p = spkg.nevra2pkg(srpm)
        packages.append(p)

    return packages

def packages_bin_from_compose(rjson):
    rpms = []

    for variant in rjson['payload']['rpms'].keys():
        for arch in rjson['payload']['rpms'][variant].keys():
            for srpm in rjson['payload']['rpms'][variant][arch].keys():
                if 'module+' in srpm:
                    continue
                rpms.extend(rjson['payload']['rpms'][variant][arch][srpm].keys())

    packages = []
    for rpm in set(rpms):
        p = spkg.nevra2pkg(rpm)
        packages.append(p)

    return packages


def modules_from_compose(rjson):
    modules = []
    module_nsvcs = []

    for variant in rjson['payload']['modules'].keys():
        for arch in rjson['payload']['modules'][variant].keys():
            module_nsvcs.extend(rjson['payload']['modules'][variant][arch].keys())

    for mns in module_nsvcs:
        module = Module()
        module.fullname = mns
        n, s, v, c = module.fullname.split(':')
        module.name = n
        module.stream = s
        module.version = v
        module.context = c
        modules.append(module)

    return modules

def _data_url(url):
    try:
        if hasattr(urllib, "urlopen"):
            response = urllib.urlopen(url)
        else: # python3 imcompatibile
            import urllib.request as u2
            response = u2.urlopen(url)
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

#  We get a lot of duplicate modules in the data, because we do per. arch,
# so sort and remove.
def dedup_modules(m):
    nm = []
    last = None
    for module in sorted(m):
        if last is not None:
            if last == module:
                continue
        last = module
        nm.append(module)
    return nm

class Compose(object):
    # Eg. http://download.eng.bos.redhat.com/composes/nightly-rhel-8/RHEL-8/latest-RHEL-8/
    # https://kojipkgs.fedoraproject.org/compose/rawhide/latest-Fedora-Rawhide/
    def __init__(self, baseurl):
        self.baseurl = baseurl

    def data_id(self):
        cid   = _data_url(self.baseurl + "/COMPOSE_ID")
        return cid

    def data_status(self):
        cstat = _data_url(self.baseurl + "/STATUS")
        return cstat

    def json_rpms(self):
        pdata = _json_url(self.baseurl + "/compose/metadata/rpms.json")
        return pdata

    def json_modules(self):
        mdata = _json_url(self.baseurl + "/compose/metadata/modules.json")
        return mdata

def main():
    compose = Compose(sys.argv[1])

    cid = compose.data_id()
    print('Found Compose:', cid)

    cstat = compose.data_status()
    print(' Status:', cstat)

    pdata = compose.json_rpms()
    p = packages_from_compose(pdata)
    print(' Packages:', len(p))
    for pkg in sorted(p):
        print("    {}".format(pkg.ui_nevr()))

    mdata = compose.json_modules()
    m = modules_from_compose(mdata)
    m = dedup_modules(m)
    print(' Modules:', len(m))
    done = False
    for module in sorted(m):
        print("    {}-{}-{}-{}".format(module.name, module.stream, module.version, module.context))
        if not done:
            done = True
            try:
                import sync
            except:
                sync = None
        if sync is not None:
            build = sync.composed_modules2tagged_builds([module])[0]
            module_id, tag, module_spec_in_json = sync.modbuild2mbsjson(build)
            if len(module_spec_in_json['items']) < 1:
                print("** No items:", module_id)
                continue
            rpms = module_spec_in_json['items'][0]['tasks'].get('rpms', [])
            for name in sorted(rpms):
                print("        {} {}".format(name, tag))


if __name__ == '__main__':
    main()
