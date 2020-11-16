#! /usr/bin/python3

"""Sync modules/packages from a dist-git repository to a koji build system.
Eg. Build packages which are newer in git than in the tag/compose we are
looking at.
"""

from __future__ import print_function

import koji
import json
import sys
import os
import shutil
import tempfile
import spkg
from optparse import OptionParser

# Do we want to filter through the CVE checker
conf_filter_cve = True

# Do we want to check pushed modules for any rpms that need pushing
conf_check_extra_rpms = True

# Just do the downloads, and don't alt-src
conf_data_downloadonly = False

# Create temp. dirs. for alt-src.
conf_alt_src_tmp = True

# Cache looking up tags for builds.
conf_cache_builds = False

# This should never have CVEs and CVE checker hates it (timeout = fail).
auto_passcvelist_module_packages = ["module-build-macros"]

# Do we want to output old tags data, useful for debugging
__output_old_tags = False

# Do we want to output build data, useful for debugging
__output_build_lines = False

# Do we want to include all packages from a compose...
__auto_compose_allowlist = True

# Do we want to include all packages from a tag...
__auto_tag_allowlist = True

# Do we want to just test...
__test_print_tagged = False

if not __test_print_tagged:
    import git

if not hasattr(tempfile, 'TemporaryDirectory'):
    class TemporaryDirectory(object):
        """Do it using __del__ as a hack """

        def __init__(self, suffix='', prefix='tmp', dir=None):
            self.name = tempfile.mkdtemp(suffix, prefix, dir)

        def __del__(self):
            shutil.rmtree(self.name)
    tempfile.TemporaryDirectory = TemporaryDirectory

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

# This is mostly hacked from: koji_cli/commands.py buildinfo/rpminfo
def koji_nvr2srpm(session, nvr):
    """ Given an rpm nvr, convert it into an srpm nvr for CVE checker.
        Also takes a build_id, due to API leakage.
    """
    buildinfo = session.getBuild(nvr)
    if buildinfo is None:
        return None

    buildinfo['name'] = buildinfo['package_name']
    buildinfo['arch'] = 'src'
    epoch = buildinfo['epoch']
    if buildinfo['epoch'] is None:
        buildinfo['epoch'] = ""
        epoch = '0'
    else:
        buildinfo['epoch'] = str(buildinfo['epoch']) + ":"

    snvr = buildinfo['name']
    snvr += '-'
    snvr += buildinfo['version']
    snvr += '-'
    snvr += buildinfo['release']
    ent = {'package_name' : buildinfo['name'], 'nvr' : snvr,
           # These aren't used atm.
           'name' : buildinfo['name'], 'version' : buildinfo['version'],
           'release' : buildinfo['release'],
           'epoch' : None}
    return ent

# This is mostly copied and pasted from: koji_cli/commands.py rpminfo
def koji_nvra2srpm(session, nvra):
    """ Given an rpm nvra, convert it into an srpm nvr for CVE checker.
    """
    info = session.getRPM(nvra)
    if info is None:
        return None

    if info['epoch'] is None:
        info['epoch'] = ""
    else:
        info['epoch'] = str(info['epoch']) + ":"

    if info.get('external_repo_id'):
        repo = session.getExternalRepo(info['external_repo_id'])
        print("External Repository: %(name)s [%(id)i]" % repo)
        print("External Repository url: %(url)s" % repo)
        return None

    return koji_nvr2srpm(session, info['build_id'])

def load_package_list():
    return _read_lines("conf/sync2build-packages.txt")

def load_module_list():
    return _read_lines("conf/sync2build-modules.txt")

def load_package_denylist():
    return _read_lines("conf/sync2build-packages-denylist.txt")

def koji_tag2pkgs(kapi, tag):
    """
    Return a list of latest builds that are tagged with certain tag
    """
    return [spkg.nvr2pkg(x['nvr']) for x in kapi.listTagged(tag, latest=True)]

def filter_latest_modules(tagged_modules):
    """ 
    This function takes a list of tagged modules and returns only latest modules
    from it.
    """
    latest_tagged_modules = {}
    # print(json.dumps(tagged_modules, indent=4, sort_keys=True, separators=[",",":"]))
    for module in tagged_modules:
       module_name = module["name"]
       if module_name in latest_tagged_modules.keys():
           current_latest_module = latest_tagged_modules[module_name]
           biggest_number = int(current_latest_module["release"].split('.')[0])
           big_number = int(module["release"].split('.')[0])
           if big_number > biggest_number:
               latest_tagged_modules[module_name] = module
       else:
           latest_tagged_modules[module_name] = module
    return latest_tagged_modules.values()

def get_tagged_modules(kapi, tag):
    """
    Return a list of latest builds that are tagged with certain tag
    """
    # `kapi.listTagged(tag, latest=True)` won't work as `latest` flag is broken with modules
    # We have to parse list of modules manually and get the latest one
    return filter_latest_modules(kapi.listTagged(tag, latest=False))

def composed_url2pkgs(baseurl):
    """
    Return a list of latest packages that are in the given compose
    """
    import compose

    c = compose.Compose(baseurl)
    pdata = c.json_rpms()
    p = compose.packages_from_compose(pdata)
    return p

def get_composed_modules(baseurl):
    """
    Return a list of latest modules that are in the given compose
    """
    import compose

    c = compose.Compose(baseurl)
    mdata = c.json_modules()
    m = compose.modules_from_compose(mdata)
    return compose.dedup_modules(m)

_cached_upath = None
def _cached_setup():
    if not conf_cache_builds:
        return None

    try:
        import mtimecache
    except:
        return None
    global _cached_upath
    if _cached_upath is None:
        _cached_upath = mtimecache.userappcachedir("sync2build")
        mtimecache.clean_dir(_cached_upath + "nvr")
        mtimecache.clean_dir(_cached_upath + "version-nvr")
    return mtimecache

def cached_nvr(nvr):
    mtimecache = _cached_setup()
    if mtimecache is None:
        return None
    ret = mtimecache.Cache(_cached_upath + "nvr/" + nvr)
    return ret

def cached_version_nvr(version, nvr):
    mtimecache = _cached_setup()
    if mtimecache is None:
        return None
    ret = mtimecache.Cache(_cached_upath + "version-nvr/" + version + '-' + nvr)
    return ret

def composed_modules2tagged_builds(composed):
    """
    Convert compose module JSON data into build/nvr data from koji
    """
    ret = []
    for mod in composed:
        ent = {'package_name' : mod.name, 'nvr' : mod.nsvc(),
               # These aren't used atm.
               'name' : mod.name, 'version' : mod.stream,
               'release' : mod.vc(),
               'epoch' : None}
        ret.append(ent)
    return ret

def _deny_prefix(bpkg, prefixes):
    for prefix in prefixes:
        if bpkg.name.startswith(prefix):
            return True
    return False

def check_denylist_builds(bpkgs, denylist):
    """
    Look for any builds on the denylist, and remove them.
    """
    prefixes = []
    for dname in denylist:
        if dname[-1] != '*':
            continue
        prefixes.append(dname[:-1])

    ret = []
    for bpkg in sorted(bpkgs):
        if bpkg.name in denylist:
            print("Denied Pkg: ", bpkg)
            sys.stdout.flush()
            continue
        if _deny_prefix(bpkg, prefixes):
            print("Denied Pkg (prefix): ", bpkg)
            sys.stdout.flush()
            continue

        ret.append(bpkg)
    return ret

def build2git_tags(build, codir, T="rpms"):
    giturl = "https://git.centos.org/"
    giturl += T
    giturl += "/"
    giturl += build['package_name']
    giturl += ".git"
    try:
        repo = git.Repo.clone_from(giturl, codir)
        tags = repo.tags
    except git.exc.GitCommandError:
        # This means the clone didn't work, so it's a new package.
        tags = []
    return tags

def bpkg2git_tags(bpkg, codir, T="rpms"):
    giturl = "https://git.centos.org/"
    giturl += T
    giturl += "/"
    giturl += bpkg.name
    giturl += ".git"
    try:
        repo = git.Repo.clone_from(giturl, codir)
        tags = repo.tags
    except git.exc.GitCommandError:
        # This means the clone didn't work, so it's a new package.
        tags = []
    return tags

def _tags2pkgs(tags):
    tpkgs = []
    for tag in tags:
        stag = str(tag)
        if not stag.startswith("imports/c8"):
            continue
        stag = stag[len("imports/c8"):]
        # Eg. See: https://git.centos.org/rpms/ongres-scram/releases
        stag = stag.replace('%7e', '~')
        if '%' in stag: # FIXME? panic?
            continue
        if stag.startswith("s/"):
            stream = True
            stag = stag[len("s/"):]
        elif  stag.startswith("/"):
            stream = False
            stag = stag[len("/"):]
        else:
            continue

        # Tag is now N-V-R
        pkg = spkg.nvr2pkg(stag)
        pkg.stream = stream
        tpkgs.append(pkg)

    return tpkgs

def check_unsynced_builds(bpkgs, packages_to_track):
    """
    Look for builds that are not synced with centos streams
    """
    ret = []

    tcoroot = tempfile.TemporaryDirectory(prefix="sync2build-", dir="/tmp")
    corootdir = tcoroot.name + '/'
    print("Using tmp dir:", corootdir)
    for bpkg in sorted(bpkgs):
        if bpkg.name not in packages_to_track:
            continue

        cb = cached_nvr(bpkg.nvr)
        if cb is not None and cb.cached():
            print("Cached-Tag: ", cb.read())
            continue
        codir = corootdir + bpkg.name

        tags = bpkg2git_tags(bpkg, codir)
        if os.path.exists(codir + '/README.debrand'):
            print("Skip (debranding): ", bpkg)

        tpkgs = _tags2pkgs(tags)

        for tpkg in sorted(spkg.returnNewestByName(tpkgs)):
            if tpkg.name != bpkg.name:
                print("Err:", tpkg, "!=", pkg)
                continue
            if not tpkg.verGT(bpkg):
                continue
            print("Need to build:", tpkg, "(latest build:", bpkg, ")")
            ret.append(tpkg)

        sys.stdout.flush()
        shutil.rmtree(codir, ignore_errors=True)
    return ret

# Given:
# perl-IO-Tty-1.12-12.module+el8.3.0+6446+37a50855
# We want to match to:
# perl-IO-Tty-1.12-12.module+el8.3.0+6446+594cad75
def nvr2shared_nvr(nvr):
    val = nvr.rfind('+') # Remove the +37a50855 suffix
    if val != -1:
        nvr = nvr[:val]
    if False: # Just remove the last bit?
        return nvr
    val = nvr.rfind('+') # Remove the +6446 suffix
    if val != -1:
        nvr = nvr[:val]
    return nvr

def find_shared_nvr(nvr, builds):
    """
    Given a shared nvr, search through all the build dicts. and see if it
    matches.
    """
    for build in builds:
        snvr = nvr2shared_nvr(build['nvr'])
        if snvr == nvr:
            return True
    return False

def check_extra_rpms(kapi, build, modcodir, extras):
    """
    Check all the rpms within a module and make sure they are also pushed.
    """
    if not conf_check_extra_rpms:
        return

# Is this good or bad?
#   ** PKG perl-IO-Tty in mod perl-IO-Socket-SSL-2.066-8030020200430120526.ea09926d needs to be updated to perl-IO-Tty-1.12-12.module+el8.3.0+6446+37a50855
#   * Old Tag: imports/c8s-stream-2.066/perl-IO-Tty-1.12-12.module+el8.3.0+6446+594cad75

    module_id, tag, module_spec_in_json = modbuild2mbsjson(build)
    if len(module_spec_in_json['items']) < 1:
        print("** No items:", module_id)
        return
    rpms = module_spec_in_json['items'][0]['tasks'].get('rpms', [])
    srpms = set()
    for name in sorted(rpms):
        if name in auto_passcvelist_module_packages:
            continue

        ent = json_nvr2koji_srpm(kapi, rpms[name]['nvr'])
        if ent is None: # Fail?
            print("Skipping extra check:", rpms[name]['nvr'])
            sys.stdout.flush()
            continue

        if ent['package_name'] in srpms:
            continue
        srpms.add(ent['package_name'])

        nvr = nvr2shared_nvr(ent['nvr'])
        if find_shared_nvr(nvr, extras):
            continue

        cb = cached_version_nvr(build['version'], nvr)
        if cb is not None and cb.cached():
            print("  Pkg mod Cached-Tag: ", cb.read())
            continue

        tags = build2git_tags(ent, modcodir + "/" + ent['package_name'])
        # Eg. from the module: pki-deps-10.6-8030020200527165326-30b713e6
        # imports/c8s-stream-10.6/glassfish-jax-rs-api-2.0.1-6.module+el8.2.0+5723+4574fbff 
        tag_8 = "imports/c8-stream-" + build['version'] + '/' + nvr
        tag_8s ="imports/c8s-stream-"+ build['version'] + '/' + nvr
        tags_to_check = (tag_8, tag_8s)
        new_build = True
        for tag in tags:
            if nvr2shared_nvr(str(tag)) not in tags_to_check:
                continue
            uitag = str(tag)[len("imports/"):]
            if cb is not None:
                cb.touch(uitag)
            if uitag.endswith(ent['nvr']): # Direct match.
                print("  Pkg mod tag: ", uitag)
            else:
                print("  Pkg mod tag: ", uitag, "(shared:",  ent['nvr'] +")")
            new_build = False
            break

        if not new_build:
            continue

        ent['_git-branch'] = 'c8s-stream-' + build['version']
        print(("  ** PKG %s in mod %s needs to be updated to %s") % (ent['package_name'], build['nvr'], ent['nvr']))
        if __output_old_tags:
            for tag in sorted([str(x) for x in tags]):
                print("     * Old Tag:", tag)
        extras.append(ent)

def check_unsynced_modules(kapi, tagged_builds, modules_to_track):
    """
    Look for modules that are not synced with centos streams.
    """
    unsynced_builds = []
    extra_pkg_builds = []
    tcoroot = tempfile.TemporaryDirectory(prefix="centos-sync-mod-", dir="/tmp")
    corootdir = tcoroot.name + '/'
    print("Using tmp dir:", corootdir)
    for build in sorted(tagged_builds, key=lambda x: x['package_name']):
        if build['package_name'] in modules_to_track:
            codir = corootdir + build['package_name']

            cb = cached_version_nvr(build['version'], build['nvr'])
            if cb is not None and cb.cached():
                print("Cached-Tag: ", cb.read())
                continue

            tags = build2git_tags(build, codir+"/_mod", T="modules")

            # imports/c8-stream-1.0/libvirt-4.5.0-35.3.module+el8.1.0+5931+8897e7e1 
            # This is actualy: imports/c8-stream-<version>/<nvr>
            #                  imports/c8s-stream-<version>/<nvr>
            tag_8 = "imports/c8-stream-" + build['version'] + '/' + build['nvr']
            tag_8s ="imports/c8s-stream-"+ build['version'] + '/' + build['nvr']
            tags_to_check = (tag_8, tag_8s)
            new_build = True
            for tag in tags:
                # print(" Mod tag check: {}".format(str(tag)))
                if str(tag) in tags_to_check:
                    new_build = False
                    uitag = str(tag)[len("imports/"):]
                    if cb is not None:
                        cb.touch(uitag)
                    print("Tag: ", uitag)
                    if __output_build_lines:
                        print("Build: ", build)
                        print( ("%s is already updated to %s") % (build['package_name'], build['nvr']) )
                    # Now we have to check the rpms within the module, because
                    # it doesn't push them all sometimes ... sigh.
                    check_extra_rpms(kapi, build, codir, extra_pkg_builds)
                    break
            if new_build:
                print( ("%s needs to be updated to %s") % (build['package_name'], build['nvr']) )
                if __output_old_tags:
                    for tag in sorted([str(x) for x in tags]):
                        print("  Old Tag:", tag)
                unsynced_builds.append(build)
            sys.stdout.flush()
            shutil.rmtree(codir, ignore_errors=True)

    return unsynced_builds, extra_pkg_builds

def modbuild2mbsjson(build):
    """
    Given a module nvr contact MBS and return the JSON build data
    """
    module_id = "module-" + build['nvr'][::-1].replace('.', '-', 1)[::-1]
    tag = "c8s-stream-" + build['version']
    mbs_url = "https://mbs.engineering.redhat.com/module-build-service/1/module-builds/?koji_tag={}&verbose=1".format(module_id)
    # print(mbs_url)
    import urllib, json
    http_response= urllib.request.urlopen(mbs_url)
    module_spec_in_json = json.load(http_response)
    return module_id, tag, module_spec_in_json

def json_nvr2koji_srpm(kapi, rpmnvr):
    ent = koji_nvr2srpm(kapi, rpmnvr)
    if ent is None:
        print("No such koji rpm: %s" % rpmnvr)
    return ent

def build_packages(kapi, bpkgs, tag, giturl='git+https://git.centos.org/rpms/'):
    """
    Build the newer rpms to centos stream tags
    """

    for bpkg in sorted(bpkgs):
        url = giturl + bpkg.name
        url += '?#imports/c8s/' + bpkg.nvr
        # print("URL:", url)
        print("Building:", bpkg)
        sys.stdout.flush()

        if conf_data_downloadonly:
            continue

        task_id = kapi.build(url, tag)
        weburl = "https://koji.mbox.centos.org/koji"
        print("Task: %s/taskinfo?taskID=%d" % (weburl, task_id))
        sys.stdout.flush()

def sync_modules_directly(kapi, unsynced_builds):
    """
    This is a temporary method to sync by directly uploading modules to centos repos
    """

    extra_pkg_builds = []
    tcoroot = tempfile.TemporaryDirectory(prefix="centos-sync-mod2-",dir="/tmp")
    corootdir = tcoroot.name + '/'
    print("Using tmp dir:", corootdir)
    for build in sorted(unsynced_builds, key=lambda x: x['package_name']):
        if conf_data_downloadonly:
            continue

    return extra_pkg_builds

def sync_packages(tag, compose, kapi, packages_to_track, denylist=[]):
    """
        tag: Specify a koji tag to pull packages from.
        compose: Specify a "koji" compose to pull packages from (None uses the tag.
        kapi: koji object to query
        packages_to_track: list of packages we care about (unused for compose)
    """
    if compose is None:
        bpkgs = koji_tag2pkgs(kapi, tag)
        if __auto_tag_allowlist:
            packages_to_track = set()
            for bpkg in bpkgs:
                packages_to_track.add(bpkg.name)
    else:
        bpkgs = composed_url2pkgs(compose)
        if __auto_compose_allowlist:
            packages_to_track = set()
            for bpkg in bpkgs:
                packages_to_track.add(bpkg.name)
    if __test_print_tagged:
        from pprint import pprint
        pprint(bpkgs)
        return
    bpkgs = check_denylist_builds(bpkgs, denylist)
    bpkgs = check_unsynced_builds(bpkgs, packages_to_track)
    build_packages(kapi, bpkgs, tag)

def sync_modules(tag, compose, kapi, modules_to_track):
    """
        tag: Specify a koji tag to pull modules from.
        compose: Specify a "koji" compose to pull modules from (None uses the tag).
        kapi: koji object to query
        modules_to_track: list of modules we care about
    """
    if True: return
    if compose is None:
        tagged_builds = get_tagged_modules(kapi, tag)
    else:
        composed_builds = get_composed_modules(compose)
        tagged_builds = composed_modules2tagged_builds(composed_builds)
        if __auto_compose_allowlist:
            modules_to_track = set()
            for build in tagged_builds:
                modules_to_track.add(build['package_name'])
    if __test_print_tagged:
        from pprint import pprint
        pprint(tagged_builds)
        return
    unsynced_builds, extra_pkgs = check_unsynced_modules(kapi, tagged_builds,
                                                         modules_to_track)
    unsynced_builds = check_cve_modules(kapi, unsynced_builds)
    extra_pkg2 = sync_modules_directly(kapi, unsynced_builds)
    # These are the extra rpms needed for already pushed modules...
    sync_directly(extra_pkgs)
    sync_directly(extra_pkg2)

def _match_pkgs(args, bpkgs):
    import fnmatch
    ret = []
    for bpkg in sorted(bpkgs):
        full = (bpkg.name, bpkg.nv, bpkg.nvr, bpkg.nvra)
        found = len(args) == 0
        for arg in sorted(args):
            if arg in full:
                found = True
                break
            for m in full:
                if fnmatch.fnmatch(m, arg):
                    found = True
                    break
            if found:
                break
        if not found:
            continue
        ret.append(bpkg)
    return ret

def main():
    parser = OptionParser()
    parser.add_option("", "--koji-host", dest="koji_host",
                      help="Host to connect to", default="https://koji.mbox.centos.org/kojihub")
    parser.add_option("", "--packages-tag", dest="packages_tag",
                      help="Specify package tag to sync", default="dist-c8-stream")
    parser.add_option("", "--modules-tag", dest="modules_tag",
                      help="Specify module tag to sync", default="dist-c8-stream-module")
    parser.add_option("", "--packages-compose", dest="packages_compose",
                      help="Specify package compose to sync", default=None)
    parser.add_option("", "--modules-compose", dest="modules_compose",
                      help="Specify module compose to sync", default=None)
    parser.add_option("", "--download-only", dest="download_only",
                      help="Just download, always safe", default=False, action="store_true")
    parser.add_option("", "--nocache", dest="nocache",
                      help="Don't cache any results", default=False, action="store_true")

    (options, args) = parser.parse_args()

    kapi = koji.ClientSession(options.koji_host)
    kapi.ssl_login("/compose/.koji/mbox_admin.pem", None, "/compose/.koji/ca.crt")

    packages_to_track = load_package_list()
    modules_to_track = load_module_list()
    denylist = load_package_denylist()
    denylist = set(denylist)

    if options.nocache:
        global conf_cache_builds
        conf_cache_builds = False

    if options.download_only:
        global conf_data_downloadonly
        conf_data_downloadonly = True
    else:
        print(" ** Warning: This will build pkgs/mods in koji.")

    if not args: pass
    elif args[0] in ('list-packages', 'list-pkgs', 'ls-pkgs'):
        args = args[1:]

        tag  = options.packages_tag
        comp = options.packages_compose

        def _out_pkg(prefix, bpkgs):
            prefix = "%8s" % prefix
            for bpkg in sorted(bpkgs):
                suffix = ''
                if hasattr(bpkg, 'stream') and bpkg.stream:
                    suffix = '(stream)'
                print(prefix, bpkg, suffix)
        bpkgs = koji_tag2pkgs(kapi, tag)
        _out_pkg("Tag:", _match_pkgs(args, bpkgs))
        if comp is not None:
            cpkgs = composed_url2pkgs(comp)
            _out_pkg("Compose:", _match_pkgs(args, cpkgs))
    elif args[0] in ('summary-packages', 'summary-pkgs', 'sum-pkgs'):
        args = args[1:]

        tag  = options.packages_tag
        comp = options.packages_compose

        bpkgs = koji_tag2pkgs(kapi, tag)
        print("  Tagged packages:", len(bpkgs))
        if args:
            print("  Matched:", len(_match_pkgs(args, bpkgs)))
        if comp is not None:
            cpkgs = composed_url2pkgs(comp)
            print("Composed packages:", len(cpkgs))
            if args:
                print("  Matched:", len(_match_pkgs(args, cpkgs)))
    elif args[0] == 'check-nvr':

        tag  = options.packages_tag
        comp = options.packages_compose

        bpkg = spkg.nvr2pkg(args[1])
        print("Pkg:", bpkg)

        def _out_pkg(prefix, pkg, bpkgs):
            prefix = "%8s" % prefix
            for bpkg in sorted(bpkgs):
                if bpkg.name != pkg.name:
                    continue
                suffix = ''
                if hasattr(bpkg, 'stream') and bpkg.stream:
                    suffix = '(stream)'
                if False: pass
                elif bpkg.verGT(pkg):
                    print(prefix, "Newer:", bpkg, suffix)
                elif bpkg.verEQ(pkg):
                    print(prefix, "   EQ:", bpkg, suffix)
                elif bpkg.verLT(pkg):
                    print(prefix, "Older:", bpkg, suffix)
                else:
                    print(prefix, "!!:", bpkg, suffix)
        bpkgs = koji_tag2pkgs(kapi, tag)
        _out_pkg("Tag:", bpkg, bpkgs)
        if comp is not None:
            cpkgs = composed_url2pkgs(comp)
            _out_pkg("Compose:", bpkg, cpkgs)

        tcoroot = tempfile.TemporaryDirectory(prefix="sync2build-chk-", dir="/tmp")
        corootdir = tcoroot.name + '/'
        codir = corootdir + bpkg.name
        tags = bpkg2git_tags(bpkg, codir)
        if os.path.exists(codir + '/README.debrand'): # Doesn't work
            print(" ** Debranding **")
        tpkgs = _tags2pkgs(tags)
        _out_pkg("GIT:", bpkg, tpkgs)
    elif args[0] == 'build-nvr':
        pkg = spkg.nvr2pkg(args[1])
        print("Pkg:", pkg)
        if not check_denylist_builds([pkg], denylist):
            print("Pkg in denylist:", pkg)
            sys.exit(1) # Allow force?
        tcoroot = tempfile.TemporaryDirectory(prefix="sync2build-chk-", dir="/tmp")
        corootdir = tcoroot.name + '/'
        codir = corootdir + pkg.name
        tags = bpkg2git_tags(pkg, codir)
        tpkgs = _tags2pkgs(tags)
        found = False
        for tpkg in sorted(tpkgs):
            if tpkg.name != pkg.name:
                continue
            suffix = ''
            if hasattr(tpkg, 'stream') and tpkg.stream:
                suffix = '(stream)'
            if tpkg.verGT(pkg):
                print("Newer version in GIT, building that!", pkg, tpkg, suffix)
                pkg = tpkg
                found = True # Allow building older packages??
            elif tpkg.verEQ(pkg):
                found = True
                print("Found version in GIT:", tpkg, suffix)
        if not found:
            print("Didn't find (so can't build):", tpkg, suffix)
        else:
            build_packages(kapi, [pkg], options.packages_tag)
        sys.exit(0)

    if 'packages' in args:
        tag  = options.packages_tag
        comp = options.packages_compose
        sync_packages(tag, comp, kapi, packages_to_track, denylist)

    if False and 'modules' in args:
        tag  = options.modules_tag
        comp = options.modules_compose
        sync_modules(tag, comp, kapi, modules_to_track)
    if not sys.stdout.isatty():
        print(" -- Done --")

# Badly written but working python script
if __name__ == "__main__":
    main()
