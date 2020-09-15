import koji as brew
import json
import sys
import os
import shutil
import tempfile
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
conf_cache_builds = True

# This should never have CVEs and CVE checker hates it (timeout = fail).
auto_passcvelist_module_packages = ["module-build-macros"]

# Do we want to output old tags data, useful for debugging
__output_old_tags = False

# Do we want to output build data, useful for debugging
__output_build_lines = False

# Do we want to include all packages from a compose...
__auto_compose_allowlist = True

# Do we want to just test...
__test_print_tagged = False

if not __test_print_tagged:
    import git

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
    return _read_lines("packages.txt")

def load_module_list():
    return _read_lines("modules.txt")

def load_package_denylist():
    return _read_lines("packages-denylist.txt")

def get_tagged_builds(brew_proxy, tag):
    """
    Return a list of latest builds that are tagged with certain tag
    """
    return brew_proxy.listTagged(tag, latest=True)

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

def get_tagged_modules(brew_proxy, tag):
    """
    Return a list of latest builds that are tagged with certain tag
    """
    # `brew_proxy.listTagged(tag, latest=True)` won't work as `latest` flag is broken with modules
    # We have to parse list of modules manually and get the latest one
    return filter_latest_modules(brew_proxy.listTagged(tag, latest=False))

def get_composed_builds(baseurl):
    """
    Return a list of latest builds that are in the given compose
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
def cached_nvr(nvr):
    if not conf_cache_builds:
        return None

    try:
        import mtimecache
    except:
        return None
    global _cached_upath
    if _cached_upath is None:
        _cached_upath = mtimecache.userappcachedir("sync2git")
        mtimecache.clean_dir(_cached_upath + "nvr")
    ret = mtimecache.Cache(_cached_upath + "nvr/" + nvr)
    return ret

def cached_version_nvr(version, nvr):
    if not conf_cache_builds:
        return None

    try:
        import mtimecache
    except:
        return None
    global _cached_upath
    if _cached_upath is None:
        _cached_upath = mtimecache.userappcachedir("sync2git")
        mtimecache.clean_dir(_cached_upath + "version-nvr")
    ret = mtimecache.Cache(_cached_upath + "version-nvr/" + version + '-' + nvr)
    return ret

def composed_builds2tagged_builds(composed):
    """
    Convert compose package JSON data into build/nvr data from koji
    """
    ret = []
    for pkg in composed:
        ent = {'package_name' : pkg.name, 'nvr' : pkg.nvr(),
               # These aren't used atm.
               'name' : pkg.name, 'version' : pkg.version, 'release' : pkg.release,
               'epoch' : pkg.koji_epochnum()}
        ret.append(ent)
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

def check_denylist_builds(builds, denylist):
    """
    Look for any builds on the denylist, and remove them.
    """
    ret = []
    for build in sorted(builds, key=lambda x: x['package_name']):
        if build['package_name'] in denylist:
            print("Denied Pkg: ", build['nvr'])
            sys.stdout.flush()
            continue
        ret.append(build)
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

def check_unsynced_builds(tagged_builds, packages_to_track):
    """
    Look for builds that are not synced with centos streams
    """
    unsynced_builds = []

    tcoroot = tempfile.TemporaryDirectory(prefix="centos-sync-", dir="/tmp")
    corootdir = tcoroot.name + '/'
    print("Using tmp dir:", corootdir)
    for build in sorted(tagged_builds, key=lambda x: x['package_name']):
        if build['package_name'] in packages_to_track:
            cb = cached_nvr(build['nvr'])
            if cb is not None and cb.cached():
                print("Cached-Tag: ", cb.read())
                continue
            codir = corootdir + build['package_name']

            tags = build2git_tags(build, codir)
            tags_to_check = ("imports/c8s/" + build['nvr'], "imports/c8/" + build['nvr'])
            new_build = True
            for tag in tags:
                if str(tag) in tags_to_check:
                    uitag = str(tag)[len("imports/"):]
                    if cb is not None:
                        cb.touch(uitag)
                    new_build = False
                    print("Tag: ", uitag)
                    if __output_build_lines:
                        print("Build: ", build)
                        print( ("%s is already updated to %s") % (build['package_name'], build['nvr']) )
                    break
            if new_build:
                print( ("%s needs to be updated to %s") % (build['package_name'], build['nvr']) )
                if __output_old_tags:
                    for tag in sorted([str(x) for x in tags]):
                        print("  Old Tag:", tag)
                unsynced_builds.append(build)
            sys.stdout.flush()
            # TODO: Ideally we should keep this directory and fetch latest tags to avoid repeated clones
            shutil.rmtree(codir, ignore_errors=True)
    return unsynced_builds

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

def check_cve_builds(tagged_builds):
    """
    Look for builds that aren't allowed and filter them
    """
    if not conf_filter_cve:
        return tagged_builds
    import access

    reqs = {}
    for build in sorted(tagged_builds, key=lambda x: x['package_name']):
        if build['nvr'] in reqs:
            continue

        n, v, r = build['nvr'].rsplit('-', 2)
        req = access.NvrInfo(n, v, r)
        reqs[build['nvr']] = req
        #  Precache for speed, downside is it means once we get an allow
        # we stop querying.
        if not req.hist_precache():
            req.req()

    # Now we look at the results and filter those that aren't allowed...
    allowed_builds = []
    for build in sorted(tagged_builds, key=lambda x: x['package_name']):
        if build['nvr'] not in reqs: # How did this happen?
            print("Error Pkg: ", build['package_name'])
            continue
        req = reqs[build['nvr']]
        if not req.allow():
            print("Filtered Pkg: ", req)
            sys.stdout.flush()
            continue
        allowed_builds.append(build)
    return allowed_builds

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

def check_cve_modules(kapi, tagged_builds):
    """
    Look for any rpms in the modulebuilds that aren't allowed and filter them
    """
    if not conf_filter_cve:
        return tagged_builds
    allowed_builds = []
    for build in sorted(tagged_builds, key=lambda x: x['package_name']):
        module_id, tag, module_spec_in_json = modbuild2mbsjson(build)
        if len(module_spec_in_json['items']) < 1:
            print("** No items:", module_id)
            continue

        failed = False
        rpms = module_spec_in_json['items'][0]['tasks'].get('rpms', [])
        for name in sorted(rpms):
            if name in auto_passcvelist_module_packages:
                continue
            # ent = {'package_name' : name, 'nvr' : rpms[name]['nvr']}
            ent = json_nvr2koji_srpm(kapi, rpms[name]['nvr'])
            if ent is None: # Fail?
                print("Skipping CVE lookup:", rpms[name]['nvr'])
                sys.stdout.flush()
                continue

            if not check_cve_builds([ent]):
                failed = True
                print("Filtered Mod: ", build['nvr'])
                sys.stdout.flush()
                break
        if not failed:
            allowed_builds.append(build)
    return allowed_builds

def sync_through_pub(unsynced_builds):
    """
    Create `pub` jobs that will sync package builds with Centos repositories
    """
    # We should be able to initally use `push-rpm` to push individual rpms
    # http://pub.devel.redhat.com/pub/docs/pubcli.html#push-rpms
    # But later we should use staging structure for efficiency
    # http://pub.devel.redhat.com/pub/docs/usage.html#staging-structure
    # http://pub.devel.redhat.com/pub/docs/pubcli.html#push-staged

    # APIs for `pub` are written using `python2` and I don't want to depend on python2
    # So instead directly use CLI to push rpms
    # pub push-rpm --target alt-src /path/to/rpm
    # import ipdb
    # ipdb.set_trace()
    pass

def _alt_src_cmd(args):
    cmd = "alt-src "
    if not conf_alt_src_tmp:
        return os.system(cmd + args)

    tmpdir = tempfile.TemporaryDirectory(prefix="sync2git-altsrc-", dir="/tmp")

    os.mkdir(tmpdir + "/stage")
    os.mkdir(tmpdir + "/git")
    os.mkdir(tmpdir + "/lookaside")

    cmd += "-o stagedir=" + tmpdir + "stage "
    cmd += "-o gitdir=" + tmpdir + "git "
    cmd += "-o lookaside=" + tmpdir + "lookaside "

    ret = os.system(cmd + args)
    return ret

def alt_src_cmd_build(branch, build):
    print("alt-src", branch, build['nvr'])
    sys.stdout.flush()
    _alt_src_cmd("-d --push " + branch + " " + build['nvr'] + ".src.rpm")

def alt_src_cmd_module(tag, filename):
    print("alt-src", tag, filename)
    sys.stdout.flush()
    _alt_src_cmd("--push --brew " + tag + " " + filename)

def sync_directly(unsynced_builds):
    """
    This is a temporary method to sync by directly uploading rpms to centos repos
    This should be replaced by `sync_through_pub()` function at some point in future
    """
    for build in sorted(unsynced_builds, key=lambda x: x['package_name']):
        # FIXME: This should use the API...
        cmd = "brew download-build --rpm"
        if not sys.stdout.isatty():
            cmd = "brew download-build --noprogress --rpm"
        cmd += " " + build['nvr'] + ".src.rpm"
        print(cmd)
        sys.stdout.flush()
        os.system(cmd)

    for build in sorted(unsynced_builds, key=lambda x: x['package_name']):
        branch = "c8s"
        if '_git-branch' in build:
            branch = build['_git-branch']
        if conf_data_downloadonly:
            print("!alt-src", branch, build['nvr'])
            continue
        alt_src_cmd_build(branch, build)

    if conf_data_downloadonly:
        return

    for build in sorted(unsynced_builds, key=lambda x: x['package_name']):
        print("Removing " + build['nvr'] + ".src.rpm...")
        sys.stdout.flush()
        os.remove(build['nvr'] + ".src.rpm")

def sync_modules_directly(kapi, unsynced_builds):
    """
    This is a temporary method to sync by directly uploading modules to centos repos
    This should be replaced by `sync_through_pub()` function at some point in future
    """

    extra_pkg_builds = []
    tcoroot = tempfile.TemporaryDirectory(prefix="centos-sync-mod2-",dir="/tmp")
    corootdir = tcoroot.name + '/'
    print("Using tmp dir:", corootdir)
    for build in sorted(unsynced_builds, key=lambda x: x['package_name']):
        module_id, tag, module_spec_in_json = modbuild2mbsjson(build)
        if len(module_spec_in_json['items']) < 1:
            print("** No items:", module_id)
            continue
        modulemd = module_spec_in_json['items'][0]['modulemd']
        # print(modulemd)
        filename = "{}:modulemd.src.txt".format(build['nvr'])
        with open(filename, "w") as modulemd_file:
            modulemd_file.write(modulemd)

        print("Wrote:", filename)
        if conf_data_downloadonly:
            print("!alt-src", tag, filename)
            continue

        alt_src_cmd_module(tag, filename)
        os.remove(filename)

        # Now we have to check the rpms within the module, because
        # it doesn't push them all sometimes ... sigh.
        codir = corootdir + build['package_name']
        check_extra_rpms(kapi, build, codir, extra_pkg_builds)
    return extra_pkg_builds

def sync_packages(tag, compose, brew_proxy, packages_to_track, denylist=[]):
    """
        tag: Specify a koji tag to pull packages from.
        compose: Specify a "koji" compose to pull packages from (None uses the tag.
        brew_proxy: brew object to query
        packages_to_track: list of packages we care about (unused for compose)
    """
    if compose is None:
        tagged_builds = get_tagged_builds(brew_proxy, tag)
    else:
        composed_builds = get_composed_builds(compose)
        tagged_builds = composed_builds2tagged_builds(composed_builds)
        if __auto_compose_allowlist:
            packages_to_track = set()
            for build in tagged_builds:
                packages_to_track.add(build['package_name'])
    if __test_print_tagged:
        from pprint import pprint
        pprint(tagged_builds)
        return
    # build = brew_proxy.getBuild(sys.argv[1]) # module
    # `nvr` attribute of `tagged_build` contains git tags
    # print(json.dumps(tagged_builds, indent=4, sort_keys=True, separators=[",",":"]))
    unsynced_builds = tagged_builds
    unsynced_builds = check_denylist_builds(unsynced_builds, denylist)
    unsynced_builds = check_unsynced_builds(unsynced_builds, packages_to_track)
    unsynced_builds = check_cve_builds(unsynced_builds)
    # sync_through_pub(unsynced_builds)
    sync_directly(unsynced_builds)

def sync_modules(tag, compose, brew_proxy, modules_to_track):
    """
        tag: Specify a koji tag to pull modules from.
        compose: Specify a "koji" compose to pull modules from (None uses the tag).
        brew_proxy: brew object to query
        modules_to_track: list of modules we care about
    """
    if compose is None:
        tagged_builds = get_tagged_modules(brew_proxy, tag)
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
    kapi = brew_proxy
    unsynced_builds, extra_pkgs = check_unsynced_modules(kapi, tagged_builds,
                                                         modules_to_track)
    unsynced_builds = check_cve_modules(brew_proxy, unsynced_builds)
    extra_pkg2 = sync_modules_directly(kapi, unsynced_builds)
    # These are the extra rpms needed for already pushed modules...
    sync_directly(extra_pkgs)
    sync_directly(extra_pkg2)

def main():
    parser = OptionParser()
    parser.add_option("", "--koji-host", dest="koji_host",
                      help="Host to connect to", default="http://brewhub.engineering.redhat.com/brewhub/")
    parser.add_option("", "--sync-packages", dest="sync_packages",
                      help="Sync packages to streams", default=False, action="store_true")
    parser.add_option("", "--sync-modules", dest="sync_modules",
                      help="Sync modules to streams", default=False, action="store_true")
    parser.add_option("", "--packages-tag", dest="packages_tag",
                      help="Specify package tag to sync", default="rhel-8.2.0-candidate")
    parser.add_option("", "--modules-tag", dest="modules_tag",
                      help="Specify module tag to sync", default="rhel-8.2.0-modules-candidate")
    parser.add_option("", "--packages-compose", dest="packages_compose",
                      help="Specify package compose to sync", default=None)
    parser.add_option("", "--modules-compose", dest="modules_compose",
                      help="Specify module compose to sync", default=None)
    parser.add_option("", "--download-only", dest="download_only",
                      help="Just download, always safe", default=False, action="store_true")

    (options, args) = parser.parse_args()

    brew_proxy = brew.ClientSession(options.koji_host)
    packages_to_track = load_package_list()
    modules_to_track = load_module_list()
    denylist = load_package_denylist()
    denylist = set(denylist)

    if options.download_only:
        global conf_data_downloadonly
        conf_data_downloadonly = True
    else:
        print(" ** Warning: This will run alt-src to push packages/modules.")
    if options.sync_packages:
        sync_packages(options.packages_tag, options.packages_compose, brew_proxy, packages_to_track, denylist)
    if options.sync_modules:
        sync_modules(options.modules_tag, options.modules_compose, brew_proxy, modules_to_track)
    if not sys.stdout.isatty():
        print(" -- Done --")

# Badly written but working python script
if __name__ == "__main__":
    main()
