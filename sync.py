import koji as brew
import json
import sys
import os
import shutil
import tempfile
from optparse import OptionParser

# Do we want to filter through the CVE checker
filter_cve = True

# Just do the downloads, and don't alt-src
data_downloadonly = False

# This should never have CVEs and CVE checker hates it (timeout = fail).
auto_passcvelist_module_packages = ["module-build-macros"]

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

# This is mostly copied and pasted from: koji_cli/commands.py rpminfo
def koji_name2srpm(session, nvra):
    """ Given an rpm nvra from mbs, convert it into an srpm nvr for CVE checker.
    """
    info = session.getRPM(nvra)
    if info is None:
        print("No such koji rpm: %s\n" % nvra)
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

    buildinfo = session.getBuild(info['build_id'])
    buildinfo['name'] = buildinfo['package_name']
    buildinfo['arch'] = 'src'
    epoch = buildinfo['epoch']
    if buildinfo['epoch'] is None:
        buildinfo['epoch'] = ""
        epoch = '0'
    else:
        buildinfo['epoch'] = str(buildinfo['epoch']) + ":"

    if False:
            print("RPM Path: %s" %
                  os.path.join(koji.pathinfo.build(buildinfo), koji.pathinfo.rpm(info)))
            print("SRPM: %(epoch)s%(name)s-%(version)s-%(release)s [%(id)d]" % buildinfo)
            print("SRPM Path: %s" %
                  os.path.join(koji.pathinfo.build(buildinfo), koji.pathinfo.rpm(buildinfo)))
    else:
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
            codir = corootdir + build['package_name']

            tags = build2git_tags(build, codir)
            tags_to_check = ("imports/c8s/" + build['nvr'], "imports/c8/" + build['nvr'])
            new_build = True
            for tag in tags:
                if str(tag) in tags_to_check:
                    new_build = False
                    print("Tag: ", tag)
                    if __output_build_lines:
                        print("Build: ", build)
                        print( ("%s is already updated to %s") % (build['package_name'], build['nvr']) )
                    break
            if new_build:
                print( ("%s needs to be updated to %s") % (build['package_name'], build['nvr']) )
                for tag in sorted([str(x) for x in tags]):
                    print("  Old Tag:", tag)
                unsynced_builds.append(build)
            sys.stdout.flush()
            # TODO: Ideally we should keep this directory and fetch latest tags to avoid repeated clones
            shutil.rmtree(codir, ignore_errors=True)
    return unsynced_builds

def check_extra_rpms(kapi, build, modcodir):
    """
    Check all the rpms within a module and make sure they are also pushed.
    """
    ret = []
    module_id, tag, module_spec_in_json = modbuild2mbsjson(build)
    if len(module_spec_in_json['items']) < 1:
        print("** No items:", module_id)
        return
    rpms = module_spec_in_json['items'][0]['tasks'].get('rpms', [])
    srpms = set()
    for name in sorted(rpms):
        ent = json_nvr2koji_srpm(kapi, rpms[name]['nvr'])
        if ent is None: # Fail?
            print("Skipping extra check:", rpms[name]['nvr'])
            sys.stdout.flush()
            continue

        if ent['package-name'] in srpms:
            continue
        srpms.add(ent['package-name'])

        tags = build2git_tags(ent, modcodir + "/" + ent['package-name'])
        # Eg. from the module: pki-deps-10.6-8030020200527165326-30b713e6
        # imports/c8s-stream-10.6/glassfish-jax-rs-api-2.0.1-6.module+el8.2.0+5723+4574fbff 
        tag_8 = "imports/c8-stream-" + build['version'] + '/' + ent['nvr']
        tag_8s ="imports/c8s-stream-"+ build['version'] + '/' + ent['nvr']
        tags_to_check = (tag_8, tag_8s)
        new_build = True
        for tag in tags:
            if str(tag) not in tags_to_check:
                continue
            new_build = False
            break

        if not new_build:
            continue

        print(("  ** PKG %s in mod %s needs to be updated to %s") % (ent['package_name'], build['nvr'], ent['nvr']))
        for tag in sorted([str(x) for x in tags]):
            print("  * Old Tag:", tag)
        ret.append(ent)
    return ret

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
                    print("Tag: ", tag)
                    if __output_build_lines:
                        print("Build: ", build)
                        print( ("%s is already updated to %s") % (build['package_name'], build['nvr']) )
                    # Now we have to check the rpms within the module, because
                    # it doesn't push them all sometimes ... sigh.
                    extra_pkg_builds.extend(check_extra_rpms(kapi, build,codir))
                    break
            if new_build:
                print( ("%s needs to be updated to %s") % (build['package_name'], build['nvr']) )
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
    if not filter_cve:
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
    ent = koji_name2srpm(kapi, rpmnvr + ".x86_64")
    if ent is None:
        ent = koji_name2srpm(kapi, rpmnvr + ".noarch")
    return ent

def check_cve_modules(kapi, tagged_builds):
    """
    Look for any rpms in the modulebuilds that aren't allowed and filter them
    """
    if not filter_cve:
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

    if data_downloadonly:
        return

    for build in sorted(unsynced_builds, key=lambda x: x['package_name']):
        print("alt-src", build['nvr'])
        sys.stdout.flush()
        os.system("alt-src -d --push c8s " + build['nvr'] + ".src.rpm")

    for build in sorted(unsynced_builds, key=lambda x: x['package_name']):
        print("Removing " + build['nvr'] + ".src.rpm...")
        sys.stdout.flush()
        os.remove(build['nvr'] + ".src.rpm")

def sync_modules_directly(unsynced_builds):
    """
    This is a temporary method to sync by directly uploading modules to centos repos
    This should be replaced by `sync_through_pub()` function at some point in future
    """

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
        if data_downloadonly:
            continue

        # print("alt-src --push --brew " + tag + " " + filename)
        print("alt-src", tag, filename)
        sys.stdout.flush()
        os.system("alt-src --push --brew " + tag + " " + filename)
        # print("alt-src -v --push --koji c8-stream-1.0 container-tools-2.0-8020020200324071351.0d58ad57\:modulemd.src.txt")
        os.remove(filename)

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
    sync_modules_directly(unsynced_builds)
    # These are the extra rpms needed for already pushed modules...
    sync_directly(extra_pkgs)

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
        global data_downloadonly
        data_downloadonly = True
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
