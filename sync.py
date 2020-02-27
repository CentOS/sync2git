#! /usr/bin/python2

from __future__ import print_function

import koji as brew
import json
import sys
import git
import os

# Takes 666 years to get the git repo. So ignore this for testing.
skip_kernel = False

def load_package_list():
    return open("packages.txt", "r").read().split("\n")

def get_tagged_builds(brew_proxy, tag):
    """
    Return a list of latest builds that are tagged with certain tag
    """
    return brew_proxy.listTagged(tag, latest=True)

def check_unsynced_builds(tagged_builds, packages_to_track):
    """
    Look for builds that are not synced with centos streams
    """
    unsynced_builds = []

    for build in sorted(tagged_builds, key=lambda x: x['package_name']):
        if skip_kernel and build['package_name'] == 'kernel':
            continue
        if build['package_name'] in packages_to_track:
            print("Pkg: ", build['package_name'])
            os.system("rm -rf /tmp/" + build['package_name'])
            repo = git.Repo.clone_from("https://git.centos.org/rpms/" + build['package_name'] + ".git", "/tmp/" +
            build['package_name'])
           
            tag_to_check = build['nvr']
            new_build = True
            for tag in repo.tags:
                if tag_to_check in str(tag):
                    new_build = False
                    print("Tag: ", tag)
                    print("Build: ", build)
                    print( ("%s is already updated to %s") % (build['package_name'], build['nvr']) )
            if new_build:
                print( ("%s needs to be updated to %s") % (build['package_name'], build['nvr']) )
            unsynced_builds.append(build) # test, move back to above `if` block

    return unsynced_builds

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

def sync_directly(unsycned_builds):
    """
    This is a temporary method to sync by directly uploading rpms to centos repos
    This should be replaced by `sync_through_pub()` function at some point in future
    """
    for build in unsynced_builds:
        print("brew download-build --rpm " + build['nvr'] + ".src.rpm")
        os.system("brew download-build --rpm " + build['nvr'] + ".src.rpm")

    for build in unsynced_builds:
        os.system("alt-src --push c8s " + build['nvr'] + ".src.rpm")

    for build in unsynced_builds:
        print("Removing " + build['nvr'] + ".src.rpm...")
        os.remove(build['nvr'] + ".src.rpm")

local_packages = False
# Badly written but working python script
if __name__ == "__main__":
    # tag = sys.argv[1]
    tag = "rhel-8.2.0-candidate"
    ctag = "dist-c8-stream-compose"

    brew_proxy = brew.ClientSession("http://brewhub.engineering.redhat.com/brewhub/")
    if local_packages:
        packages_to_track = load_package_list()
    else:
        print("Contacting mbox for:", ctag)
        cproxy = brew.ClientSession("https://koji.mbox.centos.org/kojihub/")
        ctagged_builds = get_tagged_builds(cproxy, ctag)
        packages_to_track = [b['package_name'] for b in ctagged_builds]
        # Now filter out the pacakges which are already uptodate in CentOS
        latest = set()
        for build in ctagged_builds:
            latest.add(build['nvr'])
        ntagged = []
        for build in sorted(tagged_builds, key=lambda x: x['package_name']):
            if build['nvr'] in latest:
                print("Already in sync with", build['package_name'])
                continue
            ntagged.append(build)
        tagged_builds = ntagged

    # build = brew_proxy.getTag()
    tagged_builds = get_tagged_builds(brew_proxy, tag)
    # build = brew_proxy.getBuild(sys.argv[1]) # module
    # `nvr` attribute of `tagged_build` contains git tags
    # print(json.dumps(tagged_builds, indent=4, sort_keys=True, separators=[",",":"]))
    unsynced_builds = check_unsynced_builds(tagged_builds, packages_to_track)
    # sync_through_pub(unsynced_builds)
    sync_directly(unsynced_builds)
