#! /usr/bin/python3

"""Sync packages from a dist-git repository to a koji build system.
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
import time
import matchlist
from optparse import OptionParser
import git

if not hasattr(tempfile, 'TemporaryDirectory'):
    class TemporaryDirectory(object):
        """Do it using __del__ as a hack """

        def __init__(self, suffix='', prefix='tmp', dir=None):
            self.name = tempfile.mkdtemp(suffix, prefix, dir)

        def __del__(self):
            shutil.rmtree(self.name)
    tempfile.TemporaryDirectory = TemporaryDirectory

ml_pkgdeny = matchlist.Matchlist()
ml_gitdeny = matchlist.Matchlist()
def load_package_denylist():
    ml_gitdeny.load("conf/sync2build-gittags-denylist.txt")
    ml_pkgdeny.load("conf/sync2build-packages-denylist.txt")


_koji_max_query = 2000
def koji_archpkgs2sigs(kapi, pkgs):
    if len(pkgs) > _koji_max_query:
        for i in range(0, len(pkgs), _koji_max_query):  
            koji_archpkgs2sigs(kapi, pkgs[i:i + _koji_max_query])
        return

    # Get unsigned packages
    kapi.multicall = True
    # Query for the specific key we're looking for, no results means
    # that it isn't signed and thus add it to the unsigned list
    for pkg in pkgs:
        kapi.queryRPMSigs(rpm_id=pkg._koji_rpm_id)

    results = kapi.multiCall()
    for ([result], pkg) in zip(results, pkgs):
        pkg.signed = []
        for res in result:
            if not res['sigkey']:
                continue
            pkg.signed.append(res['sigkey'])
        if len(pkg.signed) == 0:
            pkg.signed = ''
        if len(pkg.signed) == 1:
            pkg.signed = pkg.signed[0]

def koji_pkgs2archsigs(kapi, pkgs):
    if len(pkgs) > _koji_max_query:
        ret = []
        for i in range(0, len(pkgs), _koji_max_query):
            ret.extend(koji_pkgs2archsigs(kapi, pkgs[i:i + _koji_max_query]))
        return ret

    kapi.multicall = True
    for pkg in pkgs:
        kapi.listRPMs(buildID=pkg._koji_build_id)

    ret = []
    results = kapi.multiCall()
    for ([rpms], bpkg) in zip(results, pkgs):
        for rpm in rpms:
            epoch = spkg.epochnum2epoch(rpm['epoch'])
            pkg = spkg.nvr2pkg(rpm['nvr'], epoch=epoch)
            pkg.arch = rpm['arch']
            pkg._koji_rpm_id = rpm['id']
            pkg._koji_build_id = bpkg._koji_build_id
            ret.append(pkg)

    koji_archpkgs2sigs(kapi, ret)
    return ret

def _task_state(info):
    return koji.TASK_STATES[info['state']]

def _pkg_koji_task_state(self):
    if not hasattr(self, '_cached_koji_task_state'):
        tinfo = self._kapi.getTaskInfo(self._koji_task_id)
        # This overwrites the property call
        self._cached_koji_task_state = _task_state(tinfo)
        del self._kapi
    return self._cached_koji_task_state
# This is a hack, so we can continue to use spkg.Pkg() indirectly. Sigh.
spkg.Pkg._koji_task_state = property(_pkg_koji_task_state)

def _koji_buildinfo2pkg(kapi, binfo):
    epoch = spkg.epochnum2epoch(binfo['epoch'])
    pkg = spkg.nvr2pkg(binfo['nvr'], epoch=epoch)
    pkg._koji_build_id = binfo['build_id']
    if 'task_id' in binfo:
        pkg._koji_task_id = binfo['task_id']
        pkg._kapi = kapi
    return pkg

def koji_tag2pkgs(kapi, tag):
    """
    Return a list of latest build packages that are tagged with certain tag
    """
    ret = []
    for rpminfo in kapi.listTagged(tag, inherit=True, latest=True):
        pkg = _koji_buildinfo2pkg(kapi, rpminfo)
        ret.append(pkg)

    return ret

def koji_pkgid2pkgs(kapi, pkgid):
    """
    Return a the build pacakges from a package id
    """
    ret = []
    for binfo in kapi.listBuilds(packageID=pkgid):
        pkg = _koji_buildinfo2pkg(kapi, binfo)
        ret.append(pkg)
    return ret

def _koji_pkg2task_state(kapi, pkg):
    pkgid = kapi.getPackageID(pkg.name)
    for ppkg in koji_pkgid2pkgs(kapi, pkgid):
        if ppkg == pkg:
            return ppkg._koji_task_id, ppkg._koji_task_state
    return None, 'NONE'

def composed_url2pkgs(baseurl):
    """
    Return a list of latest packages that are in the given compose
    """
    import compose

    c = compose.Compose(baseurl)
    cid = c.data_id()
    cstat = c.data_status()
    pdata = c.json_rpms()
    p = compose.packages_from_compose(pdata)
    pb = compose.packages_bin_from_compose(pdata)
    return p, pb, cid, cstat

def composed_url2modules(baseurl):
    """
    Return a list of latest modules that are in the given compose
    """
    import compose

    c = compose.Compose(baseurl)
    cid = c.data_id()
    cstat = c.data_status()
    print('Mod Compose:', cid)
    print(' Status:', cstat)
    mdata = c.json_modules()
    m = compose.modules_from_compose(mdata)
    return compose.dedup_modules(m)

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

# See: https://www.datatables.net
html_header = """\
    <html>
        <head>
   <title>%s</title>
   <script
      src="https://code.jquery.com/jquery-3.3.1.slim.min.js"
      integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo"
      crossorigin="anonymous">
    </script>
    
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.22/css/jquery.dataTables.css">
    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.22/js/jquery.dataTables.js"></script>

        <link rel="dns-prefetch" href="https://fonts.googleapis.com">
            <style>
@import url('https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,700');

body {
	font-family:'Source Sans Pro', sans-serif;
	margin:0;
}

h1,h2,h3,h4,h5,h6 {
	margin:0;
}

td.dtclass {
  display: none;
}

.denied {
    background: orange !important;
    text-decoration: line-through;
}
.error {
    background: red !important;
}
.older {
    background: orange !important;
    text-decoration: overline;
}
.oldtag {
    background: orange !important;
    text-decoration: overline;
}
.done {
}
.nobuild {
    background: lightgrey !important;
}
.missing {
    background: lightgrey !important;
}
.need_build {
    background: lightgreen !important;
}
.need_build_free {
    background: lightgreen !important;
    text-decoration: overline;
}
.need_build_open {
    background: lightgreen !important;
    text-decoration: overline;
}
.need_build_closed {
    background: lightred !important;
    text-decoration: overline;
}
.need_build_canceled {
    background: red !important;
    text-decoration: overline;
}
.need_build_assigned {
    background: lightgreen !important;
    text-decoration: overline;
}
.need_build_failed {
    background: red !important;
}
.need_build_unknown {
    background: red !important;
}
.need_build_manual {
    background: red !important;
}
.push {
    background: lightgreen;
    text-decoration: underline;
}
.sign {
    background: yellow !important;
}
.extra {
    background: lightblue !important;
}

            </style>
        </head>
        <body>
        <a href="unsigned-packages.txt">unsigned nvra</a> <br>
"""

# Again See: https://www.datatables.net

html_table = """\
        <table id="pkgdata" style="compact">
        <thead>
		<tr>
			<th>_cStatus</th>
			<th>Packages</th>
			<th>Status</th>
			<th>Note</th>
		</tr>
        </thead>
        <tbody>
"""

html_footer = """\
        </tbody>
		</table>
        <script>
        $(document).ready(
            function() {
                $('#pkgdata').DataTable(
                    {
                        "paging" : false,
                        "columnDefs": [{
                            "targets" : [0],
                            "visible" : false
                        }],
                        "createdRow" : function(row, data, dataIndex) {
                            $(row).addClass(data[0]);
                        },
                        "order": [[ 1, "asc" ]]
                    }
                );
            }
        );
        </script>
        </body>
    </html>
"""

def html_row(fo, *args, **kwargs):
    lc = kwargs.get('lc')
    if lc is None:
        lc = ''
    links = kwargs.get('links', {})

    # Want this to do nice things both with and without JS.
    fo.write("""\
    <tr class="%s"> <td class="dtclass">%s</td>
""" % (lc,lc))
    for arg in args:
        if arg in links:
            arg = '<a href="%s">%s</a>' % (links[arg], arg)
        fo.write("""\
		<td>%s</td>
""" % (arg,))
    fo.write("""\
	</tr>
""")

# Key:
#  cpkg == compose package
#  bpkg == koji build tag package
#  tpkg == git tag package
def html_main(kapi, fo, cpkgs,cbpkgs, bpkgs,
              filter_pushed=False, filter_signed=False):

    def _html_row(status, **kwargs):
        note = bpkg._html_note
        note = note or cpkg._html_note
        note = note or ""

        # Kind of hacky, but eh...
        if kwargs['lc'] == "need_build":
            tid, state = _koji_pkg2task_state(kapi, cpkg)
            tnote = ""
            if False: pass
            elif state == 'NONE':
                pass # No build yet
            elif state == 'FREE':
                kwargs['lc'] = "need_build_free"
                tnote = "Task (%d) is %s" % (tid, state)
            elif state == 'OPEN':
                kwargs['lc'] = "need_build_open"
                tnote = "Task (%d) is %s" % (tid, state)
            elif state == 'CLOSED':
                kwargs['lc'] = "need_build_closed"
                tnote = "Task (%d) has %s" % (tid, state)
            elif state == 'CANCELED':
                kwargs['lc'] = "need_build_canceled"
                tnote = "Task (%d) was %s" % (tid, state)
            elif state == 'ASSIGNED':
                kwargs['lc'] = "need_build_assigned"
                tnote = "Task (%d) is %s" % (tid, state)
            elif state == 'FAILED':
                kwargs['lc'] = "need_build_failed"
                tnote = "Task (%d) has %s" % (tid, state)
            else:
                kwargs['lc'] = "need_build_unknown"
            if kwargs['lc'] != "need_build":
                if kwargs['lc'] not in stats:
                    stats[kwargs['lc']] = 0
                stats[kwargs['lc']] += 1

            if tid is not None: # A Build has happened.
                if 'links' not in kwargs:
                    kwargs['links'] = {}
                weburl = "https://koji.mbox.centos.org/koji/"
                weburl += "taskinfo?taskID=%d"
                weburl %= tid
                kwargs['links'][cpkg] = weburl

            if not note: # Auto notes based on auto filtering...
                if tnote:
                    note = tnote
                elif spkg._is_rebuild(cpkg):
                    note = "Rebuild"
                elif spkg._is_branch_el8(cpkg):
                    note = "Branch"
                elif spkg._is_module(cpkg):
                    note = "Module"
                if note:
                    if kwargs['lc'] == "need_build":
                        kwargs['lc'] = "need_build_manual"

        html_row(fo, cpkg, status, note, **kwargs)

    pushed = {}
    for bpkg in bpkgs:
        pushed[bpkg.name] = bpkg

    tcoroot = tempfile.TemporaryDirectory(prefix="sync2html-", dir="/tmp")
    corootdir = tcoroot.name + '/'

    fo.write(html_table)
    stats = {'sign' : 0, 'done' : 0, 'push' : 0, 'need_build' : 0, 'denied' : 0,
             'missing' : 0, 'extra' : 0, 'older' : 0, 'oldtag' : 0,
             'nobuild' : 0, 'error' : 0}
    for cpkg in sorted(cpkgs):
        denied = ml_pkgdeny.nvr(cpkg.name, cpkg.version, cpkg.release)

        if cpkg.name not in pushed:
            if denied:
                _html_row("denied", lc="denied")
                stats['denied'] += 1
                continue
            # html_row(fo, cpkg, "MISSING", lc="missing")
            stats['missing'] += 1
            bpkg = cpkg
        else:
            bpkg = pushed[cpkg.name]
            weburl = "https://koji.mbox.centos.org/koji/"
            weburl += "buildinfo?buildID=%d"
            weburl %= bpkg._koji_build_id
            links = {cpkg : weburl}
            if cpkg == bpkg:
                if not filter_signed and not bpkg.signed:
                    _html_row("built not signed", lc="sign",
                              links=links)
                    stats['sign'] += 1
                elif not filter_pushed:
                    _html_row("built and signed", lc="done", links=links)
                    stats['done'] += 1
                continue
            if cpkg < bpkg:
                _html_row("OLDER than build: " + str(bpkg), lc="oldtag",
                          links=links)
                stats['oldtag'] += 1
                continue
            if cpkg > bpkg:
                if denied:
                    sbpkg = " " + str(bpkg)
                    _html_row("autobuild denied:"+ sbpkg, lc="denied")
                    stats['denied'] += 1
                    continue
                # html_row(fo, cpkg, "BUILD needed, latest build: " + str(bpkg), lc="need_build")
            else:
                _html_row("ERROR: " + str(bpkg), lc="error")
                stats['error'] += 1

        # cpkg > bpkg, or no bpkg
        codir = corootdir + bpkg.name
        tpkgs = _tags2pkgs(bpkg2git_tags(bpkg, codir))
        found = False
        for tpkg in reversed(sorted(tpkgs)):
            if tpkg.name != cpkg.name:
                continue
            found = True
            # This is the newest version in git...
            if cpkg < tpkg:
                _html_row("OLDER than git: " + str(tpkg), lc="older")
                stats['older'] += 1
                continue # See if the next oldest is ==
            if cpkg == tpkg:
                if cpkg == bpkg:
                    _html_row("No BUILD", lc="nobuild")
                    stats['nobuild'] += 1
                else:
                    _html_row("BUILD needed, latest build: " + str(bpkg), lc="need_build")
                    stats['need_build'] += 1
                break
            if cpkg > tpkg:
                _html_row("PUSH needed, latest git: " + str(tpkg), lc="push")
                stats['push'] += 1
                break

            _html_row("Error: bpkg: " + str(bpkg) + " tpkg: ", str(tpkg), lc="error")
            stats['error'] += 1
        if not found:
            _html_row("Missing from git", lc="missing")
            stats['missing'] += 1

    if False:
        # Comparing a compose to a tag gives way too many extras...
        del pushed
        composed = {}
        for cpkg in cbpkgs:
            composed[cpkg.name] = cpkg
        for bpkg in sorted(bpkgs):
            if bpkg.name in composed:
                continue
            html_row(fo, bpkg, "extra", "", lc="extra")
            stats['extra'] += 1

    fo.write(html_footer)

    return stats

def _read_note(fname):
    if not os.path.exists(fname):
        return None
    return open(fname).read()

def read_note(basedir, pkg):
    for k in (pkg.nvra, pkg.nvr, pkg.nv, pkg.name):
        note = _read_note(basedir + '/' + k)
        if note is not None:
            return note

    return None

def read_notes(basedir, pkgs):
    for pkg in pkgs:
        pkg._html_note = read_note(basedir, pkg)

def main():
    parser = OptionParser()
    parser.add_option("", "--to-koji-host", dest="koji_host",
                      help="Host to connect to", default="https://koji.mbox.centos.org/kojihub")
    parser.add_option("", "--to-packages-tag", dest="packages_tag",
                      help="Specify package tag to sync2", default="dist-c8-stream")
    parser.add_option("", "--to-modules-tag", dest="modules_tag",
                      help="Specify module tag to sync2", default="dist-c8-stream-module")
    parser.add_option("", "--from-packages-compose", dest="packages_compose",
                      help="Specify package compose to sync", default="http://download.eng.bos.redhat.com/rhel-8/nightly/RHEL-8/latest-RHEL-8.4/")
    parser.add_option("", "--from-modules-compose", dest="modules_compose",
                      help="Specify module compose to sync", default="http://download.eng.bos.redhat.com/rhel-8/nightly/RHEL-8/latest-RHEL-8.4")
    parser.add_option("", "--notes", dest="notes",
                      help="Specify basedir to package notes", default="notes")


    (options, args) = parser.parse_args()

    tkapi = koji.ClientSession(options.koji_host)
    tkapi.ssl_login("/compose/.koji/mbox_admin.pem", None, "/compose/.koji/ca.crt")


    load_package_denylist()

    cpkgs, cbpkgs, cid, cstat = composed_url2pkgs(options.packages_compose)
    bpkgs = koji_tag2pkgs(tkapi, options.packages_tag)
    bpkgs = koji_pkgs2archsigs(tkapi, bpkgs)

    read_notes(options.notes, bpkgs)
    read_notes(options.notes, cpkgs)

    if not args: pass
    elif args[0] in ('packages', 'pkgs'):
        fo.write(html_header % ('All packages: ' + cid,))
        html_main(tkapi, sys.stdout, cpkgs, cbpkgs, bpkgs)
    elif args[0] in ('filtered-packages', 'filtered-pkgs', 'filt-pkgs'):
        fo.write(html_header % ('Filtered packages: ' + cid,))
        html_main(tkapi, sys.stdout, cpkgs, cbpkgs, bpkgs, filter_pushed=True)
    elif args[0] in ('output-files',):
        print("Compose:", cid, cstat)

        # We end up creating stats. inside html generation, so write to
        # /dev/null to collect them first. Sigh.
        fo = open("/dev/null", "w")
        stats = html_main(tkapi, fo, cpkgs, cbpkgs, bpkgs, filter_pushed=False)

        def _prefix(prehtml):
            tmhtml = '<h3> Generated:'
            tmhtml += time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
            prehtml += tmhtml
            pkghtml = '''<table style="width: 60%%;">
            <thead><tr>
            <th>From</th>
            <th>Source Pkgs</th>
            <th>Binary Pkgs</th>
            </tr></thead>
            <tbody>
            <tr><td>RHEL</td><td>%d</td><td>%d</td></tr>
'''
            pkghtml %= (len(cpkgs), len(cbpkgs))
            prehtml += pkghtml

            sbpkgs = [x for x in bpkgs if x.arch == 'src']
            pkghtml = '''
            <tr><td>%s</td><td>%d</td><td>%d</td></tr>
            </tbody>
            </table>
'''
            pkghtml %= (options.packages_tag, len(sbpkgs), len(bpkgs))
            prehtml += pkghtml

            prehtml += '<table><tr>'
            for stat in sorted(stats):
                if stats[stat] == 0:
                    continue
                pkghtml = '<td class="%s">%s Pkgs: %d</td>'
                pkghtml %= (stat, stat, stats[stat])
                prehtml += pkghtml
            prehtml += '</tr></table>'
            return prehtml

        fo = open("all-packages.html", "w")
        prehtml = '<h2><a href="filt-packages.html">All</a> packages: ' +  cid

        fo.write(html_header % ('All packages: ' + cid,))
        fo.write(_prefix(prehtml))
        html_main(tkapi, fo, cpkgs, cbpkgs, bpkgs, filter_pushed=False)

        fo = open("filt-packages.html", "w")
        prehtml = '<h2><a href="all-packages.html">Filtered</a> packages: ' +  cid
        fo.write(html_header % ('Filtered packages: ' + cid,))
        fo.write(_prefix(prehtml))
        html_main(tkapi, fo, cpkgs, cbpkgs, bpkgs, filter_pushed=True)
    else:
        print("Args: filtereed-packages | packages")

# Badly written but working python script
if __name__ == "__main__":
    main()
