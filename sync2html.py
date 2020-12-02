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
            pkg = spkg.nvr2pkg(rpm['nvr'])
            if rpm['epoch'] is not None:
                pkg.epoch = str(rpm['epoch'])
            pkg.arch = rpm['arch']
            pkg._koji_rpm_id = rpm['id']
            pkg._koji_build_id = bpkg._koji_build_id
            ret.append(pkg)

    koji_archpkgs2sigs(kapi, ret)
    return ret

def koji_tag2pkgs(kapi, tag, signed=False):
    """
    Return a list of latest builds that are tagged with certain tag
    """
    ret = []
    for rpminfo in kapi.listTagged(tag, latest=True):
        pkg = spkg.nvr2pkg(rpminfo['nvr'])
        if rpminfo['epoch'] is not None:
            pkg.epoch = str(rpminfo['epoch'])
        pkg._koji_build_id = rpminfo['build_id']
        ret.append(pkg)

    if signed:
        ret = koji_pkgs2archsigs(kapi, ret)

    return ret

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

# See: https://codepen.io/nathancockerill/pen/OQyXWb
html_header = """\
    <html>
        <head>
            <style>
@import url('https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,700');

$base-spacing-unit: 24px;
$half-spacing-unit: $base-spacing-unit / 2;

$color-alpha: #1772FF;
$color-form-highlight: #EEEEEE;

*, *:before, *:after {
	box-sizing:border-box;
}

body {
	padding:$base-spacing-unit;
	font-family:'Source Sans Pro', sans-serif;
	margin:0;
}

h1,h2,h3,h4,h5,h6 {
	margin:0;
}

.container {
	max-width: 1000px;
	margin-right:auto;
	margin-left:auto;
	display:flex;
	justify-content:center;
	align-items:center;
	min-height:100vh;
}

.table {
	width:100%;
	border:1px solid $color-form-highlight;
}

.table-header {
	display:flex;
	width:100%;
	background:#000;
	padding:($half-spacing-unit * 1.5) 0;
}

.table-row {
	display:flex;
	width:100%;
	padding:($half-spacing-unit * 1.5) 0;
	
	&:nth-of-type(odd) {
		background:$color-form-highlight;
	}
}

.table-row.denied {
    background: orange;
    text-decoration: line-through;
}
.table-row.error {
    background: red;
}
.table-row.older {
    background: orange;
    text-decoration: overline;
}
.table-row.done {
}
.table-row.need_build {
    background: lightgreen;
    text-decoration: overline;
}
.table-row.need_push {
    background: lightgreen;
    text-decoration: underline;
}
.table-row.need_signing {
    background: yellow;
}
.table-row.missing {
    background: lightgreen;
}
.table-row.extra {
    background: lightblue;
}

.table-data, .header__item {
	flex: 1 1 20%;
	text-align: left;
}

.header__item {
	text-transform:uppercase;
}

.filter__link {
	color:white;
	text-decoration: none;
	position:relative;
	display:inline-block;
	padding-left:$base-spacing-unit;
	padding-right:$base-spacing-unit;
	
	&::after {
		content:'';
		position:absolute;
		right:-($half-spacing-unit * 1.5);
		color:white;
		font-size:$half-spacing-unit;
		top: 50%;
		transform: translateY(-50%);
	}
	
	&.desc::after {
		content: '(desc)';
	}

	&.asc::after {
		content: '(asc)';
	}
	
}
            </style>
            <script type="text/javascript">
var properties = [
	'name',
	'wins',
	'draws',
	'losses',
	'total',
];

$.each( properties, function( i, val ) {
	
	var orderClass = '';

	$("#" + val).click(function(e){
		e.preventDefault();
		$('.filter__link.filter__link--active').not(this).removeClass('filter__link--active');
  		$(this).toggleClass('filter__link--active');
   		$('.filter__link').removeClass('asc desc');

   		if(orderClass == 'desc' || orderClass == '') {
    			$(this).addClass('asc');
    			orderClass = 'asc';
       	} else {
       		$(this).addClass('desc');
       		orderClass = 'desc';
       	}

		var parent = $(this).closest('.header__item');
    		var index = $(".header__item").index(parent);
		var $table = $('.table-content');
		var rows = $table.find('.table-row').get();
		var isSelected = $(this).hasClass('filter__link--active');
		var isNumber = $(this).hasClass('filter__link--number');
			
		rows.sort(function(a, b){

			var x = $(a).find('.table-data').eq(index).text();
    			var y = $(b).find('.table-data').eq(index).text();
				
			if(isNumber == true) {
    					
				if(isSelected) {
					return x - y;
				} else {
					return y - x;
				}

			} else {
			
				if(isSelected) {		
					if(x < y) return -1;
					if(x > y) return 1;
					return 0;
				} else {
					if(x > y) return -1;
					if(x < y) return 1;
					return 0;
				}
			}
    		});

		$.each(rows, function(index,row) {
			$table.append(row);
		});

		return false;
	});

});
            </script>
        </head>
        <body>
"""

# filter__link--number for build ids?

html_table = """\
        <div class="table">
		<div class="table-header">
			<div class="header__item"><a id="pkg" class="filter__link" href="#">Packages</a></div>
			<div class="header__item"><a id="pushed" class="filter__link" href="#">Pushed</a></div>
		</div>
        <div class="table-content">
"""

html_footer = """\
		</div>
		</div>
        </body>
    </html>
"""

def html_row(fo, *args, **kwargs):
    lc = kwargs.get('lc')
    if lc is None:
        lc = ''
    else:
        lc = " " + str(lc)
    links = kwargs.get('links', {})

    fo.write("""\
    <div class="table-row%s">
""" % (lc,))
    for arg in args:
        if arg in links:
            arg = '<a href="%s">%s</a>' % (links[arg], arg)
        fo.write("""\
		<div class="table-data">%s</div>
""" % (arg,))
    fo.write("""\
	</div>
""")

def html_main(fo, cpkgs,cbpkgs, bpkgs, filter_pushed=False, filter_signed=False,
              prefix=None):
    fo.write(html_header)

    if prefix:
        prefix(fo)

    pushed = {}
    for bpkg in bpkgs:
        pushed[bpkg.name] = bpkg

    tcoroot = tempfile.TemporaryDirectory(prefix="sync2html-", dir="/tmp")
    corootdir = tcoroot.name + '/'

    fo.write(html_table)
    stats = {'sign' : 0, 'done' : 0, 'push' : 0, 'build' : 0, 'denied' : 0,
             'missing' : 0, 'extra' : 0, 'git-old' : 0, 'tag-old' : 0,
             'error' : 0}
    for cpkg in sorted(cpkgs):
        denied = ml_pkgdeny.nvr(cpkg.name, cpkg.version, cpkg.release)

        if cpkg.name not in pushed:
            if denied:
                html_row(fo, cpkg, "denied", lc="denied")
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
                    html_row(fo, cpkg, "pushed not signed", lc="need_signing",
                             links=links)
                    stats['sign'] += 1
                elif not filter_pushed:
                    html_row(fo, cpkg, "pushed and signed", lc="done",
                             links=links)
                    stats['done'] += 1
                continue
            if cpkg < bpkg:
                html_row(fo, cpkg, "OLDER than build: " + str(bpkg), lc="older",
                         links=links)
                stats['tag-old'] += 1
                continue
            if cpkg > bpkg:
                if denied:
                    sbpkg = " " + str(bpkg)
                    html_row(fo, cpkg, "autobuild denied:"+ sbpkg, lc="denied")
                    stats['denied'] += 1
                    continue
                # html_row(fo, cpkg, "BUILD needed, latest build: " + str(bpkg), lc="need_build")
            else:
                html_row(fo, cpkg, "ERROR: " + str(bpkg), lc="error")
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
                html_row(fo, cpkg, "OLDER than git: " + str(tpkg), lc="older")
                stats['git-old'] += 1
                continue # See if the next oldest is ==
            if cpkg == tpkg:
                if cpkg == bpkg:
                    html_row(fo, cpkg, "BUILD needed, no build", lc="need_build")
                else:
                    html_row(fo, cpkg, "BUILD needed, latest build: " + str(bpkg), lc="need_build")
                stats['build'] += 1
                break
            if cpkg > tpkg:
                html_row(fo, cpkg, "PUSH needed, latest git: " + str(tpkg), lc="need_push")
                stats['push'] += 1
                break

            html_row(fo, cpkg, "Error: bpkg: " + str(bpkg) + " tpkg: ", str(tpkg), lc="error")
            stats['error'] += 1
        if not found:
            html_row(fo, cpkg, "PUSH needed, not in git", lc="missing")
            stats['push'] += 1

    if False:
        # Comparing a compose to a tag gives way too many extras...
        del pushed
        composed = {}
        for cpkg in cbpkgs:
            composed[cpkg.name] = cpkg
        for bpkg in sorted(bpkgs):
            if bpkg.name in composed:
                continue
            html_row(fo, bpkg, "extra", lc="extra")
            stats['extra'] += 1

    fo.write(html_footer)

    return stats

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


    (options, args) = parser.parse_args()

    tkapi = koji.ClientSession(options.koji_host)
    tkapi.ssl_login("/compose/.koji/mbox_admin.pem", None, "/compose/.koji/ca.crt")


    load_package_denylist()

    cpkgs, cbpkgs, cid, cstat = composed_url2pkgs(options.packages_compose)
    bpkgs = koji_tag2pkgs(tkapi, options.packages_tag, True)

    if not args: pass
    elif args[0] in ('packages', 'pkgs'):
        html_main(sys.stdout, cpkgs, cbpkgs, bpkgs)
    elif args[0] in ('filtered-packages', 'filtered-pkgs', 'filt-pkgs'):
        html_main(sys.stdout, cpkgs, cbpkgs, bpkgs, filter_pushed=True)
    elif args[0] in ('output-files',):
        print("Compose:", cid, cstat)

        fo = open("all-packages.html", "w")
        prehtml = '<h2><a href="filt-packages.html">All</a> packages: ' +  cid
        pkghtml = '<p>RHEL Packages: %d (%d bin packages)'
        pkghtml %= (len(cpkgs), len(cbpkgs))
        prehtml += pkghtml
        sbpkgs = [x for x in bpkgs if x.arch == 'src']
        pkghtml = '<p>%s Packages: %d (%d bin packages)'
        pkghtml %= (options.packages_tag, len(sbpkgs), len(bpkgs))
        prehtml += pkghtml
        pre = lambda x: x.write(prehtml)
        stats = html_main(fo, cpkgs, cbpkgs, bpkgs, filter_pushed=False, prefix=pre)

        fo = open("filt-packages.html", "w")
        prehtml = '<h2><a href="all-packages.html">Filtered</a> packages: ' +  cid
        for stat in sorted(stats):
            if stats[stat] == 0:
                continue
            pkghtml = '<p>%s Packages: %d'
            pkghtml %= (stat, stats[stat])
            prehtml += pkghtml

        pre = lambda x: x.write(prehtml)
        html_main(fo, cpkgs, cbpkgs, bpkgs, filter_pushed=True, prefix=pre)
    else:
        print("Args: filtereed-packages | packages")

# Badly written but working python script
if __name__ == "__main__":
    main()
