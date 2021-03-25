#! /usr/bin/python

from __future__ import print_function
import os
import sys

import glob

from optparse import OptionParser

def log2stats(logname):
    ret = {'date' : None, 'pkgs' : {}, 'mods' : {'' : {}}}
    fn = os.path.basename(logname)
    ret['date'] = fn[:-len(".out.log")].replace("T", " ").replace("+0000", "Z")

    state = 'beg'
    for line in open(logname):
        if False: pass
        elif state == 'beg':
            if line.startswith("Checking CVEs for packages:"):
                state = 'pkgs'
            continue

        elif state == 'mods':
            if False: pass
            elif line.startswith("Filtered Pkg:"):
                pkg = line[len("Filtered Pkg:"):]
                pkg = pkg.strip()
                pkg = pkg.split(': ')
                ret['mods'][''][pkg[0]] = pkg[1]
            elif line.startswith("Filtered Mod:"):
                mod = line[len("Filtered Mod:"):]
                mod = mod.strip()
                ret['mods'][mod] = ret['mods']['']
                ret['mods'][''] = {}
        elif state == 'pkgs':
            if False: pass
            elif line.startswith("Checking CVEs for modules:"):
                state = 'mods'
            elif line.startswith("Filtered Pkg:"):
                pkg = line[len("Filtered Pkg:"):]
                pkg = pkg.strip()
                pkg = pkg.split(': ')
                ret['pkgs'][pkg[0]] = pkg[1]
        else:
            break
    del ret['mods']['']
    return ret

def stats_subset(superset, subset):
    """ Remove extra pkg/mod data from subset that isn't in superset. """
    npkgs = {}

    for pkg in subset['pkgs']:
        if pkg not in superset['pkgs']:
            continue
        npkgs[pkg] = subset['pkgs'][pkg]

    subset['pkgs'] = npkgs

    nmods = {}
    fmodns = set()
    for mod in superset['mods']:
        modns = mod.rsplit("-", 1)[0]
        fmodns.add(modns)
    for mod in subset['mods']:
        modns = mod.rsplit("-", 1)[0]
        if modns not in fmodns:
            continue
        nmods[mod] = subset['mods'][mod]

    subset['mods'] = nmods
    return subset

def process(logs):
    ret = []
    first = None
    for log in reversed(sorted(logs)):
        if not log.endswith(".out.log"):
            continue
        stats = log2stats(log)
        if first is None:
            first = stats
        else:
            stats = stats_subset(first, stats)
            if not stats['pkgs'] and not stats['mods']:
                break
        ret.append(stats)
    return list(reversed(ret))

def _usage(ec=1):
    print('logdata4sync2git [-h] text|html dir...')
    print('       text  dir')
    print('       html  dir')
    sys.exit(ec)


def output_text(stats, verbose):
    latest = stats[-1]
    if not latest['pkgs'] and len(latest['mods']) == 1:
        print('No packages held by CVE checker.')
        return

    pkgs = set(latest['pkgs'].keys())
    print("Pkgs:")
    for stat in stats:
        for pkg in stat['pkgs']:
            if pkg not in pkgs:
                continue
            print(" %-60s %s" % (pkg, stat['date']))
            if verbose:
                print(" \_ %s" % (latest['pkgs'][pkg],))
            pkgs.remove(pkg)

    print("Mods:")
    fmodns = {}
    for mod in latest['mods']:
        modns = mod.rsplit("-", 1)[0]
        fmodns[modns] = mod
    for stat in stats:
        for mod in stat['mods']:
            modns = mod.rsplit("-", 1)[0]
            if modns not in fmodns:
                continue

            modui = mod
            if not verbose:
                modui = modns
            print(" %-60s %s" % (modui, stat['date']))
            if verbose:
                print(" \_ %s" % (fmodns[modns],))
            for pkg in latest['mods'][fmodns[modns]]:
                print("   %s" % (pkg,))
                if verbose:
                    print("   \_ %s" % (latest['mods'][fmodns[modns]][pkg],))
            del fmodns[modns]

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

td.dtclass, th.dtclass {
  display: none;
}

.tmout {
    background: orange !important;
}
.fail {
    background: red !important;
}
.unknown {
    background: lightred !important;
    text-decoration: line-through;
}
.done {
}

            </style>
        </head>
        <body>
        <h1>%s</h1>
"""

# Again See: https://www.datatables.net
html_table = """\
        <table id="pkgdata" style="compact">
        <thead>
                <tr>
                        <th>Module</th>
                        <th>Package</th>
                        <th>Status</th>
                        <th>Date</th>
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
                        "createdRow" : function(row, data, dataIndex) {
                            $(row).addClass(data[0]);
                        },
                        "order": [[ 3, "asc" ]]
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

def _status(status):
    if False: pass
    elif status.endswith("=!Timeout!"):
        return "Timeout", "tmout"
    elif status.endswith("=False"):
        return "Fail", "fail"
    else:
        return status, "unknown"

def output_html(stats):
    fo = sys.stdout

    latest = stats[-1]
    h = 'CVE checker: ' + latest['date']
    fo.write(html_header % (h, h))

    if not latest['pkgs'] and len(latest['mods']) == 1:
        fo.write('<h3>No packages held by CVE checker.</h3>')
        fo.write(html_footer)
        return

    fo.write(html_table)
    pkgs = set(latest['pkgs'].keys())
    for stat in stats:
        for pkg in stat['pkgs']:
            if pkg not in pkgs:
                continue
            status,lc = _status(latest['pkgs'][pkg])
            html_row(fo, '&lt;BaseOS&gt;', pkg, status, stat['date'], lc=lc)
            pkgs.remove(pkg)

    fmodns = {}
    for mod in latest['mods']:
        modns = mod.rsplit("-", 1)[0]
        fmodns[modns] = mod
    for stat in stats:
        for mod in stat['mods']:
            modui = mod.rsplit("-", 1)[0]
            if modui not in fmodns:
                continue
            for pkg in latest['mods'][fmodns[modui]]:
                status,lc = _status(latest['mods'][fmodns[modui]][pkg])
                html_row(fo, modui, pkg, status, stat['date'], lc=lc)
            del fmodns[modui]
    fo.write(html_footer)

def main():
    parser = OptionParser()
    parser.add_option("-v", "--verbose",
                      help="Print out more info.", default=False, action="store_true")

    (options, args) = parser.parse_args()

    if len(args) < 2:
        _usage()

    logs = sorted(glob.glob(args[1] + '/*.log'))
    stats = process(logs)

    if False: pass
    elif args[0] in ('text', 'txt'):
        output_text(stats, options.verbose)
    elif args[0] in ('html',):
        output_html(stats)

if __name__ == '__main__':
    main()

