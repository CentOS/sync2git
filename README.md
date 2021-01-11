sync2git
========

This will take a bunch of modules and/or packages from a koji tag, or a
koji compose, and compare against the sources in a CentOS style git
repository ... for newer versions of the modules/packages it will call
[alt-src](https://github.com/release-engineering/alt-src) to sync them.

It can filter modules/packages manually and also optionally call a
CVE checker service to filter embargoed data.

Also has optional, time limited, caching.

Default setup is to sync from internal Red Hat EL8 nightly composes to
[CentOS Stream 8](https://git.centos.org/rpms/centos-release-stream/).

Usage:
    `sync-cron.sh`

Other commands:
 * ./sync2git.py - Take packages from koji tag/compose and sync them to git.
 * * ./sync2git.py force-push-module N:S:V:C - Push without checking CVE.
 * * ./sync2git.py push - Push packages/modules to git (depending on options).
 * ./sync2build.py - Take packages from git and sync them to koji builds.
 * * ./sync2build.py packages
 * * ./sync2build.py modules
 * * ./sync2build.py check-nvr - Check a given NVR against git.
 * * ./sync2build.py check-nvra - Check a given NVRA against git.
 * * ./sync2build.py build-nvr - Build a given NVR from git.
 * * ./sync2build.py build-nvra - Build a given NVRA from git.
 * * ./sync2build.py bpids-list - list koji build tasks
 * * ./sync2build.py bpids-wait - wait for current koji build tasks
 * * ./sync2build.py tag-rpms-hash - Give a hash for the tag, based on all rpms.
 * * ./sync2build.py tag-srpms-hash - Give a hash for the tag, based on srpms.
 * * ./sync2build.py summary-packages - ?
 * * ./sync2build.py list-packages - ?
 * * ./sync2build.py nvra-unsigned-packages - List packages which aren't signed.
 * * ./sync2build.py list-unsigned-packages - List packages which aren't signed.
 * ./compose.py - Get data from a compose.
 * * ./compose.py &lt;compose-base-url>
 * ./access.py - Query CVE checker data
 * * ./access.py -h = Do history lookups, for speed
 * * ./access.py -t &lt;duration> = set the query timeout
 * * ./access.py logs &lt;query-id> = Show the log data for the query id
 * * ./access.py history name[-version[-release]] = Show the history of the n/nvr
 * * ./access.py nvrs nvr... = Query the given NVRs
 * * ./access.py names name... = Query the given NVRs for local pkgs. named
 * * ./access.py names name... = Query the given NVRs for local pkgs. named
 * * ./access.py file-nvrs nvr... = Query all the nvrs in the files
 * ./rpmvercmp.py = rpm version comparison in python
 * * ./rpmvercmp.py &lt;s1> &lt;s2> = compare s1 vs. s2 using rpmvercmp logic
