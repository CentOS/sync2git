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
