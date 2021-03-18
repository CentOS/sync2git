#! /bin/sh -e

rsync="rsync --partial --info=progress2 -a -rlptD --del -e ssh"

$rsync composer01.rdu2.centos.org:centos-sync-packages/latest-RHEL-8.x .
$rsync composer01.rdu2.centos.org:centos-sync-packages/logs .
$rsync composer01.rdu2.centos.org:centos-sync-packages/\*.html .
$rsync composer01.rdu2.centos.org:centos-sync-packages/\*.txt .
$rsync composer01.rdu2.centos.org:centos-sync-packages/\*.data . || true

if [ "x$1" != "x" ]; then
$rsync *.html *.txt dell-per930-01.4a2m.lab.eng.bos.redhat.com:/var/www/html/stream/
# ssh dell-per930-01.4a2m.lab.eng.bos.redhat.com restorecon -r /var/www/html/stream/
fi
