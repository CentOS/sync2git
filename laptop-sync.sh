#! /bin/sh -e

rsync="rsync --partial --info=progress2 -a -AX --del -e ssh"
md5="$(md5sum laptop-sync.sh)"

while true; do
  echo Doing RHEL sync.
  uitime
  $rsync composer01.rdu2.centos.org:centos-sync-packages/. .
  if [ "x$(md5sum laptop-sync.sh)" != "x$md5" ]; then
    echo "Rexecing!"
    exec ./laptop-sync.sh
  fi
  ./latest-RHEL-8.x/sync-rhel.sh
  for i in $(seq 10); do
    echo Doing HTML sync.
    uitime
    ssh composer01.rdu2.centos.org ./centos-sync-packages/cron-html.sh
    ./latest-RHEL-8.x/sync-file.sh x
    uitime
    echo Sleeping 15m
    sleep 15m
  done
done
