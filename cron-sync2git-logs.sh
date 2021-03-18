#! /bin/sh -e

# -a but without -o or -g (owner/group)
rsync --partial -rlptD --del \
  /home/centos/centos-sync-packages/logs/* \
  /home/james/sync2git-logs/
