#! /bin/sh -e

# ---------------- Configuration ----------------
# Use this if you just want to test (no alt-src calls)...
downloadonly=--download-only
downloadonly=

#  Where do we want to look for the nightly compose. Used for both packages
# and modules, probably a bad idea to have different ones for each.
nightly_compose=http://download.eng.bos.redhat.com/rhel-8/nightly/RHEL-8/latest-RHEL-8.5/

# If we want to turn off just packages/modules, change these...
packages=--sync-packages
# packages=
modules=--sync-modules
# modules=
# modules=--summary-modules

# Use this if you want to turn caching off...
nocache=--nocache
nocache=
# ----------------

# Find the dir. this script is in...
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

lockf=sync2git-lock-file.lock
function unlockf {
    rm -f "$lockf"
}

tm=15
while [ -f "$lockf" ]; do
  echo "Now: $(date --iso=minutes)"
  if [ $tm -ge 1920 ]; then
    echo "Exiting."
    exit 1
  fi
  echo "File <$lockf> already EXISTS! Owned by pid: $(cat $lockf)"
  echo " C-c in next $tm seconds or WAIT."
  sleep $tm
  tm=$(($tm*2))
done

echo "$$" > "$lockf"
trap unlockf EXIT



if [ ! -d logs ]; then
    mkdir logs
fi

fname="logs/$(date --iso=minutes)"

python3 ./sync2git.py \
  $downloadonly \
  $nocache \
  --packages-compose=$nightly_compose \
  --modules-compose=$nightly_compose \
  $packages \
  $modules \
  push > "$fname.out.log" 2> "$fname.err.log"

