#! /bin/sh -e

# ---------------- Configuration ----------------
# Use this if you just want to test (no alt-src calls)...
downloadonly=--download-only
downloadonly=

#  Where do we want to look for the nightly compose. Used for both packages
# and modules, probably a bad idea to have different ones for each.
nightly_compose=http://download.eng.bos.redhat.com/rhel-8/nightly/RHEL-8/latest-RHEL-8.3/

# If we want to turn off just packages/modules, change these...
packages=--sync-packages
# packages=
modules=--sync-modules
# modules=

# Use this if you want to turn caching off...
nocache=--nocache
nocache=
# ----------------

# Find the dir. this script is in...
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

if [ ! -d logs ]; then
    mkdir logs
fi

fname="logs/$(date --iso=minutes)"

python3 ./sync.py \
  $downloadonly \
  $nocache \
  --packages-compose=$nightly_compose \
  --modules-compose=$nightly_compose \
  $packages \
  $modules \
  > "$fname.out.log" 2> "$fname.err.log"

