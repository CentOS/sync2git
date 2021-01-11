#! /bin/sh -e

# Find the dir. this script is in...
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

lockf=sync2git-lock-file.lock
function unlockf {
    rm -f "$lockf"
}

tm=60
while [ -f "$lockf" ]; do
  echo "Now: $(date --iso=minutes)"
  echo "File <$lockf> already EXISTS! Owned by pid: $(cat $lockf)"
  echo " C-c in next $tm seconds or WAIT."
  sleep $tm
done

echo "$$" > "$lockf"
trap unlockf EXIT



if [ ! -d logs ]; then
    mkdir logs
fi

fname="logs/$(date --iso=minutes)"

python2 ./sync2build.py \
  packages > "$fname.out.log" 2> "$fname.err.log"

