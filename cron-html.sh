#! /bin/sh -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd $DIR

python2 ./sync2build.py nvra-unsigned-pkgs > unsigned-packages.txt
python2 ./sync2html.py  --from-packages-compose=file:///$(pwd)/latest-RHEL-8.x  output-files
