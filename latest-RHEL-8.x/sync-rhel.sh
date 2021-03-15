#! /bin/sh -e

burl="http://download.eng.bos.redhat.com/rhel-8/nightly/RHEL-8/latest-RHEL-8.5/"

curl="curl --progress-bar --compressed --remote-time --location -O"
rsync="rsync --partial --info=progress2 -a -AX --del -e ssh"

cd latest-RHEL-8.x

$curl $burl/COMPOSE_ID
$curl $burl/STATUS

echo "Compose: $(cat COMPOSE_ID) - [$(cat STATUS)]"

cd compose/metadata

$curl $burl/compose/metadata/modules.json
$curl $burl/compose/metadata/rpms.json

cd ../../..
$rsync latest-RHEL-8.x composer01.rdu2.centos.org:centos-sync-packages/
