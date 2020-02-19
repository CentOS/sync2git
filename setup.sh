#!/bin/sh

# Run this script as root

set -eux
yum install -y krb5-devel python3-devel python3-pip gcc
pip3 install koji gitpython
# Disable gpg check manually from this repo or add repo signature
# yum-config-manager --add-repo http://download.hosts.prod.upshift.rdu2.redhat.com/rel-eng/repos/eng-rhel-7/x86_64/
# yum install pub-client

yum install -y http://hdn.corp.redhat.com/rhel7-csb-stage/RPMS/noarch/redhat-internal-cert-install-0.1-15.el7.csb.noarch.rpm
yum-config-manager --add-repo http://download-ipv4.eng.brq.redhat.com/rel-eng/RCMTOOLS/rcm-tools-rhel-7-workstation.repo
yum install -y rhpkg

yum install epel-release
yum install python-pip
pip install rpm-py-installer 

# Execute these commands as `centos` user
# pip install alt-src
# pip remove rpm

cp altsrc.conf /etc/
