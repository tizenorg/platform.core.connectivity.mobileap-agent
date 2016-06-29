#!/bin/sh
PATH=/bin:/usr/bin:/sbin:/usr/sbin
#
# Tethering module log dump (tethering_dump.sh)
#

# Variables
TETH_DEBUG=$1/tethering
mkdir -p ${TETH_DEBUG}

# copy files
/bin/cp -rf /tmp/dnsmasq.conf /opt/var/lib/misc/* ${TETH_DEBUG}

/usr/sbin/iptables -t nat -L -vv > ${TETH_DEBUG}/iptables_nat.log
/usr/sbin/iptables -L -vv > ${TETH_DEBUG}/iptables_filter.log
