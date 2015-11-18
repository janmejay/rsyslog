#!/bin/bash
# added 2015-11-13 by singh.janmejay
# This file is part of the rsyslog project, released under ASL 2.0
echo ===============================================================================
echo \[dynstats_node_rehash-vg.sh\]: test for publishing enough stats to same trie-node to cause hash-resize
. $srcdir/diag.sh init
. $srcdir/diag.sh startup-vg dynstats.conf
. $srcdir/diag.sh wait-for-stats-flush 'rsyslog.out.stats.log'
. $srcdir/diag.sh injectmsg-litteral $srcdir/testsuites/dynstats_common_prefix_input
. $srcdir/diag.sh wait-queueempty
. $srcdir/diag.sh content-check "fa 001 0"
. $srcdir/diag.sh content-check "fz 026 0"
. $srcdir/diag.sh msleep 1100 # wait for stats flush
echo doing shutdown
. $srcdir/diag.sh shutdown-when-empty
echo wait on shutdown
. $srcdir/diag.sh wait-shutdown-vg
. $srcdir/diag.sh check-exit-vg
. $srcdir/diag.sh custom-content-check 'fa=1' 'rsyslog.out.stats.log'
. $srcdir/diag.sh custom-content-check 'fz=1' 'rsyslog.out.stats.log'
. $srcdir/diag.sh exit
