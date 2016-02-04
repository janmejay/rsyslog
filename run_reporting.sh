#!/bin/bash

/bin/bash -c 'while true; do; echo "--------========--------"; ps -xelf; if [ -e tests/discard-rptdmsg-vg.sh.out ] cat tests/discard-rptdmsg-vg.sh.out; cat rsyslog.out.log; fi; sleep 1; done' &
disown
