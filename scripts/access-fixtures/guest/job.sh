#!/bin/sh
# job.sh NAME CMD...: run a step detached from the guest agent, which waits
# at most 8 s. run.sh polls /var/hkfx/jobs/NAME.rc, written atomically.
name=$1
shift
mkdir -p /var/hkfx/jobs
rm -f "/var/hkfx/jobs/$name.rc"
"$@" >"/var/hkfx/jobs/$name.out" 2>&1
echo $? >"/var/hkfx/jobs/.$name.rc" && mv "/var/hkfx/jobs/.$name.rc" "/var/hkfx/jobs/$name.rc"
