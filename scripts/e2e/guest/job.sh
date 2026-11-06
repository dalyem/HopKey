#!/bin/bash
# job.sh <name> <cmd...>: run a step detached from the guest agent, which
# waits at most 8 s. The driver polls /var/e2e/jobs/<name>.rc, written
# atomically so a poll never sees part of it.
name=$1; shift
mkdir -p /var/e2e/jobs
rm -f "/var/e2e/jobs/$name.rc"
"$@" >"/var/e2e/jobs/$name.out" 2>&1
echo $? >"/var/e2e/jobs/.$name.rc" && mv "/var/e2e/jobs/.$name.rc" "/var/e2e/jobs/$name.rc"
