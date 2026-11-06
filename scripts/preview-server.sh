#!/bin/sh
# The dev command in kiln.json: runs hop-server as a Kiln preview, a test
# sync server reachable at https://$PREVIEW_HOSTNAME from the private
# network. Kiln's gateway terminates TLS and forwards plain HTTP to $PORT.
# The database lives in $DATA_DIR, which survives updates and restarts.
set -eu

PATH="$PATH:/usr/local/go/bin"
export PATH
: "${GOCACHE:=$PWD/.check-cache/go-build}"
mkdir -p "$GOCACHE"
export GOCACHE

go build -trimpath -o .bin/hop-server ./cmd/hop-server

data="$DATA_DIR/hop"
mkdir -p "$data"

# Signing up needs an invite. Make one for $HOP_INVITE_EMAIL, once per
# address, and print the code to the preview log.
if [ -n "${HOP_INVITE_EMAIL:-}" ] && [ ! -e "$data/invited-$HOP_INVITE_EMAIL" ]; then
	code=$(.bin/hop-server invite "$HOP_INVITE_EMAIL" --ttl 7d --data "$data")
	echo "hop-server invite code for $HOP_INVITE_EMAIL (valid 7 days): $code"
	: >"$data/invited-$HOP_INVITE_EMAIL"
fi

exec .bin/hop-server serve --listen "0.0.0.0:$PORT" --data "$data" \
	--origin "https://$PREVIEW_HOSTNAME" --insecure-http
