#!/bin/sh
# Starts a built hop-server image and checks that it works, before the
# release workflow pushes it.
#
#   sh scripts/image-smoke.sh IMAGE VERSION
#
# VERSION is the release version without the leading v, which the image's
# hop-server must report. The container gets a fresh named volume and a port
# published to loopback only, and both are removed at the end. The invite
# code the check issues is never printed.
set -eu

if [ $# -ne 2 ]; then
	echo "usage: $0 IMAGE VERSION" >&2
	exit 2
fi
image=$1
version=$2
name=hop-smoke-$$
volume=$name-data
err=$(mktemp)

cleanup() {
	docker rm -f "$name" >/dev/null 2>&1 || true
	docker volume rm "$volume" >/dev/null 2>&1 || true
	rm -f "$err"
}
trap cleanup EXIT

fail() {
	echo "smoke: $*" >&2
	if [ -s "$err" ]; then
		echo "--- stderr of the failed command" >&2
		cat "$err" >&2
	fi
	echo "--- docker logs $name" >&2
	docker logs "$name" >&2 || true
	exit 1
}

docker volume create "$volume" >/dev/null
docker run -d --name "$name" -v "$volume:/data" -p 127.0.0.1::8080 "$image" \
	--origin https://hop.test --insecure-http --trusted-proxy 127.0.0.1/32 >/dev/null

# The server runs as the nonroot user the volume is made for.
user=$(docker inspect -f '{{.Config.User}}' "$name")
[ "$user" = 65532:65532 ] || fail "the image runs as '$user', not 65532:65532"

port=$(docker port "$name" 8080/tcp | sed -n 's/^127\.0\.0\.1:\([0-9][0-9]*\)$/\1/p' | head -n 1)
[ -n "$port" ] || fail "no loopback port is published for 8080"

up=
i=0
while [ "$i" -lt 30 ]; do
	[ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || fail "the container stopped"
	if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$port/v1/healthz" 2>"$err"; then
		up=1
		break
	fi
	i=$((i + 1))
	sleep 1
done
[ -n "$up" ] || fail "GET /v1/healthz did not answer 200 within 30 seconds"
: >"$err"

# Writes the database in the volume, as the nonroot user, beside the running
# server. The code goes to /dev/null; the audit line on stderr holds none.
docker exec "$name" hop-server invite smoke@example.com --ttl 1h --data /data >/dev/null 2>"$err" ||
	fail "hop-server invite failed"
: >"$err"
docker exec "$name" hop-server invites ls --data /data 2>"$err" | grep -q smoke@example.com ||
	fail "the invite is not in the database in the volume"
: >"$err"

got=$(docker exec "$name" hop-server version) || fail "hop-server version failed"
[ "$got" = "hop-server $version" ] || fail "hop-server version printed '$got', want 'hop-server $version'"

echo "smoke: $image answers on /v1/healthz, writes its volume as $user, and is hop-server $version"
