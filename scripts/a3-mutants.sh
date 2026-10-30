#!/bin/sh
# Mutants for the account delete tests (slice A3): each breaks one
# guarantee, and the test that covers it must fail. Run on Kiln:
#   kiln checks run --command 'sh scripts/a3-mutants.sh'
set -u
PATH="$PATH:/usr/local/go/bin"
export PATH
: "${GOCACHE:=$PWD/.check-cache/go-build}"
mkdir -p "$GOCACHE"
export GOCACHE
status=0

# mutant NAME FILE SED-EXPR PACKAGE RUN
mutant() {
	name=$1 file=$2 expr=$3 pkg=$4 run=$5
	cp "$file" "$file.orig"
	sed -i "$expr" "$file"
	if cmp -s "$file" "$file.orig"; then
		echo "MUTANT $name: the edit matched nothing"
		status=1
	elif HOPKEY_REQUIRE_SSH=1 sh scripts/with-passwd.sh go test "$pkg" -run "$run" -count=1 >/tmp/mutant.log 2>&1; then
		echo "MUTANT $name: SURVIVED ($run passed)"
		status=1
	else
		echo "MUTANT $name: killed"
		grep -E -e '--- FAIL' -e 'FAIL\b' /tmp/mutant.log | head -4
	fi
	mv "$file.orig" "$file"
}

mutant late-seen internal/server/sqlite.go \
	's|SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM devices WHERE account_id = ? AND device_id = ?)|SELECT ?, ?, ? WHERE ? IS NOT NULL OR ? IS NOT NULL|' \
	./internal/server/ 'TestLateLastSeenAfterDelete'
mutant rows-device-seen internal/server/sqlite.go \
	'/{"device_seen", `account_id = ?`, false},/d' \
	./internal/server/ 'TestDeleteCoversEveryTable|TestDeleteAccount$'
mutant rows-claimed-mailboxes internal/server/sqlite.go \
	'/{"enroll_messages", /d' \
	./internal/server/ 'TestDeleteAccount$'
mutant triggers internal/server/sqlite.go \
	"s|SELECT RAISE(ABORT, 'the ID of a deleted account or vault');|SELECT 1;|" \
	./internal/server/ 'TestDeletedIDsAreNeverReused'
mutant taken internal/server/sqlite.go \
	"s|(SELECT COUNT(\*) FROM deleted_ids WHERE kind IN ('account', 'vault') AND id IN (?, ?))|(SELECT 0 WHERE ? IS NOT NULL OR ? IS NOT NULL)|" \
	./internal/server/ 'TestDeletedIDsAreNeverReused'
mutant fence-commit internal/server/vault.go \
	's|if err := fenceRefusal(tx, accountID); err != nil {|if err := fenceRefusal(tx, accountID); false \&\& err != nil {|' \
	./internal/server/ 'TestDeleteFenceAndCancel'
mutant fence-retire internal/server/retire.go \
	's|if err := fenceRefusal(tx, ch.AccountID); err != nil {|if err := fenceRefusal(tx, ch.AccountID); false \&\& err != nil {|' \
	./internal/server/ 'TestDeleteFenceAndCancel'
mutant enable-fenced internal/server/access.go \
	's|if f, err = tx.DeleteFence(p.AccountID); err == nil && f != nil {|if f, err = tx.DeleteFence(p.AccountID); false \&\& f != nil {|' \
	./internal/server/ 'TestDeleteFenceAndCancel'
mutant deleted-answer internal/server/auth.go \
	's|return errAccountDeleted|return errUnauthorized|' \
	./internal/server/ 'TestDeletedAccountRefusals'
mutant head-moved internal/server/delete.go \
	's|got.VaultID == want.VaultID && got.Head == want.Head &&|got.VaultID == want.VaultID \&\&|' \
	./internal/server/ 'TestDeletePreconditions'
mutant verify-fence internal/server/delete.go \
	's|if at != f.At.Unix() |if false \&\& at != f.At.Unix() |' \
	./internal/server/ 'TestVerifyBackupRefuses'
mutant backup-mode internal/server/sqlite.go \
	's|syscall.O_NOFOLLOW, 0o600)|syscall.O_NOFOLLOW, 0o644)|' \
	./internal/server/ 'TestDeleteAccount$|TestVerifyBackupRefuses'
mutant confirm-email cmd/hop-server/delete.go \
	's#if err != nil || got != want {#if err != nil || len(got) == 0 {#' \
	./cmd/hop-server/ 'TestAccountsDelete$'
mutant client-code internal/syncclient/errors.go \
	's/e.Code == store.AdminAccountDeleted) {/false) {/' \
	./internal/syncclient/ 'TestChallengeAccountDeleted|TestErrorMapping'
mutant status-text internal/cli/cmd_lock.go \
	's|if a.Code == store.AdminAccountDeleted {|if false {|' \
	./internal/cli/ 'TestVaultStateOfAnAdminLock'
mutant logout-text internal/cli/cmd_auth.go \
	's|errors.As(err, &ar) && ar.Code == store.AdminAccountDeleted {|errors.As(err, \&ar) \&\& false {|' \
	./internal/cli/ 'TestLogoutOfADeletedAccount'
mutant why-deleted internal/daemon/revocation.go \
	's|why = whyDeleted|why = whyDisabled|' \
	./internal/daemon/ 'TestDeleteLocksHopSync'
exit $status
