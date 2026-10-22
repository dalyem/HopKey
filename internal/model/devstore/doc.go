// Package devstore is a development-only model.Store that keeps the vault in a
// plaintext JSON file, so the CLI can be tried before the encrypted store
// exists. Its implementation is behind the hopdev build tag and is not part of
// any normal build. Private keys in it are NOT encrypted.
package devstore
