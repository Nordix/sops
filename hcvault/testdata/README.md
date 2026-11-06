# Static CRL test fixtures

This directory holds fixed PEM material used by the static CRL tests in
`../keysource_test.go` (the `*_StaticFixture*` / `TestStaticFixturesSanity`
tests). Unlike the fixtures in `../crl_test.go`, which are generated at runtime
relative to `time.Now()`, these files are committed as-is so the tests run
against known, unchanging input.

## Files

| File                    | Description                                               |
| ----------------------- | --------------------------------------------------------- |
| `static_ca.pem`         | Self-signed CA, `CN=Test Vault Static CA`, serial 1.      |
| `static_leaf.pem`       | Leaf `CN=vault.example.com`, serial 42, signed by the CA. |
| `static_revoked.crl.pem`| Revokes the leaf (serial 42).                             |
| `static_empty.crl.pem`  | Revokes nothing — the happy-path CRL.                     |

All material uses P-256 / ECDSA and a ~100 year validity window, so the
certificates and CRLs do not expire for the practical lifetime of these tests.
The `NextUpdate` of each CRL is likewise far in the future, so
`isCRLCurrentlyValid` treats them as in effect. That window ends in 2126; if
you are reading this close to then, regenerate the fixtures with a fresh one.

## Regenerating / replacing the fixtures

Run [`gen-fixtures.sh`](gen-fixtures.sh); it drives OpenSSL to rebuild all four
files in place and cleans up its intermediates. You can run it from anywhere —
it operates on its own directory.

```sh
./gen-fixtures.sh
```

### Changing the leaf serial

`TestStaticFixturesSanity` and `TestParseCRLs_StaticFixture` assert the leaf
serial is `42`. To use a different one, pass it (in decimal) to the script and
update the `int64(42)` assertions in `../keysource_test.go` to match:

```sh
./gen-fixtures.sh 255
```

### Checking a regenerated fixture

Confirm the CA issued the leaf and the CRL revokes the serial you expect:

```sh
openssl verify -CAfile static_ca.pem static_leaf.pem
openssl crl -in static_revoked.crl.pem -noout -text
```

Then run the tests:

```sh
go test ../ -run 'StaticFixture|TestStaticFixturesSanity' -v
```
