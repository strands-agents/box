# Dogwood 1.0.0 history fixture

`history_1_0_0.redb` contains saved history created with Dogwood 1.0.0. The history-version
regression test uses it to verify that the 1.1.2 adapter refuses old history without changing
its policy or event records. It is test input, not a supported conversion format.

The file is copied without changes from
`crates/policy/src/migration/storage/fixtures/old-complete.redb` at commit
`0b5f0e0df4d36fbeb6c6f64a352d37dd2135162a`.

SHA-256: `6f12465faa3632b98599163080fc2605c8cab38d7b6c654766261522d97f16b3`.
