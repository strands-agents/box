# Legacy HTTP history fixture

These four event records came from the pre-fix sbox-72 reproduction at commit
`0dee080468be21085773d09ad789b8ccc014137c`. The two identical HTTP operations were
both allowed. Their request and response records contain no `requestId`.

The fixture preserves the captured record bytes. The compatibility test decodes
and submits those events into an isolated durable history, which assigns fresh
timestamps. This keeps finite-window checks valid on future runs without changing
any captured event fields or supplying identifiers that were never recorded.

The test then opens the history through Box, checks retained host-based policy
state, adds a new correlated operation, and reopens the mixed history. This proves
field and monitor compatibility. It does not claim that missing old correlations
can be recovered.
