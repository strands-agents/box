# Captured Dogwood 1.0.0 migration histories

These fixtures preserve record streams and engine metadata captured from Box using the published `dogwood-language = "=1.0.0"` and `dogwood-local-engine = "=1.0.0"` packages. They exercise explicit migration without building an old dependency during the test suite.

The source baseline was Box commit `a41332d57e409fc7a10b4337501277a1469f987c`. The histories were created on November 13, 2026. Each history records an allowed HTTP request, its 150-byte completed outcome, and a subsequent request denied by a 100-byte budget. The authored macro policy has a generated-name collision in separate scopes; the corrected renderer changes its stored spelling.

| Fixture | Stored state |
| --- | --- |
| `collision.jsonl` | One exhausted HTTP budget rule. |
| `staged.jsonl` | The HTTP budget, a coarse Model Context Protocol (MCP) grant, and an explicit typed-tool forbid. |
| `duplicates.jsonl` | The HTTP budget and two identical file-read rules with separate installed identities. |

`alpha-original.cedarschema` is the exact decoded `append_action_schema.fragment` from record 3 of `staged.jsonl`. Migration uses this original input. The discovery test then uses the current schema generator, whose output can differ even when the raw tool description is unchanged.

The `.jsonl` files contain the complete, unpruned captured records. The `.metadata.json` files contain the two persisted engine settings used by these stores: the timestamp unit and the service schema. None of the captured stores had a snapshot or a Box migration marker. `provenance.json` records hashes and the generating binary identities.

The test loader reconstructs these records with the current storage library. It uniformly shifts record timestamps so the newest is five seconds before the current system clock. It preserves the intervals, ties within policy-operation batches, record order, policy statements, identifiers, tokens, and event fields. It verifies codec round trips and reverses each timestamp shift to check that no other record content changed. It copies the captured metadata exactly and creates no snapshot, so recovery replays the full history.

These are captured-and-retimestamped histories, not freshly generated 1.0.0 stores. The production clock remains unchanged. Separate validation covers genuine old database files and preexisting pruned snapshots. The separate focused endurance validation creates two new automatic checkpoints after migration and checks actual pruning and restart behavior.
