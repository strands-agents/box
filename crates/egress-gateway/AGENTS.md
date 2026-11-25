# Egress gateway guidance

Policy reaches this crate through mandatory `EffectInterceptor`; capabilities can mutate or refuse,
never authorize. Keep dependency direction `policy -> egress-gateway -> credentials`.
The root freeze covers this facade.

## Boundary traps

- Decide the host before DNS, then each pinned address before dialing. The decided address must be
  the dialed address. Policy owns metadata-address rules; the gateway's own-listener refusal is a
  separate, exact deny-only guard, not a destination list to grow.
- Bind intercepted HTTP authority to the admitted CONNECT destination. The CONNECT phantom check
  is best-effort because SDKs omit it; the kernel's proxy routing supplies the boundary.
- Keep the `host.box.internal` spelling aligned with Box. Its loopback plaintext credential
  exception requires exact routes and no backend; it does not generalize to arbitrary HTTP hosts.
- Log the pre-mutation `workload_path`, never the credential-bearing rewritten target. Attempts
  carry no secret headers or bodies. Avoid `Debug` on request/header containers.
- Reserve enough header and coalesced-body capacity before copying secrets. Reallocation leaves
  un-wiped prefixes despite `Zeroizing`. `Target::path`/`query` and the CA library's private key
  remain wiping gaps; do not turn partial wiping into a completeness claim.
- Upstream bytes need `ResponseRelease`; `WorkloadResponse::bare` and `refusal` are only for static,
  secret-free gateway responses. Scrub before release, preserving cross-chunk matches and refusing
  encoded bodies the scrubber cannot inspect. After a WebSocket upgrade, bytes pass unscrubbed.
- Keep the upstream deadline through body receipt and downstream backpressure. After downstream
  abandonment, drain upstream within the same runtime and connection slot so the outcome records
  actual completion or failure, not merely the last successful downstream write.
- Preserve both capability pattern checks. Collision detection counts setters, not query strips;
  a strip and add deliberately share a target. Decode query keys before stripping them.
- A WebSocket relay requires a validated handshake and matching `101` response. Keep ordinary
  responses `Connection: close`; hyper's `keep_alive(false)` also disables upgrades. Accept TLS
  on `Upgraded`, retaining hyper's buffered bytes or the early ClientHello disappears.
- Shutdown must self-connect over `BoundTransport`. Reducing it to a TCP port deadlocks `Drop`
  when the listener is an AF_UNIX socket.

## TCP latency

Keep `TCP_NODELAY` on accepted and upstream TCP sockets under the root rule. Historical paired
measurements found about 50 ms extra latency on small HTTPS requests to four Cloudflare origins
and 17 ms to Bedrock without it (macOS release build, four pairs each). On Linux loopback, a stream
emitting every 10 ms delivered its first chunk at about 53 ms without it and 10.5 ms with it
(two passes of 30 requests). These measurements justify the option, not a performance guarantee.

## Verification beyond the root gates

Also build with `--no-default-features` to keep the TLS feature boundary intact, and run rustdoc
with warnings denied. Secret-buffer, response-release, and shutdown tests protect boundaries;
retain them when changing transport plumbing.
