# Security Policy

## Supported Versions

Strands Box is pre-1.0 and under active development. Security fixes are applied
to the latest `main`.


## What Is a Security Issue

Strands Box confines an agent workload behind an operating system (OS) boundary and an
egress gateway. A bypass of any control the box is meant to enforce is
treated as a security issue, including:

- Reading or writing files beyond a process's direct filesystem grants, or bypassing
  policy when Box performs a file operation on its behalf
- Bypassing network policy on traffic through the egress gateway, or obtaining direct
  outbound access without a declared exception
- Exfiltrating or misrouting an injected credential, including a credential
  reaching a destination other than the credential route that matched it, or
  surviving a redirect to a different host
- Injected credentials appearing in workload-visible surfaces: command output,
  error messages, environment-variable dumps, or the handler payload
- Escaping OS containment (Seatbelt on macOS)
  to reach host resources the box did not grant
- Using symlinks, `..` components, or race conditions to escape a declared
  filesystem grant
- An operator environment variable reaching the workload through unintended inheritance
- Crafted config or handler input that causes the supervisor or a boundary
  crate to panic, hang, or consume unbounded resources


## Out of Scope

The following are explicitly **not** part of the security boundary and will not
be treated as security issues:

- Speculative-execution and side-channel attacks (run each box inside a VM or
  microVM if this is in your threat model)
- Multi-tenant isolation within a single OS process: one box confines one
  workload; run untrusted or multi-tenant code inside a container or microVM as
  well
- A workload reading files or reaching hosts it was explicitly granted (the
  grant is the authority; working as designed)
- Resource consumption within externally configured limits (use controls in the
  surrounding OS to bound workload resource use)


## Reporting Security Issues

Amazon Web Services (AWS) is dedicated to the responsible disclosure of security vulnerabilities.

We kindly ask that you **do not** open a public GitHub issue to report security concerns.

Instead, please submit the issue to the AWS Vulnerability Disclosure Program via [HackerOne](https://hackerone.com/aws_vdp) or send your report via [email](mailto:aws-security@amazon.com).

For more details, visit the [AWS Vulnerability Reporting Page](http://aws.amazon.com/security/vulnerability-reporting/).

Thank you in advance for collaborating with us to help protect our customers.
