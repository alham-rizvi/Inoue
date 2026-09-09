
## Supported versions

This project follows a lightweight semantic versioning policy for CLI releases:

- Stable release tags are in the form `v1.1.0`.
- The current supported release is the latest tag on the default branch.
- Only the latest minor release receives active fixes and security review.

## Valid vulnerability reports

We welcome well-scoped security reports that affect the project as shipped. The following are considered valid report candidates:

- Remote or local command execution that can be triggered from untrusted input.
- Arbitrary file writes or path traversal from CLI arguments or output paths.
- Dangerous deserialization or unsafe shell invocation in the code path.
- Vulnerabilities that allow the tool to exfiltrate secrets or credentials from the local environment.
- Weak TLS handling that can be exploited in a way that affects a production deployment of the scanner.
- Logic errors that create privilege escalation or unsafe automation when running inside CI or automation.

The following are not valid CVE-worthy issues for this project unless they create a concrete impact in the execution environment:

- Normal recon and fingerprinting behavior against a target host. This tool intentionally reaches out to arbitrary public hosts for enumeration.
- Standard use of `verify=False` in a local network testing context without a real MITM condition.
- Generic rate-limit, blocking, or anti-bot responses from third-party services.
- Expected behavior of public endpoint discovery or surface enumeration.

## How to report

Please send a concise report with:

1. The exact vulnerable code path.
2. The input or trigger required to reproduce it.
3. The impact and affected version.
4. Suggested fix or mitigation.

Prefer a private report channel through the maintainer contact for the repository. If no private channel is available, use the GitHub Security Advisory flow.

## Version control and release process

- Releases are tagged with annotated git tags such as `v1.1.0`.
- Security-sensitive fixes should be kept to a small patch release when possible.
- The repository should include a changelog entry before cutting a release.
- `git tag -a vX.Y.Z -m "Release vX.Y.Z"` is the standard format used for publication.



