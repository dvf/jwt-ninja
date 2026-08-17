# Security policy

## Supported versions

Security fixes are released for the latest `1.x` release line. Older major and minor release lines are unsupported and should be upgraded before reporting an issue that is already fixed in the latest release.

| Version | Supported |
| --- | --- |
| Latest `1.x` | Yes |
| `<1.0` | No |

Supported releases require a maintained Python version and Django within the bounds declared by the installed package. Dependency security updates may raise the minimum patch release within those bounds.

## Report a vulnerability privately

Do not open a public issue, discussion, or pull request for a suspected vulnerability. Use [GitHub private vulnerability reporting](https://github.com/dvf/jwt-ninja/security/advisories/new) so maintainers can investigate and coordinate a fix without exposing users.

Include, where possible:

- the affected jwtninja version and dependency versions;
- a minimal reproduction or proof of concept;
- the impact and required attacker capabilities;
- relevant configuration, with credentials and personal data removed; and
- any proposed mitigation or embargo constraints.

Maintainers will acknowledge the report through the private advisory, assess affected versions, and coordinate remediation and disclosure there. Please keep the report confidential until a release and advisory are published. Reports made in good faith will not be penalized.

For non-security bugs and support questions, use the public issue tracker. Dependency scanner output without a demonstrated impact on jwtninja may be redirected to the affected upstream project.
