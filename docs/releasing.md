# Releasing

Releases are built once in GitHub Actions and published to PyPI with OpenID Connect trusted publishing. Maintainers must not upload locally built distributions or use a long-lived PyPI API token.

## One-time external configuration

Repository and package administrators must configure controls that workflow code cannot enforce:

- require pull requests, required CI/security checks, review, and conversation resolution on `master`; prevent force pushes and deletion;
- create a tag ruleset for `v*` that restricts creation and updates to release maintainers and prevents deletion or movement;
- enable immutable GitHub Releases;
- enable GitHub secret scanning, push protection, and private vulnerability reporting;
- protect the GitHub Actions `pypi` environment with required reviewers and restrict it to protected release tags;
- configure the PyPI trusted publisher tuple exactly as repository `dvf/jwt-ninja`, workflow `publish.yml`, environment `pypi`;
- require two-factor authentication for GitHub and PyPI maintainer accounts; and
- keep branch/ruleset bypass lists minimal and review their audit logs.

Review these settings before every release. A green workflow does not prove that external controls are enabled.

## Prepare the release

1. Merge only reviewed changes through `master` and wait for all required CI, CodeQL, Gitleaks, and dependency-audit checks.
2. Confirm `uv lock --check` and `uv sync --frozen --all-groups --all-extras` succeed from a clean checkout.
3. Run formatting, linting, type checks, tests, both frozen dependency audits, and the package checks documented in CI.
4. Review the release draft and confirm its semantic version is unused on both GitHub and PyPI. Versions and tags are permanent and must never be reused.
5. Publish the release draft from the GitHub UI. Release Drafter computes the version from PR labels (`breaking-change` → major, `feature` → minor, `fix`/`maintenance` → patch) and creates the `vX.Y.Z` tag at the head of `master` when the draft is published. Do not create or push tags by hand.

Never move or delete a published tag, rebuild under an existing version, or reuse a version after any artifact has been exposed. Correct mistakes with a new version.

## Review the build and approve publishing

The release workflow requires the publishing actor to be the authorized maintainer account, checks out the released tag, checks that it matches the release commit and is an ancestor of `master`, derives the package version from that exact tag, and builds with locked, pinned backends without build isolation. The unprivileged build job then:

- builds one wheel and one source distribution exactly once;
- runs strict `twine check`;
- verifies wheel name/version metadata;
- verifies tests are absent from the wheel and retained in the source distribution;
- installs and imports the exact wheel outside the checkout; and
- writes and verifies `SHA256SUMS` before uploading an immutable workflow artifact retained for 90 days.

Before approving the protected `pypi` environment, download the workflow artifact and compare every digest with the `SHA256SUMS` printed by the build job:

```console
sha256sum --check SHA256SUMS
python -m zipfile --list jwtninja-*.whl
python -m tarfile --list jwtninja-*.tar.gz
```

Confirm there are exactly three files: one wheel, one source distribution, and `SHA256SUMS`. Inspect wheel metadata and contents, and confirm the wheel contains no `jwt_ninja/tests/` paths. Compare the tag, commit, package version, filenames, and release notes.

An unprotected `attest` job independently downloads and verifies the artifact before creating build-provenance attestations; it has no `pypi` environment. After approval, the separate `publish` job independently downloads and verifies the exact artifact again, then runs `uv publish --trusted-publishing always`. Only that job has the protected `pypi` environment. Neither job checks out source or rebuilds.

## After publishing

- Compare the PyPI wheel and source-distribution SHA-256 digests with the reviewed workflow artifact.
- Confirm PyPI metadata, version, and project links.
- Confirm GitHub artifact attestations verify for both distributions.
- Smoke-install from PyPI in a new environment without the repository on `PYTHONPATH`.
- Keep the GitHub Release and tag immutable. If verification fails, stop distribution where possible, disclose as appropriate, and issue a new version rather than changing the existing one.
