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
- protect the private key whose public fingerprint is pinned in `.github/release-signing-key.asc`; rotate that key only through a reviewed pull request before signing a release;
- require two-factor authentication for GitHub and PyPI maintainer accounts; and
- keep branch/ruleset bypass lists minimal and review their audit logs.

Review these settings before every release. A green workflow does not prove that external controls are enabled.

## Prepare the release

1. Merge only reviewed changes through `master` and wait for all required CI, CodeQL, Gitleaks, and dependency-audit checks.
2. Confirm `uv lock --check` and `uv sync --frozen --all-groups --all-extras` succeed from a clean checkout.
3. Run formatting, linting, type checks, tests, both frozen dependency audits, and the package checks documented in CI.
4. Review the release draft and confirm its semantic version is unused on both GitHub and PyPI. Versions and tags are permanent and must never be reused.
5. From the exact reviewed commit on `master`, create a signed, annotated tag:

   ```console
   git switch master
   git pull --ff-only
   git status --short
   git tag -s -a vX.Y.Z -m "jwtninja X.Y.Z"
   git verify-tag vX.Y.Z
   git push origin vX.Y.Z
   ```

   The signature must use the repository-authorized GPG key with fingerprint `B997 F709 7601 BA66 7004 F07B 230D B77D F266 ACAA`. The workflow imports only `.github/release-signing-key.asc` and rejects every other signer. Rotate the pinned key and fingerprint through a reviewed pull request before using a replacement; SSH signatures are not accepted by the current fail-closed workflow.

6. Verify on GitHub that the tag is marked verified, is annotated, points at the intended reviewed commit, and is covered by the protected tag ruleset.
7. Publish the GitHub Release for that existing tag. Do not allow release tooling to create or retarget the tag.

Never move or delete a published tag, rebuild under an existing version, or reuse a version after any artifact has been exposed. Correct mistakes with a new version.

## Review the build and approve publishing

The release workflow checks out the released tag, resolves its exact annotated-tag object SHA, requires GitHub's Git Data API to report that object's signature as verified, locally verifies it against the repository-pinned GPG key and exact authorized fingerprint, checks ancestry and the target commit, derives the package version from that exact tag, and builds with locked, pinned backends without build isolation. The unprivileged build job then:

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
