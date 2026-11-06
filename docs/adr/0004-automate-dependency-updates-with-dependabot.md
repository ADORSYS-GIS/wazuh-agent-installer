# ADR-0004: Automate Dependency Updates with Dependabot

> We introduce GitHub Dependabot configuration to automate npm package and GitHub Actions workflow updates on defined schedules with pull request limits and cool-down buffers.

## Metadata

| Field             | Value                                              |
| :---------------- | :------------------------------------------------- |
| **Document ID**   | ADR-0004                                           |
| **Status**        | `Accepted`                                         |
| **Date**          | 2026-11-06                                         |
| **Deciders**      | Wazuh maintainers                                  |
| **Governs**       | `.github/dependabot.yml`                           |
| **Amends**        | N/A                                                |
| **Amended by**    | N/A                                                |
| **Supersedes**    | N/A                                                |
| **Superseded by** | N/A                                                |

## Context

The Wazuh Agent Installer repository depends on external software components across two main ecosystems:
1. **Frontend dependencies (npm)**: Dependencies specified in `package.json` for Vite, TypeScript, Prettier, ESLint, and `@tauri-apps/api`.
2. **CI/CD Actions (github-actions)**: GitHub Actions referenced in `.github/workflows/` (`actions/checkout`, `actions/setup-node`, `dtolnay/rust-toolchain`, `tauri-apps/tauri-action`, etc.).

Previously, dependency updates were performed manually or ad-hoc during release cycles. This approach introduces operational risks:
- Critical security vulnerabilities and patch releases in upstream packages may go unaddressed until manual audits occur.
- Outdated GitHub Actions may rely on deprecated Node.js runner runtimes, eventually failing CI workflows.
- Infrequent, large batch updates introduce higher risk of breaking changes compared to frequent, incremental updates.

The organizational standard across actively maintained ADORSYS-GIS Wazuh repositories mandates automated dependency scanning and PR generation, modeled after the reference implementation in `wazuh-cert-oauth2`.

The deciding forces are:
- Minimize exposure to upstream security vulnerabilities.
- Automate routine dependency maintenance without overwhelming maintainers with excessive pull requests.
- Provide predictable update schedules and cool-down periods so CI runs remain stable.
- Maintain alignment across organizational repositories under Epic ADORSYS-GIS/wazuh#2354.

## Decision

We will configure GitHub Dependabot in `.github/dependabot.yml` to track both `npm` and `github-actions`:

1. **Ecosystem Configuration**:
   - `npm`: Scans root `/` directory on a `daily` schedule at `08:00` UTC.
   - `github-actions`: Scans `.github/workflows` on a `weekly` schedule at `08:00` UTC.

2. **Workload and Throttling Limits**:
   - `open-pull-requests-limit: 10`: Restricts active open pull requests per ecosystem to prevent review congestion.
   - `cooldown.default-days: 7`: Implements a 7-day cool-down buffer before opening non-critical update PRs, allowing patch versions to stabilize upstream.

## Options considered

| Option                                              | Verdict  | Why (one line)                                                                    |
| :-------------------------------------------------- | :------- | :-------------------------------------------------------------------------------- |
| Manual dependency updates (status quo)              | Rejected | Infrequent updates accumulate debt and delay critical security patches.           |
| Renovate bot                                        | Rejected | Requires additional third-party app permissions and configuration overhead.       |
| GitHub Dependabot with org convention               | Adopted  | Native GitHub feature, zero external credentials, matches org-wide Wazuh standard.|

## Consequences

**Not part of this decision:** Automatic merging of dependency PRs. All Dependabot PRs must still pass automated CI checks and receive human review before merging.

### Impact

**Benefits**

- Security vulnerabilities and outdated packages are detected and remediated continuously.
- Smaller, incremental version bumps reduce the blast radius and complexity of upgrades.
- Weekly scheduling for GitHub Actions avoids daily workflow noise.
- Cool-down buffers prevent churn from immediate upstream patch revisions.

**Costs**

- Maintainers will periodically review and merge Dependabot pull requests.
- CI runner usage increases due to automated checks on Dependabot PR branches.

**Risks**

- Breaking changes in minor or patch releases could cause CI failures (mitigated by existing test suite and human review requirement).

### Done when

- [x] `.github/dependabot.yml` exists with valid configuration for `npm` and `github-actions`.
- [x] Schedule, PR limits, and cool-down parameters conform to the organizational convention.
- [x] Local CI verification suite (`./run-ci.sh`) passes.
- [x] ADR-0004 is documented and indexed.

### Revisit when

- GitHub introduces native workspace-wide dependency management across repositories.
- Team review capacity requires adjusting `open-pull-requests-limit` or schedule intervals.

## Rollback

To roll back, remove or revert `.github/dependabot.yml`. Dependabot will cease opening new PRs.

## Evidence

| Claim                                                                 | Where                                                          |
| :-------------------------------------------------------------------- | :------------------------------------------------------------- |
| Organization reference convention                                     | `ADORSYS-GIS/wazuh-cert-oauth2/.github/dependabot.yml`         |
| Sub-issue scope definition                                            | `ADORSYS-GIS/wazuh-agent-installer#56`                         |
| Organization epic tracking                                            | `ADORSYS-GIS/wazuh#2354`                                       |

## References

- [GitHub Dependabot Configuration Options](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)
- [ADR template](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/template.md)
- [ADR writing guide](https://github.com/ADORSYS-GIS/wazuh/blob/main/docs/adr/GUIDE.md)

## Solution implementation

| Kind   | Tracking                                                                                                        | Status | What it covers                                       |
| :----- | :-------------------------------------------------------------------------------------------------------------- | :----- | :--------------------------------------------------- |
| Issue  | [ADORSYS-GIS/wazuh-agent-installer#56](https://github.com/ADORSYS-GIS/wazuh-agent-installer/issues/56)          | Open   | Add dependabot configuration to wazuh-agent-installer |
| PR     | [ADORSYS-GIS/wazuh-agent-installer#57](https://github.com/ADORSYS-GIS/wazuh-agent-installer/pull/57)            | Open   | Adds .github/dependabot.yml and ADR-0004             |
