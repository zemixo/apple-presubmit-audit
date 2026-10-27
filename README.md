# Apple App Store Pre-Submit Audit

<img src="https://raw.githubusercontent.com/zemixo/apple-presubmit-audit/main/quiet-orbit-banner.svg" alt="App Store Preflight: Check before you submit. Zemixo pixel robot workshop." width="100%">

[![Tests](https://github.com/zemixo/apple-presubmit-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/zemixo/apple-presubmit-audit/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-2ea44f.svg)](./LICENSE)

A local Python CLI that surfaces potential App Store submission issues before
review: inconsistent metadata, unused permission declarations, incomplete
subscription disclosures, suspicious entitlement state, and project-specific
release risks.

It is a preflight assistant, not an App Review guarantee. The checks combine
[Apple's published guidelines](https://developer.apple.com/app-store/review/guidelines/)
with conservative, submission-derived heuristics.

[Quick start](#quick-start) · [Rules](#machine-readable-rule-catalog) · [CI integration](#github-code-scanning-in-five-minutes) · [Limitations](#limitations)

```text
🔴 MyApp                [passed=24 skipped=0 total=27] blockers=1
   🔴 OFFICIAL 2.3.7 name-length          App Store name too long (34 chars, max 30)
   ⚠️  ADVISORY 3.1.2(c) renewal-disclosure-copy
                                              Heuristic: verify that price, duration,
                                              and renewal terms are clear
   ℹ️  ADVISORY 4.2 minimum-functionality-shape
                                              Heuristic: file counts do not determine
                                              compliance; review the experience
```

The output above is illustrative.

---

## What it checks

The audit combines a baseline rule set with condition-aware checks across
Apple's five review categories and additional engineering checks.

- A baseline set runs for every project; metadata-only findings are treated as
  `not_evaluated` when `--no-asc` supplies no corresponding field.
- Extra checks activate when the project declares permissions, subscriptions,
  accounts, third-party login, CloudKit, AI APIs, a paywall, or other relevant
  features.
- A synthetic coverage fixture exercises the broad conditional catalog; a
  normal project runs only the checks relevant to the signals it exposes.

| Area | Examples |
|---|---|
| Safety | misleading sensor or medical claims, Kids Category advertising |
| Performance | metadata completeness, app-name length, implementation evidence for advertised features |
| Business | subscription disclosure, restore flow, privacy and terms links, purchase-price prominence |
| Design | minimum-functionality and duplicate-app heuristics, Sign in with Apple |
| Legal | privacy policy, account deletion, permissions matched to framework use |
| Custom | StoreKit state, CloudKit save patterns, SwiftData defaults, paywall claims matched to code |

See [`audit.py`](./audit.py) for the implementation of every check.

## Quick start

Install the current source checkout in an isolated environment. This repository
does not claim a package-index release:

```bash
git clone https://github.com/zemixo/apple-presubmit-audit.git
cd apple-presubmit-audit

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

The installed command is `apple-presubmit-audit`. Running `python3 audit.py`
from a checkout remains supported for repository development and for the
composite Action.

Audit one project against App Store Connect metadata:

```bash
apple-presubmit-audit \
  --project ~/Code/MyApp \
  --bundle-id com.example.myapp \
  --key-id ABC123XYZ \
  --issuer-id 12345-67890-... \
  --key-file ~/AuthKey_ABC123XYZ.p8
```

The credentials can also come from environment variables:

```bash
export ASC_KEY_ID=ABC123XYZ
export ASC_ISSUER_ID=12345-67890-...
export ASC_KEY_FILE=~/AuthKey_ABC123XYZ.p8

apple-presubmit-audit --project ~/Code/MyApp --bundle-id com.example.myapp
```

Code-only mode skips App Store Connect. It is useful for local iteration, but
metadata-dependent checks will not have enough information:

```bash
apple-presubmit-audit --project ~/Code/MyApp --no-asc
```

For several apps, copy [`apps.example.json`](./apps.example.json) to `apps.json`
and run:

```bash
apple-presubmit-audit --config apps.json
apple-presubmit-audit --config apps.json --quiet
apple-presubmit-audit --config apps.json --json
apple-presubmit-audit --config apps.json --sarif > audit.sarif
```

Never commit App Store Connect credentials. This repository ignores common
private-key, provisioning-profile, environment, and local app-config files by
default.

## Machine-readable rule catalog

[`rule-catalog.json`](./rule-catalog.json) lists every rule family, its evidence
basis, default severity, and the Apple documentation used as either a direct
requirement or advisory context. Fetch the same document through the CLI
without a project or App Store Connect credentials:

```bash
apple-presubmit-audit --rule-catalog > /tmp/apple-presubmit-rule-catalog.json
```

Dynamic product, permission, benefit, and file-specific findings use `{...}`
templates plus `runtime_id_pattern`. `checked_on` is the date a maintainer
actually opened and verified an Apple source. It is not presented as Apple's
publication or last-updated date. Tests keep the catalog aligned with every
rule helper call and reject non-Apple source domains.

Explain one catalog family from either its template ID or an ID copied from an
audit finding:

```bash
apple-presubmit-audit --explain "OFFICIAL 2.3.7 name-length"
apple-presubmit-audit --explain \
  "READINESS CUSTOM sub-availability-com.example.product"
```

The explanation prints the rule's authority, default severity, trigger,
detection limits, remediation, and source details. It does not load a project,
read an app configuration, or initialize App Store Connect. Unknown or
ambiguous IDs fail closed with exit code 2.

`fixture_coverage` reports family-level emission by the repository's existing
fixtures:

- `baseline` — emitted for an empty temporary project with empty metadata.
- `conditional` — not baseline, but emitted by the synthetic conditional-
  coverage project and metadata.
- `regression` — exercised by a dedicated anonymized `before`/`after` pair in
  [`tests/fixtures/production-regressions`](./tests/fixtures/production-regressions).
- `not-exercised` — covered by none of the fixture classes above.

Baseline and conditional statuses only record emission; they do not claim a
triggering/non-triggering pair or detector correctness. Regression status does
require the named advisory to fail before the reduced project change and pass
after it. The fixture manifest distinguishes reproduced runtime failures from
release-audit findings and does not present either as an App Review rejection.
All values are recalculated from real `audit_app` output in the test suite.

## GitHub Code Scanning in five minutes

Copy
[`examples/github-actions/apple-presubmit-audit.yml`](./examples/github-actions/apple-presubmit-audit.yml)
to `.github/workflows/apple-presubmit-audit.yml` in an Apple project. The
workflow pins every third-party action and the audit source to full commit
SHAs, runs without App Store Connect credentials, uploads SARIF, and then
preserves the CLI exit code.

The repository also exposes a composite action for shorter workflows. Pin it
to the full commit SHA of a release rather than a mutable branch or tag:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: zemixo/apple-presubmit-audit@FULL_RELEASE_COMMIT_SHA
```

Both integrations deliberately use `--no-asc`: no issuer ID, key ID, or private
key is read. Metadata-only checks therefore report `not_evaluated`. For
repeatable offline metadata checks, pass `config_path` to the composite action
and keep non-secret field overrides in the config.

The audit always writes SARIF before returning its status. GitHub Code Scanning
receives the report first; the job then succeeds for exit `0`, fails for
blockers with exit `1`, or fails for invalid input with exit `2`. Public
repositories can use Code Scanning without an Advanced Security license;
private repositories need Code Security enabled for SARIF uploads.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No blocker was detected among the checks that ran |
| `1` | One or more blocker checks failed |
| `2` | Project/config input is invalid, or App Store Connect data could not be fetched safely |

Do not treat exit code `0` as proof that Apple will approve an app.

Configuration failures are written to stderr. With `--json`, stdout remains
valid JSON and includes an `errors` array, so CI callers can distinguish invalid
input from review findings.

In JSON output, `passed` is `true`, `false`, or `null`; `null` is paired with
`"status": "not_evaluated"` and is never counted as a blocker.

`--sarif` emits SARIF 2.1.0 while preserving the same exit codes. Failed
findings become results (`blocker` → `error`, `high` → `warning`, `low` →
`note`); passed and `not_evaluated` rules are omitted. Configuration failures
become tool execution notifications. Run the command from the repository root
when uploading the report to GitHub Code Scanning. Because most checks combine
project-wide code and App Store Connect metadata, SARIF locations point to a
real project file as an explicitly labeled audit anchor, not an exact match
line. If no safe repository-relative project file exists, the finding remains
locationless instead of exposing an absolute local path.

## How to read the findings

Every rule ID starts with its evidence basis:

- `OFFICIAL` — directly validates a field or limit published by Apple, such as
  the [30-character app-name limit](https://developer.apple.com/app-store/review/guidelines/#accurate-metadata),
  a required
  [Support URL](https://developer.apple.com/help/app-store-connect/reference/app-information/platform-version-information/),
  or a published
  [age-rating value](https://developer.apple.com/documentation/appstoreconnectapi/appstoreagerating).
- `READINESS` — directly observes a submission or StoreKit catalog state that
  can prevent the intended release or purchase flow.
- `ADVISORY` — a regex, keyword, typography, file-count, or submission-derived
  heuristic. It is evidence to inspect, not proof of an Apple violation.

Apple does not publish a 200-character minimum for review notes, a 36-point
price-font rule, a minimum number of SwiftUI views, or a mandatory literal
`auto-renewing` CTA phrase. Those checks are therefore labeled `ADVISORY`.

Treat findings as prompts for review:

1. Confirm the relevant guideline and current App Store Connect requirements.
2. Inspect the matched code or metadata.
3. Fix real issues and dismiss false positives with project context.

Severity describes release impact:

- `blocker` — reserved for `OFFICIAL` or directly observed `READINESS` findings.
- `high` — a significant manual-review prompt.
- `low` — a lower-confidence or product-quality prompt.

`ADVISORY` findings are enforced in code and tests to never use `blocker`
severity or hard-requirement wording.

## Limitations

- Swift and plist inspection is regex-based; generated code and dynamic framework
  loading can produce false negatives.
- Some checks are deliberately conservative and can produce false positives.
- The tool does not inspect the final signed binary or screenshots.
- App Store Connect does not expose every review field through its API.
- Apple can change its guidelines and reviewer behavior independently of this
  repository.

Always perform a manual final review.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile audit.py
```

Contributions are welcome. Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before
adding a rule, and include both a triggering fixture and a non-triggering
fixture when possible.

## License

[MIT](./LICENSE)

---

<sub>Made by [Zemixo](https://github.com/zemixo) · Small tools. Made with care.</sub>
