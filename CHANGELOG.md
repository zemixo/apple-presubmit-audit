# Changelog

> Entries below `Unreleased` preserve the behavior and terminology of their
> original release. They are historical records, not current App Store guidance;
> later corrections and the current README/source take precedence.

## [Unreleased]

### Added

- Deterministic triggering and non-triggering fixtures for the seven previously
  unexercised sign-in, notification, URL, account, CloudKit, and AI-request rule
  families. URL probes use test doubles; no live service or production-schema
  verification is implied.
- Standard-library regression tests for the baseline and conditional rule sets.
- GitHub Actions coverage on Python 3.10 and 3.14.
- A dependency manifest for local setup and CI.
- Explicit `OFFICIAL`, `READINESS`, and `ADVISORY` evidence labels on every
  emitted rule, with a runtime and test invariant that advisories never block.
- Sanitized, structured failures for App Store Connect authentication, network,
  rate-limit, HTTP, and response-format errors.
- Explicit `not_evaluated` results for metadata checks in `--no-asc` mode,
  instead of reporting unavailable metadata as passed.
- SARIF 2.1.0 output via `--sarif`, including stable rule IDs, severity levels,
  durable app fingerprints, project-anchor locations, and structured
  configuration-error notifications.
- A credential-free composite GitHub Action and copyable, SHA-pinned workflow
  that upload SARIF before preserving audit exit status.
- A runner-level smoke job that executes the local composite Action and verifies
  its exit-code and SARIF outputs.
- A machine-readable `rule-catalog.json` and `--rule-catalog` CLI output with
  every rule family, official Apple source links, honest source-check dates,
  and test-derived fixture-emission status.
- Three anonymized `before`/`after` regression fixtures for CloudKit repeated
  saves, CloudKit empty states, and filesystem export errors, with explicit
  evidence levels that avoid claiming an App Review rejection.
- `--explain RULE_ID` for a credential-free, project-free explanation of one
  static, template, or emitted finding, backed by catalog trigger, limit,
  remediation, and source metadata.
- PEP 517 wheel and source distributions for installing the audit as the
  `apple-presubmit-audit` command from a checkout, with the rule catalog
  packaged beside the audit module. No package-index release is implied.
- `--version` output that reports installed distribution metadata, or `source`
  when running `audit.py` directly from a checkout.

### Changed

- Documented Python 3.10 as the supported minimum.
- Clarified that the catalog includes condition-triggered heuristic families and
  that metadata-only findings are not failures in `--no-asc` mode.
- Clarified severity language and the limits of CI exit codes.
- Versioned the rule catalog schema to v2 for per-family trigger, detection-limit,
  and remediation explanations.
- Reclassified regex, keyword, file-count, typography, and rejection-derived
  checks as non-blocking advisories, even when they help inspect an official
  guideline.
- Replaced the fixed `auto-renewing` CTA assertion with a renewal-disclosure
  advisory; Apple asks for clear subscription information but does not prescribe
  that literal CTA phrase.
- Replaced the 36-point price assertion, 200-character review-note assertion,
  exact plist/ASC-name assertion, and minimum-view thresholds with clearly
  labeled advisories.
- Updated accepted App Store age-rating values to the current published
  `AppStoreAgeRating` enumeration, including 13+, 16+, and 18+.
- Limited the release-notes advisory to Apple's published 4,000-character
  What's New limit; emoji are no longer treated as categorically invalid.
- Changed URL HEAD probes and static account/privacy/StoreKit/CloudKit scans
  from blockers to advisories because those probes cannot prove a violation.
- Updated first-IAP guidance to Apple's
  [current submission workflow](https://developer.apple.com/help/app-store-connect/manage-submissions-to-app-review/submit-an-in-app-purchase/):
  direct submissions are supported, while the first item of each type is
  submitted with a new app version.

### Fixed

- Notification opt-in checks now use matched Swift content rather than matching
  file names, so ordinary `NotificationManager.swift` files are checked too.
- Made missing, non-directory, unreadable, and malformed CLI inputs fail
  consistently with exit code 2 and structured `--json` errors.
- Resolved project paths before deriving report names, so `--project .` no
  longer produces a blank app name.
- Added retry and timeout handling for App Store Connect requests.
- Reduced false positives in permission, paywall-benefit, legal-link, and custom
  view detection.
- Allowed batch-config entries to provide metadata overrides for reproducible
  offline audits.
- Rejected duplicate app names in batch configs instead of silently replacing
  an earlier app's results.

## [0.5.2] - 2026-04-24

### Added — `release-notes-asc-compatible` (1 new rule)

- **CUSTOM `release-notes-asc-compatible`** — scans `fastlane/metadata/*/release_notes.txt`,
  `metadata/*/release_notes.txt`, and the topmost block of `CHANGELOG.md` for
  characters that ASC `whatsNew` field rejects.

  **Detected violations**:
  - **Any emoji** (✅ ⚠️ 🎉 🔧 💡 🚀 etc.) — triggers `409 INVALID_CHARACTERS`
    on PATCH `/v1/appStoreVersionLocalizations`
  - **Length >4000 chars** — silently truncates / rejects

  **Why this exists**: real failure during a v1.0.10 submission. Release notes
  contained `✅ 已同步到 iCloud` — ASC API returned `409` with detail
  `"can't contain the following character(s): ✅."`. Wasted 4 round-trips
  (withdraw → patch fail → resubmit → withdraw → patch fail → bisect → fix).

  **Fix**: use plain text + Chinese punctuation `「」 ，。：；！？`. Apple's
  changelog field is text-only, no emoji even though they render fine in display.

## [0.5.1] - 2026-04-24

### Added — `empty-state-vs-error-state` (1 new rule, 7 framework variants)

- **CUSTOM `empty-state-vs-error-state`** — flags any Swift file that fetches
  from an external source (CloudKit / HealthKit / PhotoLibrary / EventKit /
  Network / FileSystem / Core Data) and surfaces ANY error verbatim to a
  UI-bound string via `errorMessage = error.localizedDescription`, without
  a branch handling the legitimate "no data yet" empty case.

  **Why this rule exists**: a recurring class of UX bug invisible to:
  - Apple Review (UX is not a reject criterion, only crashes are)
  - Static linters (no runtime semantics)
  - Happy-path QA (testers usually have data)

  Result: real users see raw codes like `CKError ... Record not found`,
  `HKError no data available`, `URLError 404` instead of friendly empty-state
  copy. Catching it pre-submit is the only place this gets caught early.

  Fix: add a typed catch for the "not found / empty / denied" case before
  the generic catch:
  ```swift
  } catch let ckErr as CKError where ckErr.code == .unknownItem {
      message = "No backup yet — sync first to create one."
  } catch { errorMessage = error.localizedDescription }
  ```

  Same pattern works for `HKError`, `PHAuthorizationStatus`, `URLError`,
  filesystem `fileDoesNotExist`, Core Data empty `fetchedObjects`, etc.

## [0.5.0] - 2026-04-23

### Added — 24 lessons from a multi-app audit-and-fix cycle

After a single audit cycle that touched a batch of in-store apps, `v0.5.0`
codifies every new pitfall into automated checks. The cycle found dozens of
P0 issues — all would have been caught earlier by the new rules below.

**Paywall benefit cross-checks (12 categories):**

- `paywall-benefit-pdf_export` — claims PDF export but no PDFKit / UIGraphicsPDFRenderer code
- `paywall-benefit-calendar_export` — claims calendar export/sync but no EventKit code
- `paywall-benefit-photo_attach` — claims photo attachment but no PhotosPicker / UIImagePickerController code
- `paywall-benefit-charts` — claims "detailed charts/trends" but no Swift Charts code
- `paywall-benefit-themes` — claims "color themes/skins" but no theme enum / @AppStorage theme code
- `paywall-benefit-multi_x` — claims "multi-kit/multi-budget/multi-X management" but no kit-switching code
- `paywall-benefit-voice_guidance` — claims voice guidance but no AVSpeechSynthesizer code
- `paywall-benefit-double_elimination` — claims double elimination bracket but no loser-bracket generation code
- `paywall-benefit-icloud_sync` — claims iCloud sync/backup but no CKContainer / Ubiquity code (extended)
- `paywall-benefit-csv_export` — claims CSV export but no CSV writing code (improved pattern)
- `paywall-benefit-unlimited_gate` — claims "unlimited" but no free-limit gating
- `paywall-benefit-notification` — claims reminders but no UNUserNotificationCenter code

All of these surfaced as real P0 issues — apps shipping with paywall benefits
whose only "implementation" was the L10n string itself.

**Permission-vs-framework cross-checks (5.1.1):**

`5.1.1 NSCameraUsageDescription` / `NSMotionUsageDescription` /
`NSCalendarsUsageDescription` / `NSContactsUsageDescription` /
`NSRemindersUsageDescription` / `NSUserNotificationsUsageDescription` /
`NSBluetoothAlwaysUsageDescription` — declared in `Info.plist` but no matching
framework usage. Apple flags this under 5.1.1 ("declared permission must be
used") in addition to the existing 2.5.1 covered by previous versions.

**Three new structural checks:**

- `3.1.2(c) paywall-legal-link-color` — a real production bug pattern:
  `HStack` containing `Link("Privacy", ...)` and `Link("Terms", ...)` wrapped in
  `.foregroundColor(.white.opacity(0.5))` made the legal links nearly invisible.
  Apple requires Privacy / Terms links to be clearly clickable. Fix: apply
  `.foregroundStyle(.blue)` to each `Link` directly, not to the parent stack.

- `swiftdata-model-defaults` — `@Model` fields declared without property-level
  defaults (`var isCompleted: Bool` instead of `var isCompleted: Bool = false`).
  When the field is added to an existing model, SwiftData migration crashes
  every existing user on first launch. Detection walks each `@Model class { ... }`
  body and flags `var name: Bool|Int|Double|String|Date` lines without `=`.

- `ai-body-missing-model-{file}` — an AI client builds a request body with
  `"messages"` array but no `"model"` field. DeepSeek / OpenAI APIs both return
  400 in this case. An nginx reverse-proxy cannot inject body fields, so the
  client must send `"model": "deepseek-chat"` (or equivalent) itself.

### Fixed
- `paywall-benefit-icloud_sync`: now requires both `icloud` AND a sync-intent
  token (`sync` / `backup` / `同步` / `备份` / `across devices`) to fire — earlier
  versions falsely flagged apps using only an `icloud.fill` SF Symbol icon.
- `paywall-benefit-csv_export`: pattern extended beyond `\.csv` literals to
  match real CSV code patterns (`exportCSV()`, `var csv = ...`, `csvFileURL`,
  `csvEscaped`, `CSVWriter`). Reduced false positives by ~80%.
- L10n resolution: paywall keyword search now reads any `L10n.swift` and
  `*.xcstrings` so `BenefitRow(text: L10n.feature5)` is matched against the
  actual localized text, not the constant name.

### Internal — operational notes for fix-cycle maintainers

These are not audit rules but operational learnings codified into the README
for future fix cycles:

- **CloudKit container creation needs both Apple Dev Portal Identifier AND
  CloudKit Dashboard Container** — adding `ICLOUD` capability via ASC API
  requires `settings: [{key: "ICLOUD_VERSION", options: [{key: "XCODE_6"}]}]`
  or you get `409 cannot have CloudkitVersion null`.
- **Production schema deploy is dashboard-only** — `cktool import-schema` only
  targets `--environment DEVELOPMENT`. Promotion to PRODUCTION must go through
  CloudKit Dashboard "Deploy Schema Changes..." button.
- **Withdraw IAP from review (legacy API still works)** — the new
  `reviewSubmissions` API rejects PATCH `canceled=true` once `submitted=true`
  with 409. The legacy `DELETE /v1/appStoreVersionSubmissions/{id}` still
  works for individual app version withdrawals.
- **First-time IAP attach has no API** — sub state `READY_TO_SUBMIT` cannot be
  attached + submitted via API; the only path is ASC web UI `App version → "In-App
  Purchases and Subscriptions" section → Select`. `reviewSubmissionItems` does
  not accept subscription items.
- **Cloudflare workers.dev is GFW-blocked in CN** — apps targeting the
  Mainland China App Store should reverse-proxy AI calls through their own
  domain. Both client and server fallback paths should be tested from a CN
  network.

## [0.4.1] - 2026-04-23

### Fixed (false positives discovered during ground-truth verification of v0.4.0)

- **paywall-benefit-icloud_sync**: previously triggered when paywall file contained the substring `icloud` anywhere — including SF Symbol names like `icloud.fill`, `icloud.and.arrow.down`. Apps using only an iCloud icon (e.g. an app whose paywall shows "Live App Store Connect metadata fetch" with an `icloud.and.arrow.down` icon) were falsely flagged. Now: strips `systemName: "..."` and `icon: "..."` strings from the paywall file before keyword search, AND requires both `icloud` AND a sync-intent token (`sync` / `backup` / `同步` / `备份` / `across devices`) to fire. Real claims like "iCloud 同步" or "Data backup" still flag.
- **paywall-benefit-csv_export**: previously matched only `\.csv` literal — missed apps that have real CSV export functions (`exportCSV()`, `var csv = "header\n"`, `csvFileURL`, `csvEscaped`). Reduced findings to a small number of real cases (apps whose paywalls mention CSV but have zero CSV code anywhere).
- **L10n resolution**: paywall benefit keyword search now also reads any `L10n.swift` and `*.xcstrings` in the project, so `BenefitRow(text: L10n.feature5)` resolves to `"iCloud 同步"` for the keyword check, not just `"feature5"`.

## [0.4.0] - 2026-04-23

### Added — 8 new rules from real production debugging

After a user reported "subscription unbuyable + iCloud sync broken" across multiple in-store apps, we traced 4 distinct silent failure modes that ASC marks "APPROVED" but Apple's StoreKit catalog cannot serve. All 8 are now BLOCKER checks:

- **CUSTOM sub-availability-{pid}** — Per-subscription `subscriptionAvailability` must have ≥1 territory. ASC creates sub at `state=APPROVED` but with 0 territories until you call `POST /v1/subscriptionAvailabilities` — Product is invisible to StoreKit. Found on multiple in-store apps.
- **CUSTOM sub-never-submitted-{pid}** — Subscription state `READY_TO_SUBMIT` means it was created but **never reviewed**. First-time IAPs MUST attach to an App version + go through unified review (cannot independently submit via API per Apple `feedback_subscription_iap_apple_limits` #5).
- **CUSTOM sub-group-loc-stuck** — Subscription **group** localizations stuck in `PREPARE_FOR_SUBMISSION`. Even if individual subs are APPROVED, group not LIVE → `https://amp-api-edge.apps.apple.com/.../in-app-purchasables` returns empty → StoreKit silently shows no products. Symptom: paywall says "loading..." or "no products available". Fix: DELETE the stuck group locs via API.
- **CUSTOM transaction-updates-listener** — `SubscriptionManager` must spawn a background `Task { for await in Transaction.updates }`. Without it: promo code redemption / auto-renewal / refund / Family Sharing changes are NOT propagated to `isPremium`. User taps "redeem code" → success on Apple side, but app UI never updates.
- **CUSTOM is-premium-bypass** — Direct writes to `dataStore.isPremium = true` (outside SubscriptionManager + outside demo mode) are a critical security bug: subscription expiry/refund will never revoke access. Found in a paywall that set `store.isPremium = true` after purchase, completely independent of the StoreKit entitlement check.
- **CUSTOM cloudkit-sync-fetch-then-modify** — Apps using CloudKit must fetch existing record before save: `if let existing = try? await db.record(for: id) { record = existing } else { record = CKRecord(recordType:, recordID:) }`. The naive `db.save(CKRecord(recordType:, recordID:))` works the FIRST time, but every subsequent sync fails with `CKError 11 "record to insert already exists"`.
- **CUSTOM cloudkit-prod-schema-deploy** — `cktool import-schema` ONLY deploys to `--environment DEVELOPMENT`. Production deploy must be done via CloudKit Dashboard "Deploy Schema Changes..." button. Without it: `CKError 1011 PartialFailure / Unknown record type` on every write. Apps with `com.apple.developer.icloud-container-environment = Production` (or App Store builds — production by default) fail silently.
- **CUSTOM paywall-benefit-{keyword}** — Extends earlier "Play along/Identify" cross-checks to common subscription claims: `iCloud`, `CSV`, `unlimited`, `notification`, `提醒`, `导出`. If paywall lists a feature with no implementation evidence in `**/*.swift`, flag it. Avoids "feature paywall is a lie" rejection AND user complaints.

### Internal
- `ASCClient.fetch_metadata` now returns:
  - `sub_states`: list of `(productId, state)` tuples
  - `sub_territories`: dict `{productId: territory_count}`
  - `sub_group_loc_states`: list of `(group_id, locale, state)` tuples

## [0.3.0] - 2026-04-18

### Added
- **5.1.1(i) privacy-url-reachable**: HEAD request to verify Privacy URL returns 200. Apple's automated review fetches it; 404 = hard reject.
- **1.5 support-url-reachable**: same check for Support URL.

### Changed
- **3.2.2(x) no-forced-rating**: tightened patterns to detect actual gating code (`SKStoreReviewController.*if.*!rated`, `guard.*hasRated.*else`) instead of free-text matches like `rate.*before` which produced false positives on description text "review and adjust before publishing".
- **4.2 / 4.3 spam check**: combine multiple signals — unique View files + Service/Manager/ViewModel/Store/Repository/Client classes + files in `/Models/` + total non-boilerplate Swift files. Single-purpose utility apps with engine classes (e.g. magnetometer with `MagnetEngine.swift` + `RootView.swift`) no longer false-flagged.
- **5.1.1(i) privacy-in-app**: broadened pattern to catch `Privacy Policy` (with space), URL paths containing `/privacy`, `PrivacyPolicy` class names, and Chinese 隐私政策. Old kebab-only regex missed real shipping apps.

### Fixed
- False positive on `2.3.8 plist-name-matches-asc` when ASC name has a tagline (e.g., `MyApp` plist matches `MyApp - Tracker` ASC name)
- False positive on `4.3 unique-views` for apps using flat structure (no `/Views/` folder)
- False positive on `3.2.2(x)` from description text containing "before"

## [0.2.1] - 2026-04-18

### Added
- **2.3.6 age-rating-set** — verify `appStoreAgeRating` is set to FOUR_PLUS / NINE_PLUS / TWELVE_PLUS / SEVENTEEN_PLUS
- **2.3.6 appinfo-not-rejected** — flag when `appInfo.state == REJECTED` (means age rating data is stale; must re-save in ASC web UI). Found in the wild on a v1.0.2 resubmission rejected with "no rating assigned" despite `appStoreAgeRating: FOUR_PLUS` because the previous appInfo was stuck in REJECTED state.

## [0.2.0] - 2026-04-18

### Added
- 7 new rules:
  - `1.3 kids-no-3rd-party-ads` — Kids Category restriction
  - `4.5.4 push-opt-in` — push notifications must call `requestAuthorization`
  - `5.1.1(iii) data-sharing-opt-in` — data sharing requires consent dialog
  - `5.2.1 content-ownership` — third-party content requires license
  - `5.4 vpn-justification` — NetworkExtension entitlement requires review notes
- `--no-asc` flag for code-only audit (skip ASC fetch)
- `--config` for batch auditing multiple apps
- Multi-language `3.1.1 trial-disclosure` (English + Chinese keywords)
- L10n.swift content included in `3.1.2(c)` checks

### Changed
- `1.4.1 medical-sensor-claim` — expanded keyword list (heart rate, pulse, blood oxygen, ECG, diagnose)
- `2.3.1(a) notes-required-items` — keyword groups instead of single keywords
- `2.3.8 plist-name-matches-asc` — accepts brand prefix variants ("MyApp" matches "MyApp - Tagline")
- `4.3 unique-views-anti-spam` — searches anywhere for `*View.swift`, not just `/Views/`
- README updated to honest 40+ rule claim

### Fixed
- Token refresh handling for batch audits running > 20 minutes
- False positive on `2.3.8` when ASC name has tagline
- False positive on `3.1.1` for paywalls using `then` instead of `after`

## [0.1.0] - 2026-04-18

### Added
- Initial open-source release
- 32 static rules + 11 dynamic permission checks
- ASC API integration for live metadata fetching
- CLI with `--project`, `--bundle-id`, `--config` options
- MIT License
