#!/usr/bin/env python3
"""
Apple App Store Pre-Submit Audit
Evidence-labeled checks across Apple Review Guideline categories plus local
engineering-readiness heuristics.

Usage:
  # Explain one stable finding without scanning a project:
  python3 audit.py --explain "OFFICIAL 2.3.7 name-length"

  # Audit local Xcode project against ASC metadata:
  python3 audit.py --project ./MyApp --bundle-id com.example.myapp \\
                   --key-id KEY_ID --issuer-id ISSUER_ID --key-file ./AuthKey.p8

  # Audit code only (no ASC fetch):
  python3 audit.py --project ./MyApp --no-asc

  # Audit multiple apps from config file:
  python3 audit.py --config apps.json

Exit codes:
  0 = no blockers
  1 = one or more blocker findings detected
  2 = config error

Read more: https://github.com/XJM-free/apple-presubmit-audit
"""
import argparse
import base64
import glob
import hashlib
from importlib import metadata
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import requests
    import jwt as pyjwt
except ImportError:
    print(
        "Install dependencies first: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(2)


RULE_CATALOG_PATH = Path(__file__).with_name("rule-catalog.json")
DISTRIBUTION_NAME = "apple-presubmit-audit"


def cli_version():
    """Return installed distribution metadata or an honest source marker."""
    if __package__:
        try:
            return metadata.version(DISTRIBUTION_NAME)
        except metadata.PackageNotFoundError:
            pass
    return "source"


def load_rule_catalog():
    """Load the versioned, machine-readable rule and source catalog."""
    with RULE_CATALOG_PATH.open(encoding="utf-8") as catalog_file:
        return json.load(catalog_file)


def match_rule_families(rule_id, catalog=None):
    """Return every catalog family matching one static, template, or runtime ID."""
    if catalog is None:
        catalog = load_rule_catalog()
    return [
        rule
        for rule in catalog["rules"]
        if rule["id"] == rule_id
        or (
            rule.get("runtime_id_pattern")
            and re.fullmatch(rule["runtime_id_pattern"], rule_id)
        )
    ]


def build_rule_explanation(rule_id, rule, catalog):
    """Join one catalog rule to its sources without inspecting an app project."""
    sources = {source["id"]: source for source in catalog["sources"]}
    return {
        "rule": rule_id,
        "family": rule["id"],
        "authority": rule["basis"],
        "severity": rule["default_severity"],
        "trigger": rule["trigger"],
        "limits": rule["limits"],
        "remediation": rule["remediation"],
        "sources": [
            {
                "title": sources[ref["source_id"]]["title"],
                "section": ref["section"],
                "url": sources[ref["source_id"]]["url"],
                "checked_on": sources[ref["source_id"]]["checked_on"],
                "relationship": ref["relationship"],
            }
            for ref in rule["source_refs"]
        ],
    }


def resolve_rule_explanation(rule_id, catalog=None):
    """Resolve exactly one family, returning a stable error for unsafe ambiguity."""
    if catalog is None:
        catalog = load_rule_catalog()
    matches = match_rule_families(rule_id, catalog)
    if not matches:
        return None, configuration_error("unknown_rule_id", "unknown rule ID")
    if len(matches) > 1:
        return None, configuration_error(
            "ambiguous_rule_id",
            "rule ID matches more than one catalog family",
        )
    return build_rule_explanation(rule_id, matches[0], catalog), None


def print_rule_explanation(explanation):
    """Print a deterministic, human-readable explanation for one rule family."""
    print(f"Rule: {explanation['rule']}")
    print(f"Family: {explanation['family']}")
    print(f"Authority: {explanation['authority']}")
    print(f"Severity: {explanation['severity']}")
    print(f"Trigger: {explanation['trigger']}")
    print(f"Limits: {explanation['limits']}")
    print(f"Remediation: {explanation['remediation']}")
    print("Sources:")
    for source in explanation["sources"]:
        print(f"  - Title: {source['title']}")
        print(f"    Section: {source['section']}")
        print(f"    URL: {source['url']}")
        print(f"    Checked on: {source['checked_on']}")
        print(f"    Relationship: {source['relationship']}")


# ─── ASC API helpers ──────────────────────────────────────────────────────────
class ASCRequestError(RuntimeError):
    """A sanitized App Store Connect failure safe to expose in CLI output."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class ASCClient:
    def __init__(self, key_id, issuer_id, key_file):
        self.key_id = key_id
        self.issuer_id = issuer_id
        self.key = Path(key_file).read_text()
        self.s = requests.Session()
        self.s.trust_env = False  # ASC API more reliable without proxy env vars

    def _token(self):
        return pyjwt.encode(
            {"iss": self.issuer_id, "exp": int(time.time()) + 1000, "aud": "appstoreconnect-v1"},
            self.key, algorithm="ES256",
            headers={"kid": self.key_id, "typ": "JWT"},
        )

    def get(self, path, **params):
        for attempt in range(3):
            try:
                token = self._token()
            except Exception as exc:
                raise ASCRequestError(
                    "asc_authentication_failed",
                    "cannot create an App Store Connect authentication token; "
                    "verify the key ID, issuer ID, and private-key file",
                ) from exc

            try:
                r = self.s.get(
                    f"https://api.appstoreconnect.apple.com{path}",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                    timeout=60,
                )
            except requests.RequestException as exc:
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise ASCRequestError(
                    "asc_network_error",
                    "App Store Connect could not be reached after three attempts",
                ) from exc

            if r.ok:
                try:
                    return r.json()
                except ValueError as exc:
                    raise ASCRequestError(
                        "asc_invalid_response",
                        "App Store Connect returned a non-JSON response",
                    ) from exc

            status = r.status_code
            retryable = status == 429 or status >= 500
            if retryable and attempt < 2:
                time.sleep(1.5 * (attempt + 1))
                continue

            if status in (401, 403):
                code = "asc_authentication_failed"
                message = (
                    "App Store Connect rejected the supplied credentials "
                    f"(HTTP {status})"
                )
            elif status == 429:
                code = "asc_rate_limited"
                message = "App Store Connect rate-limited the audit (HTTP 429)"
            else:
                code = "asc_request_failed"
                message = f"App Store Connect request failed (HTTP {status})"
            raise ASCRequestError(code, message)

        raise ASCRequestError(
            "asc_request_failed",
            "App Store Connect request failed",
        )

    def app_id_for_bundle(self, bundle_id):
        r = self.get("/v1/apps", **{"filter[bundleId]": bundle_id, "limit": 1})
        return (r.get("data") or [{}])[0].get("id")

    def fetch_metadata(self, app_id):
        out = {}
        v = (self.get(f"/v1/apps/{app_id}/appStoreVersions", limit=1).get("data") or [None])[0]
        if not v:
            return out
        out["app_state"] = v["attributes"].get("appStoreState")
        # localizations
        locs = self.get(f"/v1/appStoreVersions/{v['id']}/appStoreVersionLocalizations").get("data", [])
        en = next(
            (
                localization
                for localization in locs
                if localization["attributes"]["locale"].startswith("en")
            ),
            locs[0] if locs else None,
        )
        if en:
            out["description"] = en["attributes"].get("description") or ""
            out["supportUrl"] = en["attributes"].get("supportUrl") or ""
        out["locales_missing_support"] = [
            localization["attributes"]["locale"]
            for localization in locs
            if not localization["attributes"].get("supportUrl")
        ]
        # review notes
        rd = self.get(f"/v1/appStoreVersions/{v['id']}/appStoreReviewDetail").get("data") or {}
        out["notes"] = (rd.get("attributes") or {}).get("notes") or ""
        # appInfo (name, privacy URL, age rating)
        infos = self.get(f"/v1/apps/{app_id}/appInfos").get("data", [])
        if infos:
            out["appinfo_state"] = infos[0]["attributes"].get("state")
            out["appStoreAgeRating"] = infos[0]["attributes"].get("appStoreAgeRating")
            ilocs = self.get(f"/v1/appInfos/{infos[0]['id']}/appInfoLocalizations").get("data", [])
            ien = next(
                (
                    localization
                    for localization in ilocs
                    if localization["attributes"]["locale"].startswith("en")
                ),
                ilocs[0] if ilocs else None,
            )
            if ien:
                out["name"] = ien["attributes"].get("name") or ""
                out["privacyPolicyUrl"] = ien["attributes"].get("privacyPolicyUrl") or ""
            ard = self.get(f"/v1/appInfos/{infos[0]['id']}/ageRatingDeclaration").get("data") or {}
            out["gamblingSimulated"] = (ard.get("attributes") or {}).get("gamblingSimulated", "?")
        # subscription state + group locs + per-sub availability/territories
        groups = self.get(f"/v1/apps/{app_id}/subscriptionGroups").get("data", [])
        out["sub_group_loc_states"] = []  # list of (group_id, locale, state)
        out["sub_states"] = []            # list of (productId, state)
        out["sub_territories"] = {}       # productId -> count
        for g in groups:
            gid = g["id"]
            glocs = self.get(f"/v1/subscriptionGroups/{gid}/subscriptionGroupLocalizations").get("data", [])
            for localization in glocs:
                la = localization["attributes"]
                out["sub_group_loc_states"].append((gid, la.get("locale"), la.get("state")))
            subs = self.get(f"/v1/subscriptionGroups/{gid}/subscriptions").get("data", [])
            for sub in subs:
                sid = sub["id"]
                sa = sub["attributes"]
                out["sub_states"].append((sa.get("productId"), sa.get("state")))
                terrs = self.get(f"/v1/subscriptionAvailabilities/{sid}/availableTerritories", limit=200)
                out["sub_territories"][sa.get("productId")] = len((terrs or {}).get("data", []))
                if not out.get("sub_state"):
                    out["sub_state"] = sa.get("state")
        # Available territories (for locale-skip logic)
        try:
            ta = self.get(f"/v2/appAvailabilities/{app_id}/territoryAvailabilities?limit=200")
            avail_codes = []
            for t in ta.get("data", []):
                if t["attributes"].get("available"):
                    decoded = json.loads(
                        base64.b64decode(t["id"] + "==").decode()
                    )
                    avail_codes.append(decoded["t"])
            out["available_territories"] = avail_codes
            CN_ZONE = {"CHN","HKG","TWN","MAC"}
            out["chinese_only"] = bool(avail_codes) and set(avail_codes).issubset(CN_ZONE)
        except Exception:
            out["available_territories"] = []
            out["chinese_only"] = False
        return out


# ─── Code introspection helpers ───────────────────────────────────────────────
def grep_dir(root, pattern, ext=".swift"):
    matches = []
    for p in glob.glob(f"{root}/**/*{ext}", recursive=True):
        if "/build/" in p or "/Build/" in p or "/.build/" in p:
            continue
        try:
            if re.search(pattern, Path(p).read_text(errors="ignore")):
                matches.append(p)
        except Exception:
            pass
    return matches


def find_one(root, name):
    for p in glob.glob(f"{root}/**/{name}", recursive=True):
        if "/build/" not in p and "/Build/" not in p and ".xcarchive" not in p:
            return p
    return None


def get_plist_keys(root):
    plist = find_one(root, "Info.plist")
    if not plist:
        return {}
    try:
        c = Path(plist).read_text(errors="ignore")
        keys = {}
        for m in re.finditer(r"<key>(\w+)</key>\s*<string>([^<]*)</string>", c):
            keys[m.group(1)] = m.group(2)
        return keys
    except Exception:
        return {}


# ─── The audit ────────────────────────────────────────────────────────────────
def audit_app(root, asc):
    """Returns list of (rule_id, severity, ok, message)."""
    results = []

    def add(basis, rule, sev, ok, msg=""):
        """Record a finding with an explicit evidence basis.

        OFFICIAL findings directly validate a published Apple field or limit.
        READINESS findings directly observe a submission/catalog state that can
        prevent the intended release or purchase flow.
        ADVISORY findings are static, submission-derived heuristics. They can
        suggest manual review, but they can never block a submission.
        """
        if basis == "ADVISORY":
            if sev == "blocker":
                raise ValueError(f"advisory rule cannot be a blocker: {rule}")
            if re.search(r"\b(?:must|required)\b", msg, re.IGNORECASE):
                raise ValueError(
                    f"advisory message cannot assert a hard requirement: {rule}"
                )
            msg = f"Heuristic: {msg}"
        if ok not in (True, False, None):
            raise TypeError(f"rule result must be True, False, or None: {rule}")
        results.append((f"{basis} {rule}", sev, ok, msg))

    def official(rule, sev, ok, msg=""):
        add("OFFICIAL", rule, sev, ok, msg)

    def readiness(rule, sev, ok, msg=""):
        add("READINESS", rule, sev, ok, msg)

    def advisory(rule, sev, ok, msg=""):
        add("ADVISORY", rule, sev, ok, msg)

    plist = get_plist_keys(root)
    desc = (asc.get("description") or "").lower()
    notes = (asc.get("notes") or "").lower()
    name_asc = asc.get("name", "")
    name_plist = plist.get("CFBundleDisplayName", "")

    # ═══ 1. SAFETY ════════════════════════════════════════════════════════════
    # 1.1.6 — fake/prank content
    fake_words = ["fake gps", "fake location", "fake call", "prank battery", "prank charger"]
    advisory("1.1.6 fake-content-keywords", "high",
        not any(w in desc for w in fake_words),
        "metadata contains a fake/prank keyword; review the complete context "
        "against Guideline 1.1.6")

    # 1.4.1 — no false medical sensor claims
    medical = ["measure blood pressure", "measure blood sugar", "measure glucose",
               "measure body temperature", "measure spo2", "ekg measurement",
               "measure heart rate", "measure pulse", "measure blood oxygen",
               "ecg recording", "pulse oximeter", "diagnose"]
    advisory("1.4.1 medical-sensor-claim", "high",
        not any(c in desc for c in medical),
        "metadata appears to promise a health measurement; verify the disclosed "
        "methodology, accuracy evidence, hardware, and any regulatory clearance")

    # 1.3 — Kids Category strict rules
    if "kids" in (asc.get("category", "") or "").lower() or "for kids" in desc:
        advisory("1.3 kids-third-party-ads", "high",
            not any(grep_dir(root, p) for p in ["AdMob", "FBAds", "GADBanner"]),
            "a Kids Category signal and a third-party advertising SDK were both "
            "found; Apple permits only limited contextual-ad exceptions")

    # 1.5 — Support URL present
    official("1.5 support-url", "blocker",
        None if "supportUrl" not in asc else bool(asc.get("supportUrl")),
        "Support URL is missing in App Store Connect; this is a required "
        "localizable app-version property")

    # ═══ 2. PERFORMANCE ═══════════════════════════════════════════════════════
    # 2.1 — App completeness
    official("2.1 description-present", "blocker",
        None if "description" not in asc else bool(desc.strip()),
        "App Store description is missing; App Store Connect requires this field")
    advisory("2.1 description-detail", "low",
        not desc or len(desc) > 50,
        f"description is only {len(desc)} characters; review whether it "
        "accurately explains the core experience")
    advisory("2.1 placeholder-text", "high",
        not re.search(r"\b(lorem|todo|placeholder|tbd|coming soon)\b", desc),
        "description contains text that resembles an unfinished placeholder")

    # 2.1 — Metadata/implementation consistency advisory
    if "play along" in desc or "playback" in desc or "tap to play" in desc:
        has_audio = bool(grep_dir(root, r"AVAudioEngine|AVAudioPlayer|AudioServicesPlay"))
        advisory("2.1 audio-promise-implemented", "high", has_audio,
            "audio playback is promised in metadata, but this source scan did "
            "not find a common AVFoundation implementation marker")
    if "identify" in desc and ("ai" in desc or "photo" in desc):
        has_id = bool(grep_dir(root, r"VNCoreMLRequest|MLModel|URLSession"))
        advisory("2.1 identify-promise-implemented", "high", has_id,
            "AI identification is promised in metadata, but this source scan did "
            "not find a common Core ML or network implementation marker")

    # 2.3.1(a) — Review notes detail
    advisory("2.3.1(a) notes-detail", "low",
        "notes" not in asc or len(notes) > 200,
        f"review notes are {len(notes)} characters; Apple publishes no 200-character "
        "minimum, so review only whether the notes explain non-obvious behavior")
    notes_required_groups = [
        ["app", "purpose", "describe"],         # purpose
        ["review", "test", "step", "how to"],    # test steps
        ["external", "third-party", "api", "service", "backend"],  # external services
        ["region", "country", "market", "available", "english"],   # region/locale
    ]
    notes_score = sum(1 for grp in notes_required_groups if any(w in notes for w in grp))
    advisory("2.3.1(a) notes-coverage", "low",
        "notes" not in asc or notes_score >= 3,
        f"notes cover {notes_score}/4 commonly useful topics: purpose, test steps, "
        "external services, and regional behavior")

    # 2.3.7 — App name length ≤ 30
    official("2.3.7 name-length", "blocker",
        len(name_asc) <= 30,
        f"App Store name too long ({len(name_asc)} chars, max 30)")

    # 2.3.8 — CFBundleDisplayName matches ASC name (or its brand prefix before " - " / ":")
    asc_brand = re.split(r"\s*[-–—:|]\s+", name_asc, maxsplit=1)[0].strip()
    name_match = (not name_plist) or name_plist == name_asc or name_plist == asc_brand
    advisory("2.3.8 plist-name-consistency", "high", name_match,
        f"Info.plist CFBundleDisplayName '{name_plist}' differs from ASC name "
        f"'{name_asc}'; Apple asks for similar metadata, not exact equality")

    # 2.3.10 — Don't mention competing platforms
    advisory("2.3.10 competing-platform-reference", "high",
        not re.search(r"\b(android|google play)\b", desc),
        "metadata names another mobile platform; inspect whether Apple's "
        "approved-interactive-functionality exception applies")

    # 2.5.1 — Advisory scan for possibly unused permission declarations
    PERM_CHECKS = {
        "NSHealthShareUsageDescription":   "import HealthKit|HKHealthStore",
        "NSHealthUpdateUsageDescription":  "import HealthKit|HKHealthStore",
        "NSCalendarsUsageDescription":     "import EventKit|EKEventStore",
        "NSCameraUsageDescription":        "AVCaptureDevice|UIImagePickerController|PhotosPicker|VNRecognize",
        "NSContactsUsageDescription":      "import Contacts|CNContactStore",
        "NSLocationWhenInUseUsageDescription": "CLLocationManager|import CoreLocation",
        "NSMicrophoneUsageDescription":    "AVAudioRecorder|AVAudioEngine|AVAudioSession",
        "NSPhotoLibraryUsageDescription":  "PHPhotoLibrary|PhotosPicker|UIImagePickerController",
        "NSMotionUsageDescription":
            "CMMotionManager|CMPedometer|CMAltimeter|startRelativeAltitudeUpdates",
        "NSBluetoothAlwaysUsageDescription": "CBCentralManager",
        "NSFaceIDUsageDescription":        "LAContext",
    }
    for key, code_pat in PERM_CHECKS.items():
        if key in plist:
            has_code = bool(grep_dir(root, code_pat))
            advisory(f"2.5.1 {key}", "high", has_code,
                "the usage-description key is declared, but this regex scan did "
                "not find a common matching framework call")

    # ═══ 3. BUSINESS (subscriptions & monetization) ═══════════════════════════
    paywall_paths = [find_one(root, "PaywallView.swift"), find_one(root, "SubscriptionView.swift")]
    paywall = next((p for p in paywall_paths if p), None)
    if paywall:
        try:
            pc = Path(paywall).read_text(errors="ignore")
            xcs = ""
            for x in glob.glob(f"{root}/**/*.xcstrings", recursive=True):
                if "/build/" not in x:
                    try:
                        xcs += Path(x).read_text(errors="ignore") + "\n"
                    except Exception:
                        pass
            l10n = find_one(root, "L10n.swift")
            if l10n:
                try:
                    xcs += Path(l10n).read_text(errors="ignore") + "\n"
                except Exception:
                    pass

            # 3.1.1 — free trial disclosure (multi-language hints)
            full = (pc + xcs).lower()
            has_trial = any(k in full for k in ["free trial", "free_trial", "free-trial",
                                                "trial period", "试用"])
            if has_trial:
                disclosure_markers = ["after", "then", "afterward", "之后", "试用结束"]
                pricing_markers = ["/yr", "/year", "/mo", "/month", "auto-renew",
                                   "自动续订", "自动续费"]
                discloses = (any(m in full for m in disclosure_markers)
                             and any(p in full for p in pricing_markers))
                advisory("3.1.1 trial-disclosure", "high", discloses,
                    "a free trial is mentioned, but this text scan did not find "
                    "both post-trial timing and pricing/renewal language")

            # 3.1.2(c) — renewal disclosure wording. Apple requires clear
            # subscription information, but does not prescribe the literal
            # phrase "auto-renewing" on the CTA.
            has_ar = bool(re.search(
                r"auto-renewing|auto-renews|自动续订|自动续费|自动续期|自動續訂|自動續費|自動續期",
                pc + xcs, re.I))
            advisory("3.1.2(c) renewal-disclosure-copy", "high", has_ar,
                "this text scan did not find common renewal wording; manually "
                "confirm that price, duration, and renewal terms are clear. "
                "Apple does not prescribe the literal phrase 'auto-renewing'")

            # 3.1.2(c) — price prominence. Apple requires clear disclosure, not
            # a literal `.heavy` font token. Treat 30pt+ bold/heavy system text
            # or title/largeTitle bold text as prominent enough for pre-submit.
            has_36pt = bool(re.search(
                r"size:\s*(30|32|34|36|40|44|48),\s*weight:\s*\.(?:bold|heavy|semibold|black)",
                pc,
            )) or bool(re.search(
                r"\.font\(\s*\.(?:largeTitle|title)\s*(?:\.bold\(\)|\.weight\(\s*\.(?:bold|heavy|semibold)\s*\))",
                pc,
            ))
            advisory("3.1.2(c) price-prominence", "low", has_36pt,
                "this typography scan did not find one of its common prominent "
                "price styles; Apple publishes no 36-point font-size rule")

            # 3.1.2(c) — Restore Purchases button
            advisory("3.1.1 restore-mechanism", "high",
                "Restore" in pc or "restore" in pc.lower(),
                "this paywall source scan did not find a Restore label; verify "
                "that restorable purchases have an accessible restore mechanism")

            # 3.1.2(c) — Privacy + Terms links
            advisory("3.1.2(c) privacy-link", "high",
                "rivacy" in pc,
                "this paywall source scan did not find a Privacy Policy link")
            advisory("3.1.2(c) terms-link", "high",
                bool(re.search(r"[Tt]erms|EULA|stdeula", pc)),
                "this paywall source scan did not find a Terms of Use or EULA link")
        except Exception:
            pass

    # 3.1.2(c) — EULA / Terms metadata advisory, only for subscription apps.
    has_subscription_signals = bool(
        paywall
        or asc.get("sub_state")
        or asc.get("sub_states")
        or re.search(r"\b(?:subscription|subscribe)\b", desc)
    )
    if has_subscription_signals:
        eula_markers = [
            "eula", "stdeula",
            "terms of use", "terms of service", "terms:",
            "服务条款", "使用条款", "用户协议", "用户条款",
        ]
        has_eula = any(m in desc for m in eula_markers) or \
                   bool(re.search(r"https?://[^\s]+(terms|legal|tos|eula)", desc))
        advisory("3.1.2(c) terms-metadata", "high", has_eula,
            "this description scan did not find Terms of Use or EULA text; verify "
            "the applicable subscription metadata and agreement fields")

    # 3.2.2(x) — no forced rating (precise: actual gating code, not description text)
    bad_review = [
        "SKStoreReviewController.*if.*!rated",
        "guard.*hasRated.*else",
        "requestReview\\(\\).*lockFeature",
    ]
    advisory("3.2.2(x) forced-rating-pattern", "high",
        not any(grep_dir(root, p) for p in bad_review),
        "a source pattern resembles gating functionality on an App Store rating")

    # ═══ 4. DESIGN ════════════════════════════════════════════════════════════
    # 4.2 / 4.3 — minimum functionality + Spam
    # Smart heuristic: combine unique views + services/managers + models + total non-boilerplate
    BOILERPLATE = {"PaywallView.swift", "SettingsView.swift", "MainTabView.swift",
                   "OnboardingView.swift", "SubscriptionView.swift", "ContentView.swift",
                   "RootView.swift", "AppView.swift"}

    custom_views = []
    service_count = 0
    model_count = 0
    total_swift = 0
    for p in glob.glob(f"{root}/**/*.swift", recursive=True):
        if "/build/" in p or "/.build/" in p or "Test" in p or "/Pods/" in p:
            continue
        n = os.path.basename(p)
        if n.endswith("View.swift") and n not in BOILERPLATE:
            custom_views.append(n)
        try:
            swift_text = Path(p).read_text(errors="ignore")
            for m_view in re.finditer(r"\bstruct\s+(\w+)\s*:\s*View\b", swift_text):
                view_name = m_view.group(1)
                if f"{view_name}.swift" not in BOILERPLATE:
                    custom_views.append(f"{n}::{view_name}")
        except Exception:
            pass
        if any(n.endswith(s) for s in ("Service.swift","Manager.swift","ViewModel.swift",
                                       "Store.swift","Repository.swift","Client.swift")):
            service_count += 1
        if "/Models/" in p or "/Model/" in p:
            model_count += 1
        if n not in BOILERPLATE and n not in ("AppDelegate.swift","SceneDelegate.swift") \
           and not n.endswith("App.swift"):
            total_swift += 1

    custom_views = sorted(set(custom_views))
    func_score = len(custom_views) + service_count + model_count

    advisory("4.2 minimum-functionality-shape", "low",
        len(custom_views) >= 2 or func_score >= 3 or total_swift >= 4,
        f"project shape is {len(custom_views)} views, {service_count} services, "
        f"{model_count} models, and {total_swift} non-boilerplate files; file "
        "counts do not determine compliance")
    advisory("4.3 duplicate-app-shape", "low",
        len(custom_views) >= 3 or func_score >= 4 or total_swift >= 5,
        f"project shape is {len(custom_views)} views, {service_count} services, "
        f"{model_count} models, and {total_swift} non-boilerplate files; manually "
        "review whether the app provides a distinct experience")

    # 4.8 — third-party login requires Apple Sign-In
    has_3rd = bool(grep_dir(root, r"GIDSignIn|FBSDKLogin|TwitterAuth"))
    if has_3rd:
        has_apple = bool(grep_dir(root, r"SignInWithAppleButton|ASAuthorizationAppleIDProvider"))
        advisory("4.8 sign-in-with-apple", "high", has_apple,
            "a third-party login SDK was found without a common Sign in with "
            "Apple marker; manually check Guideline 4.8 and its exceptions")

    # 4.5.4 — advisory scan for notification authorization flow
    if grep_dir(root, "UNUserNotificationCenter"):
        # Soft check: ensure opt-in dialog code exists
        has_optin = bool(grep_dir(root, r"requestAuthorization|requestNotificationAuthorization"))
        advisory("4.5.4 push-opt-in", "high", has_optin,
            "push notification code was found, but this scan did not locate a "
            "common authorization request")

    # ═══ 5. LEGAL ═════════════════════════════════════════════════════════════
    # 5.1.1(i) — Privacy Policy in ASC + in app
    official("5.1.1(i) privacy-asc", "blocker",
        None if "privacyPolicyUrl" not in asc
        else bool(asc.get("privacyPolicyUrl")),
        "Privacy Policy URL missing in App Store Connect; Apple requires one "
        "for every app")
    privacy_patterns = [
        r"[Pp]rivacy.{0,3}[Pp]olicy",  # Privacy Policy / privacy-policy / privacy_policy
        r"/privacy",                      # URL containing /privacy
        r"PrivacyPolicy",
        r"隐私政策",
    ]
    has_priv_in_app = any(grep_dir(root, p) for p in privacy_patterns)
    advisory("5.1.1(i) privacy-in-app", "high", has_priv_in_app,
        "this source scan did not find a common in-app Privacy Policy link; "
        "verify that the policy is easily accessible in the app")

    # 5.1.1(i) — advisory HTTP reachability probe (HEAD can false-negative)
    privacy_url = asc.get("privacyPolicyUrl") or ""
    if privacy_url:
        try:
            req = urllib.request.Request(privacy_url, method="HEAD",
                                          headers={"User-Agent": "Mozilla/5.0"})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                code = resp.status
        except Exception:
            code = 0
        advisory("5.1.1(i) privacy-url-reachable", "high",
            200 <= (code or 0) < 400,
            f"the HEAD request returned HTTP {code}; confirm the public page is "
            "reachable with a normal browser because some hosts reject HEAD")

    support_url = asc.get("supportUrl") or ""
    if support_url:
        try:
            req = urllib.request.Request(support_url, method="HEAD",
                                          headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8, context=ssl.create_default_context()) as resp:
                code = resp.status
        except Exception:
            code = 0
        advisory("1.5 support-url-reachable", "high",
            200 <= (code or 0) < 400,
            f"the HEAD request returned HTTP {code}; confirm the support page "
            "is publicly reachable because some hosts reject HEAD")

    # 5.1.1(v) — Account deletion (if account exists)
    has_account = bool(grep_dir(root, r"signIn|register|createAccount|loginEmail"))
    if has_account:
        has_delete = bool(grep_dir(root, r"deleteAccount|account.*delete"))
        advisory("5.1.1(v) account-deletion-ui", "high", has_delete,
            "account-like source markers were found without a common in-app "
            "account-deletion marker; manually verify the actual account flow")

    # Simulated gambling is an age-rating input; it is not categorically
    # forbidden for individual developers. Real-money gaming is governed by
    # Guideline 5.3 and cannot be inferred from this single ASC field.
    gambling_simulated = asc.get("gamblingSimulated")
    if gambling_simulated not in (None, "?"):
        advisory("2.3.6 gambling-rating-consistency", "low", True,
            f"simulated-gambling declaration is {gambling_simulated}; compare "
            "it with the app's actual content when answering the age-rating questionnaire")

    # 2.3.6 — App Store age rating must be assigned
    age_rating = asc.get("appStoreAgeRating")
    valid_ratings = {
        "L", "ALL", "ZERO_ZERO",
        "ONE_PLUS", "TWO_PLUS", "THREE_PLUS", "FOUR_PLUS", "FIVE_PLUS",
        "SIX_PLUS", "SEVEN_PLUS", "EIGHT_PLUS", "NINE_PLUS", "TEN_PLUS",
        "ELEVEN_PLUS", "TWELVE_PLUS", "THIRTEEN_PLUS", "FOURTEEN_PLUS",
        "FIFTEEN_PLUS", "SIXTEEN_PLUS", "SEVENTEEN_PLUS", "EIGHTEEN_PLUS",
        "NINETEEN_PLUS", "TWENTY_PLUS", "TWENTY_ONE_PLUS",
    }
    official("2.3.6 age-rating-set", "blocker",
        None if "appStoreAgeRating" not in asc
        else age_rating in valid_ratings,
        f"appStoreAgeRating={age_rating}; a published AppStoreAgeRating value "
        "other than UNRATED is required")

    # 2.3.6 — appInfo state should not be REJECTED (means age rating not applied)
    appinfo_state = asc.get("appinfo_state")
    readiness("2.3.6 appinfo-not-rejected", "blocker",
        None if "appinfo_state" not in asc
        else appinfo_state not in ("REJECTED",),
        f"appInfo state={appinfo_state} (REJECTED → re-save Age Rating in ASC web UI to refresh)")

    # 5.1.1(ix) — regulated industry keywords
    forbidden = ["banking", "blood pressure monitor", "cryptocurrency exchange",
                 "casino", "sports betting", "real money gambling", "lottery ticket"]
    advisory("5.3 regulated-industry-keywords", "high",
        not any(w in desc for w in forbidden),
        "metadata contains a regulated-industry keyword; check the specific "
        "licensing, legal-entity, geography, and review-note rules that apply")

    # 5.1.1(iii) — advisory scan for a data-sharing consent flow
    if "share" in desc and ("data" in desc or "personal" in desc):
        has_consent = bool(grep_dir(
            root,
            r"requestAuthorization|UIAlertController.*data|consent|CKShare|"
            r"UICloudSharingController|ShareLink|collaborat|invite|AI.*consent|"
            r"showingConsentAlert|consentAlert",
        ))
        advisory("5.1.1(iii) data-sharing-opt-in", "high", has_consent,
            "metadata mentions sharing personal data, but this scan did not find "
            "a common consent or sharing-control marker")

    # 5.2.1 — content rights (heuristic: warn if tutorial/quote content without attribution)
    if any(w in desc for w in ["famous quote", "movie clip", "song lyric", "celebrity"]):
        advisory("5.2.1 content-ownership", "high", False,
            "metadata hints at third-party content; verify ownership or licensing")

    # 5.4 — advisory scan for VPN/Network Extension review context
    if "NetworkExtension" in str(plist) or "vpn" in desc:
        advisory("5.4 vpn-review-context", "high", "vpn" in notes,
            "VPN or Network Extension signals were found without matching review-note "
            "context; check Guideline 5.4 and organization/account eligibility")

    # ═══ CUSTOM (lessons learned from real rejections) ════════════════════════
    # Detector / Meter / Scanner apps may benefit from clear hardware context
    DETECTOR_KW = ["detector", "scanner", "meter", "decibel", "lux meter",
                   "metal detector", "stud finder", "heart rate monitor", "emf"]
    HW_DISCLAIMER = ["no external hardware", "no bluetooth", "built-in", "100% software",
                     "software-only", "onboard sensor", "iphone's built-in",
                     "apple health", "healthkit"]
    if any(k in desc[:300] for k in DETECTOR_KW):
        has_disclaimer = (
            any(d in desc[:500] for d in HW_DISCLAIMER)
            or any(d in notes for d in HW_DISCLAIMER)
        )
        advisory("CUSTOM detector-hardware-context", "high", has_disclaimer,
            "detector/meter metadata does not explain whether it uses built-in "
            "sensors or external hardware; reviewers may request clarification")

    # Health keyword without HealthKit → 2.5.1 risk
    if any(k in desc for k in ["health", "medical", "wellness"]) and "menstr" not in desc:
        if "HealthKit" not in str(plist):
            advisory("CUSTOM health-keyword-no-healthkit", "low", True,
                "health keywords in description without HealthKit may trigger 2.5.1 review")

    # Subscription state should be compatible with the intended review flow.
    sub_state = asc.get("sub_state")
    if sub_state and sub_state not in ("APPROVED", "WAITING_FOR_REVIEW", "IN_REVIEW", "READY_TO_SUBMIT"):
        readiness("CUSTOM subscription-state-ready", "blocker", False,
            f"subscription state={sub_state}; resolve its App Store Connect "
            "status before adding it to the intended review submission")

    # ─── 2026-04 NEW lessons (subscription catalog & CloudKit) ────────────────
    # CUSTOM A: per-sub availability territories (0 territories = product UNBUYABLE)
    sub_terrs = asc.get("sub_territories") or {}
    for pid, count in sub_terrs.items():
        readiness(f"CUSTOM sub-availability-{pid}", "blocker", count > 0,
            f"sub {pid} has {count} territories (0 = unbuyable in StoreKit)")
        if 0 < count < 50:
            advisory(f"CUSTOM sub-territories-coverage-{pid}", "low", False,
                f"subscription {pid} is available in {count} territories; verify "
                "that this matches the intended launch markets")

    # CUSTOM B: a first subscription in READY_TO_SUBMIT still needs review.
    # Apple currently allows direct IAP submissions, but the first item of each
    # type is submitted with a new app version.
    # https://developer.apple.com/help/app-store-connect/manage-submissions-to-app-review/submit-an-in-app-purchase/
    for pid, state in (asc.get("sub_states") or []):
        if state == "READY_TO_SUBMIT":
            readiness(f"CUSTOM sub-never-submitted-{pid}", "blocker", False,
                f"subscription {pid} is {state}; include the first subscription "
                "of this type with a new app version submission")

    # CUSTOM C: subscription group localizations stuck in PREPARE_FOR_SUBMISSION
    # → entire sub catalog unavailable, even if sub itself is APPROVED.
    # Symptom: 'in-app-purchasables' API returns empty for the bundle.
    stuck_locs = [(gid, loc, st) for gid, loc, st in (asc.get("sub_group_loc_states") or [])
                  if st not in ("APPROVED", "WAITING_FOR_REVIEW", "IN_REVIEW")]
    advisory("CUSTOM sub-group-localization-state", "high",
        not stuck_locs,
        f"{len(stuck_locs)} subscription-group localizations are outside reviewed "
        f"states; verify catalog visibility before release. Examples: "
        f"{stuck_locs[:3]}" if stuck_locs else "")

    # CUSTOM D: advisory scan for Transaction.updates handling
    # Without an updates listener, entitlement changes can be missed until the
    # app performs another explicit entitlement refresh.
    sm_files = grep_dir(root, r"Product\.products|Transaction\.currentEntitlements")
    if sm_files:
        has_tx_updates = bool(grep_dir(root, r"Transaction\.updates"))
        advisory("CUSTOM transaction-updates-listener", "high", has_tx_updates,
            "this source scan did not find Transaction.updates near StoreKit "
            "entitlement code; verify how asynchronous entitlement changes are handled")

    # CUSTOM E: isPremium bypass detection
    # Direct writes to a non-StoreKit isPremium = true field bypass the entire
    # entitlement system. Subscription expiry/refund will not revoke access.
    bypass_files = []
    for p in glob.glob(f"{root}/**/*.swift", recursive=True):
        if ("/build/" in p or "Manager.swift" in p or "Demo" in p or
                "/Tests/" in p or "/UITests/" in p or
                re.search(r"/[^/]*Tests/", p)):
            continue
        try:
            c = Path(p).read_text(errors="ignore")
            if re.search(r"\.isPremium\s*=\s*true|\.isSubscribed\s*=\s*true", c):
                if not re.search(r"isInDemoMode|--demo|DEMO_MODE", c):
                    bypass_files.append(os.path.basename(p))
        except Exception:
            pass
    advisory("CUSTOM is-premium-bypass", "high",
        not bypass_files,
        f"a direct premium-state write may bypass StoreKit entitlement checks "
        f"in: {bypass_files}")

    # CUSTOM F: CloudKit sync — fetch existing record before save (otherwise:
    # "record to insert already exists" CKError 11 on every sync after the first).
    # Precise detection: scan each `func sync*/push*/upload*To*` body for
    # `.save(` without a preceding `.record(for:` in the same function.
    if grep_dir(root, r"CKContainer\(identifier:"):
        ck_files = grep_dir(root, r"CKRecord\(recordType:")
        bad = []  # list of (file, function)
        FUNC_RE = re.compile(
            r"func\s+(sync\w*|push\w*|upload\w*|saveTo\w*|backup\w*)\s*\([^)]*\)\s*"
            r"(?:async\s+)?(?:throws\s+)?(?:->\s*\w+\s+)?\{",
            re.MULTILINE)
        for p in ck_files:
            try:
                c = Path(p).read_text(errors="ignore")
                # Find each candidate function and walk balanced braces to extract body
                for m in FUNC_RE.finditer(c):
                    fn_name = m.group(1)
                    start = m.end() - 1  # at the opening brace
                    depth = 0
                    end = start
                    for i in range(start, len(c)):
                        if c[i] == "{":
                            depth += 1
                        elif c[i] == "}":
                            depth -= 1
                            if depth == 0:
                                end = i
                                break
                    body = c[start:end+1]
                    if re.search(r"\.save\(", body) and not re.search(r"\.record\(for:", body):
                        helper_fetches_record = False
                        for call in re.finditer(r"\b(fetch\w*)\s*\(", body):
                            helper_name = call.group(1)
                            helper_re = re.compile(
                                rf"func\s+{re.escape(helper_name)}\s*\([^)]*\)\s*"
                                r"(?:async\s+)?(?:throws\s+)?(?:->\s*[\w<>\[\]?]+\s+)?\{",
                                re.MULTILINE)
                            helper_match = helper_re.search(c)
                            if not helper_match:
                                continue
                            h_start = helper_match.end() - 1
                            h_depth = 0
                            h_end = h_start
                            for j in range(h_start, len(c)):
                                if c[j] == "{":
                                    h_depth += 1
                                elif c[j] == "}":
                                    h_depth -= 1
                                    if h_depth == 0:
                                        h_end = j
                                        break
                            helper_body = c[h_start:h_end+1]
                            if re.search(r"\.record\(for:", helper_body):
                                helper_fetches_record = True
                                break
                        if not helper_fetches_record:
                            bad.append(f"{os.path.basename(p)}::{fn_name}")
            except Exception:
                pass
        advisory("CUSTOM cloudkit-sync-fetch-then-modify", "high",
            not bad,
            f"sync/push code saves a constructed CKRecord without a fetch in the "
            f"same function; review the actual record lifecycle and save policy "
            f"for possible serverRecordChanged/already-exists failures. Affected: "
            f"{bad}" if bad else "")

    # CUSTOM G: advisory prompt to confirm that production has the record types
    # referenced by source. Static source cannot observe the deployed schema.
    ck_record_types = set()
    for p in grep_dir(root, r'rootRecordType\s*=\s*"|recordType\s*=\s*"'):
        try:
            c = Path(p).read_text(errors="ignore")
            for m in re.finditer(r'(?:rootRecordType|recordType)\s*=\s*"([A-Za-z0-9_]+)"', c):
                ck_record_types.add(m.group(1))
        except Exception:
            pass
    if ck_record_types:
        ck_prod_verified = bool(asc.get("cloudkit_production_schema_verified"))
        advisory("CUSTOM cloudkit-prod-schema-deploy", "high",
            ck_prod_verified,
            f"Verify CloudKit PRODUCTION schema has record types: {sorted(ck_record_types)}. "
            f"Run: xcrun cktool export-schema --container-id <id> --environment PRODUCTION")

    # CUSTOM H: advisory consistency scan for paywall benefits vs source markers
    # (extends earlier "Play along/Identify" checks to common subscription claims)
    paywall_path = next((p for p in [find_one(root, "PaywallView.swift"),
                                      find_one(root, "SubscriptionView.swift")]
                         if p), None)
    if paywall_path:
        try:
            pc_raw = Path(paywall_path).read_text(errors="ignore")
            # Strip SF Symbol names — they look like "icloud.fill" but aren't real
            # claims. Lines like `Image(systemName: "icloud.and.arrow.down")` or
            # `BenefitRow(icon: "icloud.fill", ...)` should not trigger a "claim"
            # — only the user-facing text label does.
            pc_no_icons = re.sub(
                r'(?:systemName|icon)\s*:\s*"[^"]*"', '', pc_raw)
            pc_no_icons = re.sub(r'\bImage\s*\([^)]*\)', '', pc_no_icons)
            pc = pc_no_icons.lower()

            # Resolve only L10n constants referenced by this paywall. Pulling the
            # whole L10n.swift file creates false positives from unrelated screens
            # such as calendar/photo/chart labels.
            l10n_refs = set(re.findall(r"\bL10n\.(\w+)", pc_raw))
            if l10n_refs:
                resolved = []
                for l10n in glob.glob(f"{root}/**/L10n.swift", recursive=True):
                    try:
                        lines = Path(l10n).read_text(errors="ignore").splitlines()
                    except Exception:
                        continue
                    for i, line in enumerate(lines):
                        for ref in l10n_refs:
                            if re.search(rf"\b(static\s+(?:var|let|func)\s+{re.escape(ref)}\b|case\s+{re.escape(ref)}\b)", line):
                                resolved.extend(lines[i:i + 8])
                                break
                pc += "\n" + "\n".join(resolved).lower()

            def has_token(txt, token):
                if re.fullmatch(r"[a-z0-9_ -]+", token):
                    return re.search(
                        rf"(?<![a-z0-9_]){re.escape(token)}(?![a-z0-9_])",
                        txt,
                    ) is not None
                return token in txt

            def has_any_token(txt, tokens):
                return any(has_token(txt, token) for token in tokens)

            BENEFIT_CHECKS = {
                # icloud — both English/Chinese. Also requires a sync-intent word
                # nearby ('sync','backup','同步','备份','iCloud') — bare 'icloud'
                # in non-feature text should not trigger. Require both 'icloud'
                # and a sync-intent token before treating it as a feature claim.
                "icloud_sync": (
                    lambda txt: "icloud" in txt and any(
                        w in txt for w in ("sync", "backup", "同步", "备份", "across devices")
                    ),
                    r"CKContainer|NSUbiquitousKeyValueStore|privateCloudDatabase",
                    "iCloud sync/backup claimed but no CKContainer/Ubiquity code",
                ),
                # csv — paywall mentions CSV export
                "csv_export": (
                    lambda txt: "csv" in txt or "导出csv" in txt,
                    # Match real CSV code: function names, file refs, string
                    # construction with header row, and CSVWriter classes.
                    r"func\s+\w*[Cc]sv\w*|var\s+csv\s*[:=]|\.csv\"|csvFileURL|"
                    r"csvEscaped|csvData|CSVWriter|writeCSV|generateCSV|"
                    r"exportCSV|\"\.csv\"|\"csv\"",
                    "CSV export claimed but no CSV writing code (looked for "
                    "exportCSV function, csv variables, .csv file refs, CSVWriter)",
                ),
                # unlimited — look for a corresponding free-limit gate
                "unlimited_gate": (
                    lambda txt: any(w in txt for w in ("unlimited", "无限",
                        "no limit", "无限制")),
                    r"freeLimit|free_limit|FreeLimit|isPremium\s*\\|\\||isPremium \\|\\|",
                    "'unlimited' claimed but no free-limit gating code found",
                ),
                # notifications/reminders
                "notification": (
                    lambda txt: any(w in txt for w in ("提醒", "notification",
                        "reminder", "alerts", "alert when")),
                    r"UNUserNotificationCenter|UNNotificationRequest|UNTimeIntervalNotificationTrigger",
                    "notification/reminder claimed but no UNUserNotificationCenter code",
                ),
                # PDF export
                "pdf_export": (
                    lambda txt: "pdf" in txt and any(
                        w in txt for w in ("export", "share", "导出", "分享", "report", "报告")
                    ),
                    r"PDFKit|UIGraphicsPDFRenderer|PDFDocument|CGPDFContextCreate",
                    "PDF export claimed but no PDFKit/UIGraphicsPDFRenderer code",
                ),
                # Calendar export — EventKit
                "calendar_export": (
                    lambda txt: bool(re.search(
                        r"calendar\s+(?:export|sync)|(?:export|sync|add to)\s+calendar|"
                        r"\b(?:ical|ics)\b|日历导出|导出日历|同步日历|添加到日历",
                        txt,
                    )),
                    r"EKEventStore|EKEvent|import EventKit",
                    "Calendar export/sync claimed but no EventKit code",
                ),
                # Photo attach
                "photo_attach": (
                    lambda txt: has_any_token(txt, ("attach", "附件", "拍照", "camera", "相机"))
                        or (
                            has_any_token(txt, ("photo", "picture", "照片"))
                            and has_any_token(txt, ("upload", "import", "attach", "添加", "上传", "导入"))
                        ),
                    r"PhotosPicker|UIImagePickerController|PHPickerViewController|AVCaptureDevice",
                    "Photo attach claimed but no PhotosPicker/PHPicker/UIImagePickerController code",
                ),
                # Charts / 图表
                "charts": (
                    lambda txt: any(w in txt for w in ("chart", "graph", "图表", "趋势"))
                        and any(w in txt for w in ("detail", "progress", "trend", "stats",
                            "详细", "进度", "趋势", "统计")),
                    r"import Charts|BarMark|LineMark|PointMark|SectorMark|RuleMark|"
                    r"StatsView|HistoryView|statsGrid|splitSection|RingChart|PieSlice|"
                    r"completionRate|GeometryReader|Path\s*\(|Canvas\s*\(",
                    "Detailed charts/trends claimed but no Swift Charts code",
                ),
                # Themes / 主题色
                "themes": (
                    lambda txt: any(w in txt for w in ("theme", "color theme", "skin",
                        "主题", "皮肤", "配色")),
                    r"enum\s+\w*Theme|theme\.primary|theme\.background|@AppStorage.*theme",
                    "Theme/color skin claimed but no theme enum/AppStorage theme code",
                ),
                # Multi-X manager (e.g. multi-kit, multi-budget, multi-tank)
                "multi_x": (
                    lambda txt: any(w in txt for w in ("multiple kits", "multiple budgets",
                        "multi-tank", "多套", "多个", "多份")),
                    r"selectedKitId|kitList|currentKit|switchKit|allKits|"
                    r"StorageBox|Child|children|Course|courses|courseList|"
                    r"freeLimit|free\s+limit|canAdd|isPremium.*count",
                    "Multi-X management claimed but no kit/budget/tank-switching code",
                ),
                # Voice guidance / 语音引导
                "voice_guidance": (
                    lambda txt: any(w in txt for w in ("voice guidance", "voice over",
                        "语音引导", "语音播报", "音频引导")),
                    r"AVSpeechSynthesizer|AVSpeechUtterance",
                    "Voice guidance claimed but no AVSpeechSynthesizer code",
                ),
                # Double elimination bracket
                "double_elimination": (
                    lambda txt: any(w in txt for w in ("double elimination",
                        "双败", "双淘汰", "loser bracket")),
                    r"loserBracket|losersBracket|doubleElimination.*generate|"
                    r"buildLoserBracket",
                    "Double elimination claimed but no loser-bracket generation code",
                ),
            }
            for rule_name, (matches, code_pat, msg) in BENEFIT_CHECKS.items():
                if matches(pc):
                    has_impl = bool(grep_dir(root, code_pat))
                    advisory(f"CUSTOM paywall-benefit-{rule_name}", "high", has_impl, msg)
        except Exception:
            pass

    # All locales must have supportUrl
    missing = asc.get("locales_missing_support") or []
    official("1.5 all-locales-have-support-url", "blocker",
        None if "locales_missing_support" not in asc else not missing,
        f"localizations missing the required supportUrl field: {missing}")

    # CUSTOM I: NSXxxUsageDescription declared but framework code missing
    # Advisory variant of the declared-permission/framework pairing above
    USAGE_FRAMEWORK_PAIRS = {
        "NSCameraUsageDescription":
            r"AVCaptureDevice|UIImagePickerController|PhotosPicker|VNRecognize|"
            r"PHPickerViewController|AVCaptureSession",
        "NSMotionUsageDescription":
            r"CMMotionManager|CMPedometer|CMAltimeter|startGyroUpdates|"
            r"startAccelerometerUpdates|startMagnetometerUpdates|startDeviceMotionUpdates",
        "NSCalendarsUsageDescription":
            r"EKEventStore|EKEvent|import EventKit",
        "NSContactsUsageDescription":
            r"CNContactStore|import Contacts|CNContactPickerViewController",
        "NSRemindersUsageDescription":
            r"EKReminder|import EventKit",
        "NSUserNotificationsUsageDescription":
            r"UNUserNotificationCenter|UNNotificationRequest",
        "NSBluetoothAlwaysUsageDescription":
            r"CBCentralManager|CBPeripheralManager|import CoreBluetooth",
    }
    for key, code_pat in USAGE_FRAMEWORK_PAIRS.items():
        if key in plist:
            has_code = bool(grep_dir(root, code_pat))
            advisory(f"CUSTOM 5.1.1 {key}", "high", has_code,
                f"{key} is declared in Info.plist, but this scan found no common "
                "matching framework code "
                f"(grep: {code_pat[:60]}...)")

    # CUSTOM J: advisory scan for potentially low-contrast paywall legal links.
    # Pattern observed in production: HStack of [Restore button + Privacy
    # Link + Terms Link] all wrapped in `.foregroundColor(.white.opacity(0.5))`
    # makes the Links nearly invisible. Apple requires Privacy + Terms links
    # to be clearly clickable (3.1.2(c)).
    if paywall_path:
        try:
            pc_raw = Path(paywall_path).read_text(errors="ignore")
            # Check legal links directly. Restore buttons/separators are often
            # intentionally muted; do not flag those when each legal Link has
            # an explicit blue foreground style.
            link_colors_bad = []
            legal_link_pat = re.compile(
                r"Link\((?:(?!\n\s*(?:Button|Text|Link|\})).)*?"
                r"(?:Privacy|Terms|隐私|使用条款)"
                r"(?:(?!\n\s*(?:Button|Text|Link|\})).)*?destination\s*:",
                re.DOTALL,
            )
            for m in legal_link_pat.finditer(pc_raw):
                after = pc_raw[m.end():m.end() + 260]
                explicit_blue = re.search(
                    r"\.foreground(?:Color|Style)\(\.blue\)", after)
                direct_faded = re.search(
                    r"\.foregroundColor\(\.white\.opacity\([\d.]+\)", after)
                surrounding = pc_raw[max(0, m.start() - 260):m.end() + 260]
                inherited_faded = re.search(
                    r"\.foregroundColor\(\.white\.opacity\([\d.]+\)",
                    surrounding)
                faded_before_blue = (
                    direct_faded and
                    (not explicit_blue or direct_faded.start() < explicit_blue.start())
                )
                if faded_before_blue or (inherited_faded and not explicit_blue):
                    link_colors_bad.append(m.group(0))
            advisory("CUSTOM 3.1.2(c) paywall-legal-link-color", "high",
                not link_colors_bad,
                "Paywall Privacy/Terms Link wrapped in "
                "`.foregroundColor(.white.opacity(.x))` — links invisible. "
                "Use `.foregroundStyle(.blue)` on each Link instead.")
        except Exception:
            pass

    # CUSTOM K: SwiftData @Model field defaults — missing defaults crash
    # existing users on schema migration when adding new fields.
    bad_model_fields = []
    for p in glob.glob(f"{root}/**/*.swift", recursive=True):
        if "/build/" in p or "/.build/" in p:
            continue
        try:
            c = Path(p).read_text(errors="ignore")
            # Find @Model class blocks
            for m_class in re.finditer(r"@Model[^{]*?\bclass\s+(\w+)\s*\{", c):
                cls_name = m_class.group(1)
                start = m_class.end() - 1
                depth = 0
                end = start
                for i in range(start, len(c)):
                    if c[i] == "{":
                        depth += 1
                    elif c[i] == "}":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                body = c[start:end+1]
                # Find `var name: Type` without `=` default value
                for m_field in re.finditer(
                    r'^\s*var\s+(\w+)\s*:\s*(Bool|Int|Double|String|Date)\s*$',
                    body, re.MULTILINE):
                    bad_model_fields.append(f"{cls_name}.{m_field.group(1)}: {m_field.group(2)}")
        except Exception:
            pass
    advisory("CUSTOM swiftdata-model-defaults", "high",
        not bad_model_fields,
        f"@Model fields without inline defaults may need a compatible initializer, "
        f"default, or migration plan before being added to an existing store: "
        f"{bad_model_fields[:5]}")

    # CUSTOM L: advisory for direct provider calls that commonly need a `model`
    # field; a proxy may legitimately supply a default.
    ai_files = grep_dir(root, r"/api/ai|/api/vision|api\.deepseek\.com|api\.openai\.com|api\.anthropic\.com")
    for p in ai_files:
        try:
            c = Path(p).read_text(errors="ignore")
            if 'URLSession' in c or 'request.httpBody' in c:
                # Look for body dict with messages but check for model
                if re.search(r'"messages"\s*:', c) and not re.search(r'"model"\s*:', c):
                    advisory(f"CUSTOM ai-body-missing-model-{os.path.basename(p)}",
                        "high", False,
                        f"{os.path.basename(p)}: an AI request body has 'messages' "
                        "but no inline 'model' field; verify whether the selected "
                        "provider or proxy supplies a model default")
        except Exception:
            pass

    # CUSTOM M: Empty-state vs error-state confusion in user-facing catch blocks.
    #
    # Bug pattern: a file fetches from an external source (CloudKit, HealthKit,
    # PhotoLibrary, network, filesystem, Core Data) and surfaces ANY error verbatim
    # to a UI-bound string via `errorMessage = error.localizedDescription`. This
    # treats the legitimate "no data yet" empty state as if it were an error,
    # showing users raw codes like `CKError ... Record not found`,
    # `HKError no data available`, `URLError(404)`, etc.
    #
    # This pattern is invisible to:
    #   - Apple Review (UX is not a reject criterion, only crashes are)
    #   - Static linters (no runtime semantics)
    #   - Happy-path QA (testers usually have data)
    # → A pre-submit scan provides an early prompt to inspect this UX path.
    #
    # Heuristic: file imports/uses one of the empty-prone APIs AND has a generic
    # `errorMessage = error.localizedDescription` catch with no branch matching
    # known "empty / not-found" tokens.
    EMPTY_PRONE_APIS = {
        "CloudKit": (r"CKContainer|CKDatabase|CKRecord|import CloudKit",
                     r"CKError\s*\.\s*unknownItem|\.code\s*==\s*\.unknownItem|"
                     r"\"Record not found\"|unknownItem|notFound"),
        "HealthKit": (r"HKHealthStore|HKQuery|import HealthKit",
                      r"HKError|noData|notDetermined|denied"),
        "PhotoLibrary": (r"PHPhotoLibrary|PHAsset|import Photos",
                         r"PHAuthorizationStatus|denied|restricted|isEmpty"),
        "EventKit": (r"EKEventStore|EKReminder|import EventKit",
                     r"EKAuthorizationStatus|denied|isEmpty|noData|notFound"),
        "Network": (r"URLSession|URLRequest|URLError",
                    r"statusCode\s*==\s*404|\.notFound|notConnectedToInternet|"
                    r"isEmpty|httpResponse"),
        "FileSystem": (r"FileManager\.default|fileExists|contentsOfDirectory",
                       r"fileDoesNotExist|fileExists|noSuchFile|isEmpty"),
        "CoreData": (r"NSFetchRequest|NSManagedObject|persistentContainer",
                     r"isEmpty|count\s*==\s*0|fetchedObjects"),
    }
    bad_empty_catches: list[tuple[str, str]] = []
    for api_name, (api_re, empty_re) in EMPTY_PRONE_APIS.items():
        for p in grep_dir(root, api_re):
            try:
                c = Path(p).read_text(errors="ignore")
                has_generic_catch = re.search(
                    r'catch[^{]*\{[^}]*errorMessage\s*=\s*error\.localizedDescription',
                    c, re.DOTALL)
                handles_empty = re.search(empty_re, c)
                if has_generic_catch and not handles_empty:
                    bad_empty_catches.append((api_name, os.path.basename(p)))
            except Exception:
                pass
    advisory("CUSTOM empty-state-vs-error-state", "high",
        not bad_empty_catches,
        f"Files fetching from external sources surface raw error.localizedDescription "
        f"to UI without a 'no-data / not-found' branch. Users see raw codes when the "
        f"correct UX is an empty-state message. Add a typed catch like "
        f"`catch let e as CKError where e.code == .unknownItem`. "
        f"Files: {bad_empty_catches[:5]}")

    # CUSTOM N: Release-note source length. App Store Connect publishes a
    # 4,000-character limit for What's New. Emoji are not categorically banned,
    # so this check intentionally does not reject them.
    # We scan common release-notes file locations: fastlane/metadata/<locale>/release_notes.txt,
    # CHANGELOG.md (latest version block), and any *.txt under metadata/.
    notes_files: list[str] = []
    for pat in ['fastlane/metadata/*/release_notes.txt',
                'fastlane/metadata/**/release_notes.txt',
                'CHANGELOG.md',
                'metadata/*/release_notes.txt']:
        notes_files += glob.glob(f"{root}/{pat}", recursive=True)
    bad_notes: list[str] = []
    for nf in notes_files:
        try:
            text = Path(nf).read_text(errors="ignore")
            # CHANGELOG: only check the topmost (newest) version block
            if nf.endswith("CHANGELOG.md"):
                blocks = re.split(r'^##\s+', text, flags=re.MULTILINE)
                if len(blocks) >= 2:
                    text = blocks[1]
                else:
                    continue
            if len(text) > 4000:
                bad_notes.append(f"{os.path.basename(nf)}: {len(text)} chars > 4000")
        except Exception:
            pass
    advisory("CUSTOM release-notes-length", "high",
        not bad_notes,
        f"release-note source text may exceed App Store Connect's 4,000-character "
        f"What's New field limit. Affected: {bad_notes[:5]}")

    return results


# ─── Reporting ────────────────────────────────────────────────────────────────
SEV_ICON = {"blocker": "🔴", "high": "⚠️ ", "low": "ℹ️ "}
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "apple-presubmit-audit"
TOOL_URL = "https://github.com/XJM-free/apple-presubmit-audit"


def print_report(name, results, quiet=False):
    failed = [r for r in results if r[2] is False]
    skipped = [r for r in results if r[2] is None]
    passed = [r for r in results if r[2] is True]
    blockers = [r for r in failed if r[1] == "blocker"]
    if quiet:
        # Only print apps with blockers in quiet mode
        if blockers:
            print(f"🔴 {name}: {len(blockers)} blocker(s)")
            for rule, sev, ok, msg in blockers:
                print(f"   {rule}: {msg}")
        return len(blockers)
    if blockers:
        icon = "🔴"
    elif failed:
        icon = "⚠️ "
    elif skipped:
        icon = "🟡"
    else:
        icon = "✅"
    print(
        f"\n{icon} {name:20s} "
        f"[passed={len(passed)} skipped={len(skipped)} total={len(results)}] "
        f"blockers={len(blockers)}"
    )
    for rule, sev, ok, msg in failed:
        print(f"   {SEV_ICON.get(sev, '•')} {rule:42s} {msg}")
    return len(blockers)


def json_report(all_results, errors=None):
    """Emit machine-readable JSON for CI integration."""
    out = []
    for name, results in all_results.items():
        out.append({
            "app": name,
            "rules": [
                {
                    "rule": r,
                    "basis": r.partition(" ")[0],
                    "severity": s,
                    "passed": ok,
                    "status": (
                        "passed" if ok is True
                        else "failed" if ok is False
                        else "not_evaluated"
                    ),
                    "message": m,
                }
                for r, s, ok, m in results
            ],
            "blockers": sum(
                1 for _r, severity, ok, _message in results
                if ok is False and severity == "blocker"
            ),
        })
    print(json.dumps({
        "apps": out,
        "total_blockers": sum(a["blockers"] for a in out),
        "errors": errors or [],
    }, indent=2))


def sarif_project_reference(project):
    """Return a stable, non-absolute project reference for fingerprints."""
    if not project:
        return None
    project_path = Path(project).resolve()
    try:
        relative = project_path.relative_to(Path.cwd().resolve())
    except ValueError:
        return project_path.name or None
    return relative.as_posix() or "."


def sarif_project_anchor(project):
    """Find a real repository-relative file to anchor project-level findings."""
    if not project:
        return None
    project_path = Path(project).resolve()
    working_directory = Path.cwd().resolve()
    try:
        project_path.relative_to(working_directory)
    except ValueError:
        return None

    patterns = (
        "*.xcodeproj/project.pbxproj",
        "Info.plist",
        "Package.swift",
        "*.swift",
    )
    for pattern in patterns:
        for candidate in sorted(project_path.rglob(pattern)):
            excluded = {"build", "Build", ".build"}
            relative_parts = candidate.relative_to(project_path).parts
            if (
                candidate.is_file()
                and not excluded.intersection(relative_parts)
                and not any(
                    part.endswith(".xcarchive")
                    for part in relative_parts
                )
            ):
                relative_uri = candidate.relative_to(
                    working_directory
                ).as_posix()
                return urllib.parse.quote(relative_uri, safe="/")
    return None


def sarif_document(all_results, errors=None, app_contexts=None):
    """Build a SARIF 2.1.0 log from failed audit findings."""
    errors = errors or []
    app_contexts = app_contexts or {}
    rules = []
    rule_indexes = {}
    findings = []
    blocker_count = 0

    for app, results in all_results.items():
        app_context = app_contexts.get(app, {})
        project_reference = sarif_project_reference(app_context.get("project"))
        app_identity = (
            app_context.get("bundle_id")
            or project_reference
            or app
        )
        project_anchor = sarif_project_anchor(app_context.get("project"))
        for rule, severity, ok, message in results:
            level = {
                "blocker": "error",
                "high": "warning",
                "low": "note",
            }.get(severity, "warning")
            problem_severity = {
                "blocker": "error",
                "high": "warning",
                "low": "recommendation",
            }.get(severity, "warning")
            basis = rule.partition(" ")[0]
            if rule not in rule_indexes:
                rule_indexes[rule] = len(rules)
                rules.append({
                    "id": rule,
                    "shortDescription": {"text": rule},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "basis": basis,
                        "severity": severity,
                        "tags": ["apple-app-store", basis.lower()],
                        "problem.severity": problem_severity,
                    },
                })

            if ok is not False:
                continue

            fingerprint = hashlib.sha256(
                f"{app_identity}\0{rule}".encode("utf-8")
            ).hexdigest()
            finding = {
                "ruleId": rule,
                "ruleIndex": rule_indexes[rule],
                "level": level,
                "message": {
                    "text": f"{app}: {message or rule}",
                },
                "partialFingerprints": {
                    "applePresubmitAudit/v1": fingerprint,
                },
                "properties": {
                    "app": app,
                    "appIdentity": app_identity,
                    "basis": basis,
                    "severity": severity,
                },
            }
            if project_anchor:
                finding["message"]["text"] += (
                    " (project-level finding; the reported file is an audit anchor)"
                )
                finding["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": project_anchor,
                        },
                        "region": {
                            "startLine": 1,
                        },
                    },
                }]
                finding["properties"]["locationKind"] = "project-anchor"
            findings.append(finding)
            if severity == "blocker":
                blocker_count += 1

    if errors:
        exit_code = 2
        exit_description = "Configuration error"
    elif blocker_count:
        exit_code = 1
        exit_description = "Audit completed with blocker findings"
    else:
        exit_code = 0
        exit_description = "Audit completed without blocker findings"

    invocation = {
        "executionSuccessful": not errors,
        "exitCode": exit_code,
        "exitCodeDescription": exit_description,
    }
    if errors:
        invocation["toolExecutionNotifications"] = []
        for error in errors:
            context = {
                key: value for key, value in error.items()
                if key not in {"code", "message"}
            }
            notification = {
                "descriptor": {
                    "id": error.get("code", "configuration_error"),
                },
                "level": "error",
                "message": {
                    "text": error.get("message", "Configuration error"),
                },
            }
            if context:
                notification["properties"] = context
            invocation["toolExecutionNotifications"].append(notification)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "informationUri": TOOL_URL,
                    "rules": rules,
                },
            },
            "invocations": [invocation],
            "results": findings,
        }],
    }


def sarif_report(all_results, errors=None, app_contexts=None):
    """Emit SARIF 2.1.0 for CI and compatible analysis consumers."""
    print(json.dumps(sarif_document(
        all_results,
        errors=errors,
        app_contexts=app_contexts,
    ), indent=2))


def configuration_error(code, message, **context):
    """Create one stable, machine-readable CLI configuration error."""
    error = {"code": code, "message": message}
    error.update(context)
    return error


def exit_with_configuration_errors(
    errors,
    json_output=False,
    all_results=None,
    sarif_output=False,
    app_contexts=None,
):
    """Report configuration errors for humans and machine consumers."""
    for error in errors:
        print(f"Configuration error: {error['message']}", file=sys.stderr)
    if json_output:
        json_report(all_results or {}, errors=errors)
    elif sarif_output:
        sarif_report(
            all_results or {},
            errors=errors,
            app_contexts=app_contexts,
        )
    return 2


def load_apps(args):
    """Load, normalize, and validate app definitions without auditing them."""
    errors = []
    apps = []

    if args.config and args.project:
        errors.append(configuration_error(
            "conflicting_inputs",
            "use either --project or --config, not both",
        ))
        return apps, errors

    if args.config:
        config_path = Path(args.config).expanduser()
        try:
            with config_path.open(encoding="utf-8") as config_file:
                raw_apps = json.load(config_file)
        except json.JSONDecodeError as exc:
            errors.append(configuration_error(
                "invalid_config_json",
                f"cannot parse config file '{config_path}': "
                f"{exc.msg} at line {exc.lineno}, column {exc.colno}",
                config=str(config_path),
                line=exc.lineno,
                column=exc.colno,
            ))
            return apps, errors
        except UnicodeError as exc:
            errors.append(configuration_error(
                "invalid_config_encoding",
                f"cannot decode config file '{config_path}' as UTF-8: {exc}",
                config=str(config_path),
            ))
            return apps, errors
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            errors.append(configuration_error(
                "config_unreadable",
                f"cannot read config file '{config_path}': {reason}",
                config=str(config_path),
            ))
            return apps, errors

        if not isinstance(raw_apps, list):
            errors.append(configuration_error(
                "invalid_config_shape",
                f"config file '{config_path}' must contain a JSON array",
                config=str(config_path),
            ))
            return apps, errors
        if not raw_apps:
            errors.append(configuration_error(
                "empty_config",
                f"config file '{config_path}' contains no apps",
                config=str(config_path),
            ))
            return apps, errors

        for index, raw_app in enumerate(raw_apps):
            entry_number = index + 1
            if not isinstance(raw_app, dict):
                errors.append(configuration_error(
                    "invalid_app_entry",
                    f"config entry {entry_number} must be a JSON object",
                    config=str(config_path),
                    entry=entry_number,
                ))
                continue

            project_value = raw_app.get("project")
            if not isinstance(project_value, str) or not project_value.strip():
                errors.append(configuration_error(
                    "missing_project_path",
                    f"config entry {entry_number} is missing a project path",
                    config=str(config_path),
                    entry=entry_number,
                    app=raw_app.get("name") or "",
                ))
                continue

            project_path = Path(project_value).expanduser().resolve()
            name = raw_app.get("name")
            if not isinstance(name, str) or not name.strip():
                name = project_path.name or str(project_path)

            app = dict(raw_app)
            app.update({"name": name, "project": str(project_path)})
            apps.append(app)
    elif args.project:
        project_path = Path(args.project).expanduser().resolve()
        name = project_path.name or str(project_path)
        apps = [{
            "name": name,
            "project": str(project_path),
            "bundle_id": args.bundle_id or "",
        }]
    else:
        errors.append(configuration_error(
            "missing_input",
            "provide --project <path> or --config <file.json>",
        ))
        return apps, errors

    first_entry_by_name = {}
    for index, app in enumerate(apps):
        project_path = Path(app["project"])
        if not project_path.is_dir():
            errors.append(configuration_error(
                "invalid_project_path",
                f"project path for '{app['name']}' is not a directory: "
                f"{project_path}",
                entry=index + 1,
                app=app["name"],
                project=str(project_path),
            ))
        previous_entry = first_entry_by_name.get(app["name"])
        if previous_entry is not None:
            errors.append(configuration_error(
                "duplicate_app_name",
                f"config entry {index + 1} reuses app name '{app['name']}' "
                f"from entry {previous_entry}; app names must be unique",
                entry=index + 1,
                first_entry=previous_entry,
                app=app["name"],
            ))
        else:
            first_entry_by_name[app["name"]] = index + 1

    return apps, errors


# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Local, evidence-labeled Apple App Store pre-submit audit"
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"{DISTRIBUTION_NAME} {cli_version()}",
    )
    p.add_argument("--project", help="Path to Xcode project root")
    p.add_argument("--bundle-id", help="Bundle identifier (for ASC lookup)")
    p.add_argument("--config", help="JSON file with multiple apps to audit")
    p.add_argument("--key-id", default=os.getenv("ASC_KEY_ID"))
    p.add_argument("--issuer-id", default=os.getenv("ASC_ISSUER_ID"))
    p.add_argument("--key-file", default=os.getenv("ASC_KEY_FILE"))
    p.add_argument("--no-asc", action="store_true",
                   help="Skip App Store Connect; metadata checks are not evaluated")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Only print apps with blockers (for CI)")
    output = p.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true",
                        help="Emit JSON output (for CI / scripting)")
    output.add_argument("--sarif", action="store_true",
                        help="Emit SARIF 2.1.0 output (for CI / analysis tools)")
    output.add_argument("--rule-catalog", action="store_true",
                        help="Emit the machine-readable rule/source catalog")
    output.add_argument("--explain", metavar="RULE_ID",
                        help="Explain one static, template, or emitted rule ID")
    args = p.parse_args()

    if args.rule_catalog:
        print(json.dumps(load_rule_catalog(), indent=2, ensure_ascii=False))
        return

    if args.explain is not None:
        explanation, error = resolve_rule_explanation(args.explain)
        if error:
            sys.exit(exit_with_configuration_errors([error]))
        print_rule_explanation(explanation)
        return

    apps, errors = load_apps(args)
    if errors:
        sys.exit(exit_with_configuration_errors(
            errors,
            json_output=args.json,
            sarif_output=args.sarif,
        ))

    asc_client = None
    if not args.no_asc:
        missing_credentials = [
            flag for flag, value in (
                ("--key-id", args.key_id),
                ("--issuer-id", args.issuer_id),
                ("--key-file", args.key_file),
            )
            if not value
        ]
        if missing_credentials:
            errors.append(configuration_error(
                "missing_asc_credentials",
                "missing App Store Connect credentials: "
                + ", ".join(missing_credentials)
                + " (or use --no-asc for a code-only audit)",
                missing=missing_credentials,
            ))

        for app in apps:
            if not app.get("bundle_id"):
                errors.append(configuration_error(
                    "missing_bundle_id",
                    f"bundle identifier is missing for '{app['name']}'",
                    app=app["name"],
                    project=app["project"],
                ))

        if args.key_file:
            args.key_file = str(Path(args.key_file).expanduser())

        if errors:
            sys.exit(exit_with_configuration_errors(
                errors,
                json_output=args.json,
                sarif_output=args.sarif,
            ))
        try:
            asc_client = ASCClient(
                args.key_id,
                args.issuer_id,
                args.key_file,
            )
        except (OSError, UnicodeError) as exc:
            key_path = Path(args.key_file)
            reason = getattr(exc, "strerror", None) or type(exc).__name__
            errors.append(configuration_error(
                "key_file_unreadable",
                f"cannot read App Store Connect key file '{key_path}': "
                f"{reason}",
                key_file=str(key_path),
            ))
            sys.exit(exit_with_configuration_errors(
                errors,
                json_output=args.json,
                sarif_output=args.sarif,
            ))

    total_blockers = 0
    all_results = {}
    app_contexts = {}
    for app in apps:
        name = app["name"]
        root = app["project"]
        bid = app.get("bundle_id", "")
        app_contexts[name] = {
            "project": root,
            "bundle_id": bid,
        }
        asc_data = {}
        if asc_client and bid:
            try:
                aid = asc_client.app_id_for_bundle(bid)
            except ASCRequestError as exc:
                errors.append(configuration_error(
                    exc.code,
                    str(exc),
                    app=name,
                ))
                continue
            if aid:
                try:
                    asc_data = asc_client.fetch_metadata(aid)
                except ASCRequestError as exc:
                    errors.append(configuration_error(
                        exc.code,
                        str(exc),
                        app=name,
                    ))
                    continue
            else:
                errors.append(configuration_error(
                    "asc_app_not_found",
                    f"App Store Connect has no app matching the bundle "
                    f"identifier configured for '{name}'",
                    app=name,
                ))
                continue
        asc_data.update({
            k: v for k, v in app.items()
            if k not in ("name", "project", "bundle_id")
        })
        results = audit_app(root, asc_data)
        all_results[name] = results
        if not (args.json or args.sarif):
            total_blockers += print_report(name, results, quiet=args.quiet)

    if errors:
        sys.exit(exit_with_configuration_errors(
            errors,
            json_output=args.json,
            sarif_output=args.sarif,
            all_results=all_results,
            app_contexts=app_contexts,
        ))

    if args.json:
        json_report(all_results)
        total_blockers = sum(
            sum(
                1 for _rule, severity, ok, _message in rs
                if ok is False and severity == "blocker"
            )
            for rs in all_results.values()
        )
    elif args.sarif:
        sarif_report(all_results, app_contexts=app_contexts)
        total_blockers = sum(
            sum(
                1 for _rule, severity, ok, _message in rs
                if ok is False and severity == "blocker"
            )
            for rs in all_results.values()
        )
    elif not args.quiet:
        print(f"\n{'='*70}")
        print(f"Total blockers across all apps: {total_blockers}")
    sys.exit(1 if total_blockers else 0)


if __name__ == "__main__":
    main()
