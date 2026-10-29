import ast
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from datetime import date
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_REGRESSION_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "production-regressions"
)
sys.path.insert(0, str(REPO_ROOT))

import audit  # noqa: E402


class AuditRuleTests(unittest.TestCase):
    def test_source_cli_reports_an_honest_version_without_project_inputs(self):
        result = self._run_cli("--version")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("apple-presubmit-audit source\n", result.stdout)
        self.assertEqual("", result.stderr)

    def test_source_version_does_not_read_installed_distribution_metadata(self):
        with (
            mock.patch.object(audit, "__package__", ""),
            mock.patch.object(
                audit.metadata,
                "version",
                side_effect=AssertionError("source lookup must not inspect metadata"),
            ),
        ):
            self.assertEqual("source", audit.cli_version())

    def test_packaged_version_uses_distribution_metadata(self):
        with (
            mock.patch.object(audit, "__package__", "apple_presubmit_audit"),
            mock.patch.object(
                audit.metadata,
                "version",
                return_value="1.2.3",
            ) as version,
        ):
            self.assertEqual("1.2.3", audit.cli_version())
        version.assert_called_once_with("apple-presubmit-audit")

    def test_packaged_version_falls_back_when_metadata_is_missing(self):
        with (
            mock.patch.object(audit, "__package__", "apple_presubmit_audit"),
            mock.patch.object(
                audit.metadata,
                "version",
                side_effect=audit.metadata.PackageNotFoundError,
            ),
        ):
            self.assertEqual("source", audit.cli_version())

    def test_rule_catalog_has_verified_apple_sources_and_valid_metadata(self):
        catalog = audit.load_rule_catalog()

        self.assertEqual(2, catalog["schema_version"])
        fixture_coverage_values = {
            "baseline",
            "conditional",
            "regression",
            "not-exercised",
        }
        self.assertEqual(
            fixture_coverage_values,
            set(catalog["fixture_coverage_semantics"]),
        )

        sources = {source["id"]: source for source in catalog["sources"]}
        self.assertEqual(len(catalog["sources"]), len(sources))
        for source_id, source in sources.items():
            with self.subTest(source=source_id):
                parsed = urllib.parse.urlparse(source["url"])
                self.assertEqual("https", parsed.scheme)
                hostname = parsed.hostname or ""
                self.assertTrue(
                    hostname == "apple.com" or hostname.endswith(".apple.com")
                )
                self.assertLessEqual(
                    date.fromisoformat(source["checked_on"]),
                    date.today(),
                )

        rules = {rule["id"]: rule for rule in catalog["rules"]}
        self.assertEqual(len(catalog["rules"]), len(rules))
        placeholder_examples = {
            "{usage_description_key}": "NSCameraUsageDescription",
            "{product_id}": "com.example.product",
            "{benefit_id}": "csv_export",
            "{file_name}": "Service.swift",
        }
        used_source_ids = {
            ref["source_id"]
            for rule in catalog["rules"]
            for ref in rule["source_refs"]
        }
        self.assertEqual(set(sources), used_source_ids)
        for rule_id, rule in rules.items():
            with self.subTest(rule=rule_id):
                self.assertTrue(rule_id.startswith(f"{rule['basis']} "))
                self.assertIn(rule["basis"], {"OFFICIAL", "READINESS", "ADVISORY"})
                self.assertIn(rule["default_severity"], {"blocker", "high", "low"})
                self.assertIn(rule["fixture_coverage"], fixture_coverage_values)
                for field in ("trigger", "limits", "remediation"):
                    self.assertIsInstance(rule[field], str)
                    self.assertTrue(rule[field].strip())
                self.assertTrue(rule["source_refs"])
                self.assertTrue(all(
                    ref["source_id"] in sources
                    and ref["relationship"] in {"direct", "context"}
                    for ref in rule["source_refs"]
                ))
                if rule["basis"] == "ADVISORY":
                    self.assertNotEqual("blocker", rule["default_severity"])
                    explanation_text = " ".join(
                        rule[field] for field in ("trigger", "limits", "remediation")
                    )
                    self.assertIsNone(
                        re.search(
                            r"\b(?:must|required)\b",
                            explanation_text,
                            re.IGNORECASE,
                        )
                    )
                else:
                    self.assertIn(
                        "direct",
                        {ref["relationship"] for ref in rule["source_refs"]},
                    )
                if "{" in rule_id:
                    sample_id = rule_id
                    for placeholder, example in placeholder_examples.items():
                        sample_id = sample_id.replace(placeholder, example)
                    self.assertNotIn("{", sample_id)
                    self.assertRegex(sample_id, rule["runtime_id_pattern"])
                    self.assertEqual(
                        [rule_id],
                        [
                            match["id"]
                            for match in audit.match_rule_families(sample_id, catalog)
                        ],
                    )
                else:
                    self.assertNotIn("runtime_id_pattern", rule)
                self.assertEqual(
                    [rule_id],
                    [
                        match["id"]
                        for match in audit.match_rule_families(rule_id, catalog)
                    ],
                )

    def test_rule_catalog_covers_every_implementation_rule_family(self):
        placeholders = {
            "key": "usage_description_key",
            "pid": "product_id",
            "rule_name": "benefit_id",
            "os.path.basename(p)": "file_name",
        }

        def rule_template(call):
            basis = call.func.id.upper()
            rule_arg = call.args[0]
            if isinstance(rule_arg, ast.Constant):
                return f"{basis} {rule_arg.value}"
            if not isinstance(rule_arg, ast.JoinedStr):
                self.fail(f"unsupported rule ID expression: {ast.unparse(rule_arg)}")
            parts = []
            for value in rule_arg.values:
                if isinstance(value, ast.Constant):
                    parts.append(value.value)
                    continue
                expression = ast.unparse(value.value)
                if expression not in placeholders:
                    self.fail(f"uncataloged dynamic rule placeholder: {expression}")
                parts.append("{" + placeholders[expression] + "}")
            return f"{basis} {''.join(parts)}"

        tree = ast.parse((REPO_ROOT / "audit.py").read_text(encoding="utf-8"))
        implementation_rules = {
            rule_template(node): ast.literal_eval(node.args[1])
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"official", "readiness", "advisory"}
        }
        catalog_rules = {
            rule["id"]: rule["default_severity"]
            for rule in audit.load_rule_catalog()["rules"]
        }

        self.assertEqual(catalog_rules, implementation_rules)

    def test_fixture_coverage_matches_actual_fixture_emission(self):
        catalog = audit.load_rule_catalog()

        def family_for(runtime_id):
            matches = [
                rule["id"]
                for rule in audit.match_rule_families(runtime_id, catalog)
            ]
            self.assertEqual(1, len(matches), runtime_id)
            return matches[0]

        with tempfile.TemporaryDirectory() as tmp:
            baseline_families = {
                family_for(rule_id)
                for rule_id, _severity, _passed, _message
                in audit.audit_app(tmp, {})
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_coverage_project(root)
            synthetic_families = {
                family_for(rule_id)
                for rule_id, _severity, _passed, _message
                in self._audit_coverage_project(root)
            }

        conditional_families = synthetic_families - baseline_families
        fixture_manifest = json.loads(
            (PRODUCTION_REGRESSION_ROOT / "cases.json").read_text(encoding="utf-8")
        )
        regression_families = {
            case["rule_id"] for case in fixture_manifest["cases"]
        }
        actual = {
            rule["id"]: rule["fixture_coverage"]
            for rule in catalog["rules"]
        }
        expected = {
            rule["id"]: (
                "regression" if rule["id"] in regression_families
                else "baseline" if rule["id"] in baseline_families
                else "conditional" if rule["id"] in conditional_families
                else "not-exercised"
            )
            for rule in catalog["rules"]
        }

        self.assertEqual(expected, actual)
        self.assertNotIn("not-exercised", actual.values())

    def test_anonymized_production_regressions_fail_before_and_pass_after(self):
        manifest = json.loads(
            (PRODUCTION_REGRESSION_ROOT / "cases.json").read_text(encoding="utf-8")
        )
        catalog_rules = {
            rule["id"]: rule for rule in audit.load_rule_catalog()["rules"]
        }

        self.assertEqual(1, manifest["schema_version"])
        self.assertGreaterEqual(len(manifest["cases"]), 3)
        self.assertEqual(
            len(manifest["cases"]),
            len({case["id"] for case in manifest["cases"]}),
        )

        for case in manifest["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIn(
                    case["evidence_level"],
                    {"observed-runtime-failure", "verified-production-fix"},
                )
                self.assertTrue(case["summary"])
                self.assertTrue(case["change"])
                self.assertTrue(case["before_message_fragments"])
                self.assertIn(case["rule_id"], catalog_rules)
                self.assertEqual(
                    "regression",
                    catalog_rules[case["rule_id"]]["fixture_coverage"],
                )
                case_root = PRODUCTION_REGRESSION_ROOT / case["id"]
                before = {
                    rule_id: (passed, message)
                    for rule_id, _severity, passed, message
                    in audit.audit_app(case_root / "before", {})
                }
                after = {
                    rule_id: (passed, message)
                    for rule_id, _severity, passed, message
                    in audit.audit_app(case_root / "after", {})
                }

                self.assertIn(case["rule_id"], before)
                self.assertIs(False, before[case["rule_id"]][0])
                for fragment in case["before_message_fragments"]:
                    self.assertIn(fragment, before[case["rule_id"]][1])
                self.assertIn(case["rule_id"], after)
                self.assertIs(True, after[case["rule_id"]][0])

        fixture_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in PRODUCTION_REGRESSION_ROOT.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("com.jiexiang", fixture_text)
        self.assertNotRegex(fixture_text, r"BEGIN (?:RSA |EC )?PRIVATE KEY")

    def test_rule_catalog_cli_needs_no_project_configuration(self):
        result = self._run_cli("--rule-catalog")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(audit.load_rule_catalog(), json.loads(result.stdout))

    def test_explain_static_rule_short_circuits_project_and_asc_setup(self):
        missing_project = "/tmp/apple-presubmit-explain-does-not-exist"
        result = self._run_cli(
            "--project",
            missing_project,
            "--explain",
            "OFFICIAL 2.3.7 name-length",
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertIn("Rule: OFFICIAL 2.3.7 name-length", result.stdout)
        self.assertIn("Family: OFFICIAL 2.3.7 name-length", result.stdout)
        self.assertIn("Authority: OFFICIAL", result.stdout)
        self.assertIn("Severity: blocker", result.stdout)
        self.assertIn("Trigger:", result.stdout)
        self.assertIn("Limits:", result.stdout)
        self.assertIn("Remediation:", result.stdout)
        self.assertIn("Title: App Review Guidelines", result.stdout)
        self.assertIn("Section: 2.3.7", result.stdout)
        self.assertIn("https://developer.apple.com/", result.stdout)
        guideline_source = next(
            source
            for source in audit.load_rule_catalog()["sources"]
            if source["id"] == "app-review-guidelines"
        )
        self.assertIn(
            f"Checked on: {guideline_source['checked_on']}",
            result.stdout,
        )
        self.assertNotIn(missing_project, result.stdout)

        stdout = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "audit.py",
                    "--project",
                    missing_project,
                    "--explain",
                    "OFFICIAL 2.3.7 name-length",
                ],
            ),
            mock.patch.object(audit, "load_apps") as load_apps,
            mock.patch.object(audit, "ASCClient") as asc_client,
            mock.patch("sys.stdout", stdout),
        ):
            audit.main()

        load_apps.assert_not_called()
        asc_client.assert_not_called()

    def test_explain_preserves_catalog_source_order(self):
        result = self._run_cli("--explain", "OFFICIAL 1.5 support-url")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        platform_source = result.stdout.index("Title: Platform version information")
        guideline_source = result.stdout.index("Title: App Review Guidelines")
        self.assertLess(platform_source, guideline_source)
        self.assertEqual(2, result.stdout.count("    Section:"))
        self.assertEqual(2, result.stdout.count("    URL:"))
        self.assertEqual(2, result.stdout.count("    Checked on:"))
        self.assertEqual(2, result.stdout.count("    Relationship: direct"))

    def test_explain_accepts_dynamic_and_template_rule_ids(self):
        cases = (
            (
                "READINESS CUSTOM sub-availability-com.example.product",
                "READINESS CUSTOM sub-availability-{product_id}",
            ),
            (
                "READINESS CUSTOM sub-availability-{product_id}",
                "READINESS CUSTOM sub-availability-{product_id}",
            ),
        )
        for rule_id, family in cases:
            with self.subTest(rule_id=rule_id):
                result = self._run_cli("--explain", rule_id)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("", result.stderr)
                self.assertIn(f"Rule: {rule_id}", result.stdout)
                self.assertIn(f"Family: {family}", result.stdout)

    def test_explain_unknown_rule_has_stable_private_error(self):
        unknown = "not-a-rule /private/project/Secret.xcodeproj"
        explanation, error = audit.resolve_rule_explanation(unknown)
        result = self._run_cli("--explain", unknown)

        self.assertIsNone(explanation)
        self.assertEqual("unknown_rule_id", error["code"])
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("Configuration error: unknown rule ID\n", result.stderr)
        self.assertNotIn(unknown, result.stderr)

    def test_explain_rejects_ambiguous_runtime_id_before_scanning(self):
        catalog = audit.load_rule_catalog()
        source_rule = next(
            rule
            for rule in catalog["rules"]
            if rule["id"] == "READINESS CUSTOM sub-availability-{product_id}"
        )
        overlapping = dict(source_rule)
        overlapping["id"] = "READINESS CUSTOM overlapping-{product_id}"
        catalog["rules"] = [*catalog["rules"], overlapping]
        explanation, error = audit.resolve_rule_explanation(
            "READINESS CUSTOM sub-availability-com.example.product",
            catalog,
        )

        self.assertIsNone(explanation)
        self.assertEqual("ambiguous_rule_id", error["code"])

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "audit.py",
                    "--explain",
                    "READINESS CUSTOM sub-availability-com.example.product",
                ],
            ),
            mock.patch.object(audit, "load_rule_catalog", return_value=catalog),
            mock.patch.object(audit, "load_apps") as load_apps,
            mock.patch.object(audit, "ASCClient") as asc_client,
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
            self.assertRaises(SystemExit) as exit_context,
        ):
            audit.main()

        self.assertEqual(2, exit_context.exception.code)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual(
            "Configuration error: rule ID matches more than one catalog family\n",
            stderr.getvalue(),
        )
        load_apps.assert_not_called()
        asc_client.assert_not_called()

    def test_exact_rule_id_does_not_hide_an_overlapping_runtime_family(self):
        catalog = audit.load_rule_catalog()
        source_rule = next(
            rule
            for rule in catalog["rules"]
            if rule["id"] == "READINESS CUSTOM sub-availability-{product_id}"
        )
        overlapping = dict(source_rule)
        overlapping["id"] = "READINESS CUSTOM exact-id-overlap-{product_id}"
        overlapping["runtime_id_pattern"] = (
            r"^OFFICIAL 2\.3\.7 name-length$"
        )
        catalog["rules"] = [*catalog["rules"], overlapping]

        explanation, error = audit.resolve_rule_explanation(
            "OFFICIAL 2.3.7 name-length",
            catalog,
        )

        self.assertIsNone(explanation)
        self.assertEqual("ambiguous_rule_id", error["code"])

    def test_minimal_project_runs_the_baseline_rule_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = audit.audit_app(tmp, {})

        rule_ids = [result[0] for result in results]
        self.assertGreaterEqual(len(rule_ids), 20)
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertTrue(all(
            rule.startswith(("OFFICIAL ", "READINESS ", "ADVISORY "))
            for rule in rule_ids
        ))

    def test_relevant_features_expand_the_catalog_without_duplicates(self):
        with tempfile.TemporaryDirectory() as baseline_tmp:
            baseline_ids = {
                result[0] for result in audit.audit_app(baseline_tmp, {})
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_coverage_project(root)
            results = self._audit_coverage_project(root)

        rule_ids = {result[0] for result in results}
        self.assertGreater(len(rule_ids), len(baseline_ids))
        self.assertEqual(len(results), len(rule_ids))
        self.assertIn(
            "ADVISORY 2.5.1 NSCameraUsageDescription",
            rule_ids,
        )
        self.assertIn(
            "ADVISORY 3.1.2(c) renewal-disclosure-copy",
            rule_ids,
        )
        self.assertIn(
            "ADVISORY CUSTOM paywall-benefit-icloud_sync",
            rule_ids,
        )
        self.assertIn(
            "READINESS CUSTOM sub-never-submitted-product.one",
            rule_ids,
        )

    def test_advisories_never_block_or_assert_hard_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_coverage_project(root)
            results = self._audit_coverage_project(root)

        advisories = [result for result in results if result[0].startswith("ADVISORY ")]
        self.assertGreater(len(advisories), 40)
        for rule, severity, _passed, message in advisories:
            with self.subTest(rule=rule):
                self.assertIn(severity, {"high", "low"})
                self.assertNotEqual("blocker", severity)
                self.assertIsNone(
                    re.search(r"\b(?:must|required)\b", message, re.IGNORECASE)
                )

        tree = ast.parse((REPO_ROOT / "audit.py").read_text(encoding="utf-8"))
        advisory_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "advisory"
        ]
        self.assertGreater(len(advisory_calls), 30)
        for call in advisory_calls:
            severity = call.args[1]
            self.assertIsInstance(severity, ast.Constant)
            self.assertIn(severity.value, {"high", "low"})

    def test_current_published_age_rating_values_are_accepted(self):
        for rating in ("THIRTEEN_PLUS", "SIXTEEN_PLUS", "EIGHTEEN_PLUS"):
            with self.subTest(rating=rating), tempfile.TemporaryDirectory() as tmp:
                results = audit.audit_app(
                    tmp,
                    {
                        "appStoreAgeRating": rating,
                        "description": "A complete and accurate app description.",
                        "name": "Fixture",
                    },
                )
            age_rule = next(
                result for result in results
                if result[0] == "OFFICIAL 2.3.6 age-rating-set"
            )
            self.assertTrue(age_rule[2])

    def test_missing_project_reports_human_error_and_exit_two(self):
        result = self._run_cli(
            "--project",
            "/tmp/apple-presubmit-audit-path-that-does-not-exist",
            "--no-asc",
        )
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn(
            "Configuration error: project path for "
            "'apple-presubmit-audit-path-that-does-not-exist' "
            "is not a directory:",
            result.stderr,
        )

    def test_missing_project_reports_structured_json_error(self):
        result = self._run_cli(
            "--project",
            "/tmp/apple-presubmit-audit-path-that-does-not-exist",
            "--no-asc",
            "--json",
        )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual([], report["apps"])
        self.assertEqual(0, report["total_blockers"])
        self.assertEqual("invalid_project_path", report["errors"][0]["code"])
        self.assertIn("Configuration error:", result.stderr)

    def test_sarif_output_maps_failed_findings_and_preserves_blocker_exit(self):
        with tempfile.TemporaryDirectory(
            prefix="Fixture # 名称 ",
            dir=REPO_ROOT,
        ) as tmp:
            root = Path(tmp)
            project_file = root / "Fixture.xcodeproj" / "project.pbxproj"
            project_file.parent.mkdir()
            project_file.write_text("// synthetic project\n", encoding="utf-8")
            project_uri = urllib.parse.quote(
                project_file.relative_to(REPO_ROOT).as_posix(),
                safe="/",
            )
            config = root / "apps.json"
            config.write_text(json.dumps([{
                "name": "Fixture",
                "project": str(root),
                "bundle_id": "com.example.fixture",
                "description": "",
            }]), encoding="utf-8")

            result = self._run_cli(
                "--config",
                str(config),
                "--no-asc",
                "--sarif",
                cwd=REPO_ROOT,
            )

        self.assertEqual(1, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("2.1.0", report["version"])
        self.assertEqual(
            "https://json.schemastore.org/sarif-2.1.0.json",
            report["$schema"],
        )

        run = report["runs"][0]
        self.assertEqual("apple-presubmit-audit", run["tool"]["driver"]["name"])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(1, run["invocations"][0]["exitCode"])

        findings = {
            finding["ruleId"]: finding
            for finding in run["results"]
        }
        blocker = findings["OFFICIAL 2.1 description-present"]
        self.assertEqual("error", blocker["level"])
        self.assertEqual("Fixture", blocker["properties"]["app"])
        self.assertEqual("OFFICIAL", blocker["properties"]["basis"])
        fingerprint = blocker["partialFingerprints"][
            "applePresubmitAudit/v1"
        ]
        self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")
        self.assertEqual(
            project_uri,
            blocker["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"],
        )
        self.assertEqual(
            "project-anchor",
            blocker["properties"]["locationKind"],
        )

        rule_ids = {
            rule["id"] for rule in run["tool"]["driver"]["rules"]
        }
        self.assertTrue(set(findings).issubset(rule_ids))
        self.assertGreater(len(rule_ids), len(findings))

    def test_sarif_fingerprint_uses_durable_app_identity(self):
        results = {
            "Old Display Name": [
                (
                    "OFFICIAL 2.1 description-present",
                    "blocker",
                    False,
                    "missing",
                ),
            ],
        }
        renamed_results = {"New Display Name": results["Old Display Name"]}
        old_report = audit.sarif_document(
            results,
            app_contexts={
                "Old Display Name": {
                    "bundle_id": "com.example.fixture",
                },
            },
        )
        renamed_report = audit.sarif_document(
            renamed_results,
            app_contexts={
                "New Display Name": {
                    "bundle_id": "com.example.fixture",
                },
            },
        )

        fingerprint_key = "applePresubmitAudit/v1"
        self.assertEqual(
            old_report["runs"][0]["results"][0]["partialFingerprints"][
                fingerprint_key
            ],
            renamed_report["runs"][0]["results"][0]["partialFingerprints"][
                fingerprint_key
            ],
        )

    def test_sarif_configuration_error_is_a_tool_notification(self):
        result = self._run_cli(
            "--project",
            "/tmp/apple-presubmit-audit-path-that-does-not-exist",
            "--no-asc",
            "--sarif",
        )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        invocation = report["runs"][0]["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(2, invocation["exitCode"])
        self.assertEqual(
            "invalid_project_path",
            invocation["toolExecutionNotifications"][0]["descriptor"]["id"],
        )
        self.assertEqual([], report["runs"][0]["results"])
        self.assertIn("Configuration error:", result.stderr)

    def test_output_modes_are_mutually_exclusive(self):
        for left, right in (
            ("--json", "--sarif"),
            ("--json", "--rule-catalog"),
            ("--sarif", "--rule-catalog"),
            ("--json", "--explain"),
            ("--sarif", "--explain"),
            ("--rule-catalog", "--explain"),
        ):
            with self.subTest(left=left, right=right):
                arguments = [
                    "--project",
                    ".",
                    "--no-asc",
                    left,
                    right,
                ]
                if left == "--explain" or right == "--explain":
                    arguments.append("OFFICIAL 2.3.7 name-length")
                result = self._run_cli(
                    *arguments,
                    cwd=REPO_ROOT,
                )

                self.assertEqual(2, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn("not allowed with argument", result.stderr)

    def test_config_rejects_missing_and_non_directory_project_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            regular_file = root / "NotAProject.txt"
            regular_file.write_text("not a directory", encoding="utf-8")
            config = root / "apps.json"
            config.write_text(json.dumps([
                {
                    "name": "MissingApp",
                    "project": str(root / "missing"),
                    "bundle_id": "com.example.missing",
                },
                {
                    "name": "FileApp",
                    "project": str(regular_file),
                    "bundle_id": "com.example.file",
                },
            ]), encoding="utf-8")

            result = self._run_cli(
                "--config",
                str(config),
                "--no-asc",
                "--json",
            )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual(
            ["invalid_project_path", "invalid_project_path"],
            [error["code"] for error in report["errors"]],
        )
        self.assertEqual(2, result.stderr.count("Configuration error:"))

    def test_config_rejects_duplicate_app_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_project = root / "First"
            second_project = root / "Second"
            first_project.mkdir()
            second_project.mkdir()
            config = root / "apps.json"
            config.write_text(json.dumps([
                {
                    "name": "Duplicate",
                    "project": str(first_project),
                },
                {
                    "name": "Duplicate",
                    "project": str(second_project),
                },
            ]), encoding="utf-8")

            result = self._run_cli(
                "--config",
                str(config),
                "--no-asc",
                "--json",
            )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("duplicate_app_name", report["errors"][0]["code"])
        self.assertEqual(1, report["errors"][0]["first_entry"])
        self.assertIn("app names must be unique", result.stderr)

    def test_invalid_config_json_reports_parse_location_and_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "apps.json"
            config.write_text('[{"name": "Broken",}]', encoding="utf-8")

            result = self._run_cli(
                "--config",
                str(config),
                "--no-asc",
                "--json",
            )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        error = report["errors"][0]
        self.assertEqual("invalid_config_json", error["code"])
        self.assertEqual(1, error["line"])
        self.assertGreater(error["column"], 1)
        self.assertIn("cannot parse config file", result.stderr)

    def test_unreadable_config_path_reports_stable_error_and_exit_two(self):
        result = self._run_cli(
            "--config",
            "/tmp/apple-presubmit-audit-config-that-does-not-exist.json",
            "--no-asc",
            "--json",
        )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("config_unreadable", report["errors"][0]["code"])
        self.assertIn("cannot read config file", result.stderr)

    def test_non_utf8_config_reports_decode_error_and_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "apps.json"
            config.write_bytes(b"\xff\xfe\x00")

            result = self._run_cli(
                "--config",
                str(config),
                "--no-asc",
                "--json",
            )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("invalid_config_encoding", report["errors"][0]["code"])
        self.assertIn("cannot decode config file", result.stderr)

    def test_dot_project_uses_resolved_directory_name(self):
        result = self._run_cli(
            "--project",
            ".",
            "--no-asc",
            "--json",
            cwd=REPO_ROOT,
        )

        self.assertEqual(0, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual(REPO_ROOT.name, report["apps"][0]["app"])
        self.assertEqual([], report["errors"])
        self.assertEqual(0, report["total_blockers"])
        self.assertTrue(all(
            rule["basis"] in {"OFFICIAL", "READINESS", "ADVISORY"}
            for rule in report["apps"][0]["rules"]
        ))
        metadata_rules = [
            rule for rule in report["apps"][0]["rules"]
            if rule["rule"] in {
                "OFFICIAL 1.5 support-url",
                "OFFICIAL 2.1 description-present",
                "OFFICIAL 5.1.1(i) privacy-asc",
                "OFFICIAL 2.3.6 age-rating-set",
                "READINESS 2.3.6 appinfo-not-rejected",
                "OFFICIAL 1.5 all-locales-have-support-url",
            }
        ]
        self.assertEqual(6, len(metadata_rules))
        self.assertTrue(all(
            rule["passed"] is None
            and rule["status"] == "not_evaluated"
            for rule in metadata_rules
        ))

    def test_invalid_private_key_reports_sanitized_authentication_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_file = root / "synthetic-invalid-key.p8"
            synthetic_key = "not-a-private-key"
            key_file.write_text(synthetic_key, encoding="utf-8")

            result = self._run_cli(
                "--project",
                str(root),
                "--bundle-id",
                "com.example.synthetic-fixture",
                "--key-id",
                "SYNTHETIC",
                "--issuer-id",
                "00000000-0000-0000-0000-000000000000",
                "--key-file",
                str(key_file),
                "--json",
            )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual([], report["apps"])
        self.assertEqual(
            "asc_authentication_failed",
            report["errors"][0]["code"],
        )
        self.assertNotIn(synthetic_key, result.stdout)
        self.assertNotIn(synthetic_key, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_private_key_file_reports_structured_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self._run_cli(
                "--project",
                str(root),
                "--bundle-id",
                "com.example.synthetic-fixture",
                "--key-id",
                "SYNTHETIC",
                "--issuer-id",
                "00000000-0000-0000-0000-000000000000",
                "--key-file",
                str(root / "missing-synthetic-key.p8"),
                "--json",
            )

        self.assertEqual(2, result.returncode)
        report = json.loads(result.stdout)
        self.assertEqual("key_file_unreadable", report["errors"][0]["code"])
        self.assertNotIn("Traceback", result.stderr)

    def test_asc_http_authentication_error_is_sanitized(self):
        client = audit.ASCClient.__new__(audit.ASCClient)
        client._token = mock.Mock(return_value="synthetic-token")
        client.s = mock.Mock()
        client.s.get.return_value = mock.Mock(ok=False, status_code=401)

        with self.assertRaises(audit.ASCRequestError) as context:
            client.get("/v1/apps")

        self.assertEqual("asc_authentication_failed", context.exception.code)
        self.assertEqual(
            "App Store Connect rejected the supplied credentials (HTTP 401)",
            str(context.exception),
        )
        self.assertNotIn("synthetic-token", str(context.exception))

    def test_asc_network_error_retries_without_exposing_exception_detail(self):
        client = audit.ASCClient.__new__(audit.ASCClient)
        client._token = mock.Mock(return_value="synthetic-token")
        client.s = mock.Mock()
        client.s.get.side_effect = audit.requests.ConnectionError(
            "synthetic-private-detail"
        )

        with (
            mock.patch.object(audit.time, "sleep") as sleep,
            self.assertRaises(audit.ASCRequestError) as context,
        ):
            client.get("/v1/apps")

        self.assertEqual("asc_network_error", context.exception.code)
        self.assertEqual(3, client.s.get.call_count)
        self.assertEqual(2, sleep.call_count)
        self.assertNotIn(
            "synthetic-private-detail",
            str(context.exception),
        )

    @staticmethod
    def _write_coverage_project(root):
        plist_keys = [
            "CFBundleDisplayName",
            "NSHealthShareUsageDescription",
            "NSHealthUpdateUsageDescription",
            "NSCalendarsUsageDescription",
            "NSCameraUsageDescription",
            "NSContactsUsageDescription",
            "NSLocationWhenInUseUsageDescription",
            "NSMicrophoneUsageDescription",
            "NSPhotoLibraryUsageDescription",
            "NSMotionUsageDescription",
            "NSBluetoothAlwaysUsageDescription",
            "NSFaceIDUsageDescription",
            "NSRemindersUsageDescription",
            "NSUserNotificationsUsageDescription",
        ]
        plist = "".join(
            f"<key>{key}</key><string>"
            f"{'Fixture' if key == 'CFBundleDisplayName' else 'Needed'}"
            "</string>"
            for key in plist_keys
        )
        (root / "Info.plist").write_text(
            f"<plist><dict>{plist}</dict></plist>",
            encoding="utf-8",
        )
        (root / "PaywallView.swift").write_text(
            """
import SwiftUI
struct PaywallView: View {
    var body: some View {
        Text("iCloud sync CSV export unlimited notifications PDF export "
             "calendar export photo attachments advanced charts and trends "
             "themes multiple kits voice guidance double elimination "
             "auto-renewing free trial price after trial Restore Privacy Terms EULA")
    }
}
""",
            encoding="utf-8",
        )
        (root / "LoginView.swift").write_text(
            'import SwiftUI\nGIDSignIn.sharedInstance.signIn()\n',
            encoding="utf-8",
        )
        (root / "NotificationManager.swift").write_text(
            "UNUserNotificationCenter.current().requestAuthorization()\n",
            encoding="utf-8",
        )
        (root / "SubscriptionManager.swift").write_text(
            "Product.products(for: [])\n"
            "Transaction.currentEntitlements\n"
            "Transaction.updates\n",
            encoding="utf-8",
        )
        (root / "CloudStore.swift").write_text(
            'let rootRecordType = "FixtureRecord"\n',
            encoding="utf-8",
        )
        (root / "AIClient.swift").write_text(
            'let endpoint = "/api/ai"\n'
            'let body = ["messages": []]\n'
            'request.httpBody = encode(body)\n',
            encoding="utf-8",
        )
        for index in range(4):
            (root / f"Feature{index}View.swift").write_text(
                "import SwiftUI\n"
                f"struct Feature{index}View: View {{ "
                'var body: some View { Text("Feature") } }\n',
                encoding="utf-8",
            )

    def _audit_coverage_project(self, root):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        with mock.patch.object(
            audit.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            results = audit.audit_app(root, self._coverage_metadata())
        self.assertEqual(2, urlopen.call_count)
        self.assertEqual(
            {"https://example.com/privacy", "https://example.com/support"},
            {call.args[0].full_url for call in urlopen.call_args_list},
        )
        return results

    @staticmethod
    def _coverage_metadata():
        return {
            "description": (
                "This app purpose describes play along audio playback and "
                "identify AI photos for health. It is for kids, can share "
                "personal data, contains famous quotes, uses VPN features, "
                "and acts as a detector. Terms of use: "
                "https://example.com/terms. "
            )
            * 4,
            "notes": (
                "Review test steps explain the app purpose, external service "
                "and API, supported region and country, VPN behavior, and that "
                "the detector uses built-in sensors with no external hardware. "
            )
            * 4,
            "name": "Fixture",
            "category": "Kids",
            "gamblingSimulated": "NONE",
            "appStoreAgeRating": "FOUR_PLUS",
            "appInfoState": "READY_FOR_SUBMISSION",
            "has_account": True,
            "privacyPolicyUrl": "https://example.com/privacy",
            "supportUrl": "https://example.com/support",
            "sub_state": "DEVELOPER_ACTION_NEEDED",
            "sub_territories": {"product.one": 1},
            "sub_states": [("product.one", "READY_TO_SUBMIT")],
            "sub_group_loc_states": [
                ("group.one", "en-US", "PREPARE_FOR_SUBMISSION")
            ],
            "locales_missing_support": ["fr-FR"],
        }

    @staticmethod
    def _run_cli(*args, cwd=None):
        command = [sys.executable, str(REPO_ROOT / "audit.py"), *args]
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
