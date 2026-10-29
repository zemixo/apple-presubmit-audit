import ssl
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import audit  # noqa: E402


class ConditionalRuleTests(unittest.TestCase):
    def setUp(self):
        # Every network probe in this module has an explicit local response.
        patcher = mock.patch.object(
            audit.urllib.request,
            "urlopen",
            side_effect=AssertionError("unexpected network probe"),
        )
        self.network_guard = patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.network_guard.assert_not_called)

    def test_third_party_login_prompts_until_an_apple_marker_is_present(self):
        rule = "ADVISORY 4.8 sign-in-with-apple"
        for provider in ("GIDSignIn", "FBSDKLogin", "TwitterAuth"):
            for apple_marker in (
                "",
                "SignInWithAppleButton()",
                "ASAuthorizationAppleIDProvider()",
            ):
                with self.subTest(provider=provider, apple_marker=apple_marker):
                    findings = self._audit({
                        "LoginView.swift": f"{provider}()\n{apple_marker}\n",
                    })
                    self._assert_advisory(findings, rule, bool(apple_marker))

    def test_apple_login_alone_does_not_emit_third_party_login_advisory(self):
        findings = self._audit({
            "LoginView.swift": "SignInWithAppleButton()\n",
        })
        self.assertNotIn("ADVISORY 4.8 sign-in-with-apple", findings)

    def test_notification_authorization_check_is_independent_of_filename(self):
        rule = "ADVISORY 4.5.4 push-opt-in"
        for filename in ("NotificationManager.swift", "UNUserNotificationCenter.swift"):
            for authorization in (
                "",
                "requestAuthorization(options: [.alert])",
                "requestNotificationAuthorization()",
            ):
                with self.subTest(filename=filename, authorization=authorization):
                    findings = self._audit({
                        filename: "UNUserNotificationCenter.current()\n"
                        + authorization + "\n",
                    })
                    self._assert_advisory(findings, rule, bool(authorization))

    def test_notification_filename_without_source_marker_is_not_a_trigger(self):
        findings = self._audit({
            "UNUserNotificationCenter.swift": 'let title = "Notifications"\n',
        })
        self.assertNotIn("ADVISORY 4.5.4 push-opt-in", findings)

    def test_account_source_prompts_until_a_deletion_marker_is_present(self):
        rule = "ADVISORY 5.1.1(v) account-deletion-ui"
        for account_marker in ("signIn", "register", "createAccount", "loginEmail"):
            for deletion_marker in ("", "deleteAccount()", "account.delete()"):
                with self.subTest(account=account_marker, deletion=deletion_marker):
                    findings = self._audit({
                        "AccountView.swift": f"{account_marker}()\n{deletion_marker}\n",
                    })
                    self._assert_advisory(findings, rule, bool(deletion_marker))

    def test_deletion_marker_without_account_source_does_not_emit_advisory(self):
        findings = self._audit({"AccountView.swift": "deleteAccount()\n"})
        self.assertNotIn("ADVISORY 5.1.1(v) account-deletion-ui", findings)

    def test_cloudkit_schema_prompt_uses_explicit_verification_input(self):
        rule = "ADVISORY CUSTOM cloudkit-prod-schema-deploy"
        sources = {
            "CloudService.swift": (
                'let rootRecordType = "Workspace"\n'
                'let recordType = "Entry"\n'
                'let duplicateRecordType = "Entry"\n'
            ),
        }
        for metadata, passed in (
            ({}, False),
            ({"cloudkit_production_schema_verified": False}, False),
            ({"cloudkit_production_schema_verified": True}, True),
        ):
            with self.subTest(metadata=metadata):
                findings = self._audit(sources, metadata)
                self._assert_advisory(findings, rule, passed)
                self.assertIn("['Entry', 'Workspace']", findings[rule][2])

    def test_cloudkit_dynamic_record_type_is_outside_static_extraction(self):
        findings = self._audit({
            "CloudService.swift": "let recordType = configuredType\n",
        })
        self.assertNotIn("ADVISORY CUSTOM cloudkit-prod-schema-deploy", findings)

    def test_ai_payload_without_model_emits_file_specific_advisory(self):
        rule = "ADVISORY CUSTOM ai-body-missing-model-AIClient.swift"
        findings = self._audit({
            "AIClient.swift": (
                'let endpoint = "https://example.invalid/api/ai"\n'
                'let body = ["messages": []]\n'
                "let session = URLSession.shared\n"
            ),
        })
        self._assert_advisory(findings, rule, False)
        self.assertIn("AIClient.swift", findings[rule][2])
        self.assertIn("proxy supplies a model default", findings[rule][2])

    def test_ai_payload_with_model_or_without_trigger_parts_does_not_emit(self):
        endpoint = 'let endpoint = "https://example.invalid/api/ai"\n'
        messages = 'let body = ["messages": []]\n'
        transport = "let session = URLSession.shared\n"
        for source in (
            endpoint + 'let body = ["messages": [], "model": "fixture-model"]\n'
            + transport,
            messages + transport,
            endpoint + transport,
            endpoint + messages,
        ):
            with self.subTest(source=source):
                findings = self._audit({"AIClient.swift": source})
                self.assertFalse(any(
                    rule.startswith("ADVISORY CUSTOM ai-body-missing-model-")
                    for rule in findings
                ))

    def test_url_reachability_status_boundaries_use_head_and_timeout(self):
        for field, rule in self._url_rules():
            for status in (None, 199, 200, 299, 301, 399, 400, 500):
                with self.subTest(field=field, status=status):
                    url = f"https://example.invalid/{field}"
                    response = mock.MagicMock()
                    response.__enter__.return_value.status = status
                    with mock.patch.object(
                        audit.urllib.request, "urlopen", return_value=response,
                    ) as opener:
                        findings = self._audit({}, {field: url})
                    self._assert_advisory(
                        findings, rule, 200 <= (status or 0) < 400,
                    )
                    self._assert_head_probe(opener, url)
                    response.__exit__.assert_called_once()

    def test_url_reachability_errors_remain_advisories(self):
        for field, rule in self._url_rules():
            url = f"https://example.invalid/{field}"
            for error in (
                urllib.error.HTTPError(url, 405, "Method Not Allowed", {}, None),
                urllib.error.URLError("synthetic-network-detail"),
                TimeoutError("synthetic-timeout-detail"),
            ):
                with self.subTest(field=field, error=type(error).__name__):
                    with mock.patch.object(
                        audit.urllib.request, "urlopen", side_effect=error,
                    ) as opener:
                        findings = self._audit({}, {field: url})
                    self._assert_advisory(findings, rule, False)
                    self._assert_head_probe(opener, url)
                    self.assertIn("some hosts reject HEAD", findings[rule][2])
                    self.assertNotIn("synthetic-", findings[rule][2])

    def test_empty_url_metadata_emits_no_reachability_probe_or_finding(self):
        for metadata in ({}, {"privacyPolicyUrl": "", "supportUrl": ""}):
            with self.subTest(metadata=metadata):
                findings = self._audit({}, metadata)
                for _field, rule in self._url_rules():
                    self.assertNotIn(rule, findings)

    def _assert_advisory(self, findings, rule, passed):
        self.assertIn(rule, findings)
        self.assertTrue(rule.startswith("ADVISORY "))
        self.assertEqual("high", findings[rule][0])
        self.assertIs(passed, findings[rule][1])
        self.assertTrue(findings[rule][2])

    def _assert_head_probe(self, opener, url):
        opener.assert_called_once()
        args, kwargs = opener.call_args
        self.assertEqual(1, len(args))
        request = args[0]
        self.assertEqual(url, request.full_url)
        self.assertEqual("HEAD", request.get_method())
        self.assertEqual(8, kwargs["timeout"])
        self.assertIsInstance(kwargs["context"], ssl.SSLContext)
        self.assertEqual(ssl.CERT_REQUIRED, kwargs["context"].verify_mode)
        self.assertTrue(kwargs["context"].check_hostname)

    @staticmethod
    def _url_rules():
        return (
            ("privacyPolicyUrl", "ADVISORY 5.1.1(i) privacy-url-reachable"),
            ("supportUrl", "ADVISORY 1.5 support-url-reachable"),
        )

    @staticmethod
    def _audit(sources, metadata=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename, source in sources.items():
                (root / filename).write_text(source, encoding="utf-8")
            return {
                rule: (severity, passed, message)
                for rule, severity, passed, message
                in audit.audit_app(root, metadata or {})
            }


if __name__ == "__main__":
    unittest.main()
