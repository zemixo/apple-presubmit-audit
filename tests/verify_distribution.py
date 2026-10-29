#!/usr/bin/env python3
"""Verify that built archives contain the public CLI and no private material."""

import json
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
SOURCE_CATALOG = (ROOT / "rule-catalog.json").read_bytes()
PACKAGE = "apple_presubmit_audit"
EXPECTED_VERSION = "0.6.0.dev0"
SENSITIVE_SUFFIXES = {
    ".cer",
    ".env",
    ".key",
    ".mobileprovision",
    ".p12",
    ".p8",
    ".pem",
}


def fail(message):
    raise AssertionError(message)


def validate_member_names(names, archive_name):
    if len(names) != len(set(names)):
        fail(f"{archive_name} contains duplicate member names")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            fail(f"{archive_name} contains an unsafe path: {name}")
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            fail(f"{archive_name} contains Python cache material: {name}")
        basename = path.name.lower()
        if (
            path.suffix.lower() in SENSITIVE_SUFFIXES
            or basename == ".env"
            or basename.startswith(".env.")
        ):
            fail(f"{archive_name} contains a sensitive file type: {name}")


def verify_wheel(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        validate_member_names(names, path.name)

        required = {
            f"{PACKAGE}/__init__.py",
            f"{PACKAGE}/audit.py",
            f"{PACKAGE}/rule-catalog.json",
        }
        missing = required.difference(names)
        if missing:
            fail(f"wheel is missing package files: {sorted(missing)}")
        if archive.read(f"{PACKAGE}/rule-catalog.json") != SOURCE_CATALOG:
            fail("wheel rule catalog differs from the source catalog")

        dist_info = f"apple_presubmit_audit-{EXPECTED_VERSION}.dist-info"
        expected_names = required | {
            f"{dist_info}/METADATA",
            f"{dist_info}/RECORD",
            f"{dist_info}/WHEEL",
            f"{dist_info}/entry_points.txt",
            f"{dist_info}/licenses/LICENSE",
            f"{dist_info}/top_level.txt",
        }
        missing = expected_names.difference(names)
        if missing:
            fail(f"wheel is missing metadata files: {sorted(missing)}")
        unexpected = set(names).difference(expected_names)
        if unexpected:
            fail(f"wheel contains unexpected files: {sorted(unexpected)}")

        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_point_names = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        license_names = [name for name in names if name.endswith("/licenses/LICENSE")]
        if len(metadata_names) != 1 or len(entry_point_names) != 1:
            fail("wheel must contain one METADATA file and one entry_points.txt")
        if len(license_names) != 1:
            fail("wheel must contain exactly one packaged LICENSE")

        metadata = BytesParser(policy=default).parsebytes(
            archive.read(metadata_names[0])
        )
        if metadata["Name"] != "apple-presubmit-audit":
            fail("unexpected distribution name")
        if metadata["Version"] != EXPECTED_VERSION:
            fail("unexpected distribution version")
        if metadata["Requires-Python"] != ">=3.10":
            fail("unexpected Python version requirement")
        if metadata["License-Expression"] != "MIT":
            fail("wheel metadata must use the MIT license expression")
        if (
            metadata["Author"] != "Zemixo"
            or metadata["Author-email"]
            or metadata["Maintainer-email"]
        ):
            fail("wheel author metadata must use the public pseudonym without email")

        requirements = {
            value.lower().replace(" ", "")
            for value in metadata.get_all("Requires-Dist", [])
        }
        expected_requirements = {
            "requests<3,>=2.32",
            "pyjwt[crypto]<3,>=2.10",
        }
        if requirements != expected_requirements:
            fail(f"unexpected runtime dependencies: {sorted(requirements)}")

        entry_points = archive.read(entry_point_names[0]).decode("utf-8")
        expected_entry = (
            "apple-presubmit-audit = apple_presubmit_audit.audit:main"
        )
        if expected_entry not in entry_points.splitlines():
            fail("wheel console entry point is missing or incorrect")


def verify_sdist(path):
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        validate_member_names([member.name for member in members], path.name)
        unsupported = [
            member.name
            for member in members
            if not (member.isfile() or member.isdir())
        ]
        if unsupported:
            fail(f"sdist contains unsupported member types: {unsupported}")
        regular_members = [member for member in members if member.isfile()]
        names = [member.name for member in regular_members]
        roots = {PurePosixPath(name).parts[0] for name in names}
        if len(roots) != 1:
            fail("sdist must have exactly one top-level directory")
        root = roots.pop()
        required = {
            f"{root}/.github/workflows/tests.yml",
            f"{root}/LICENSE",
            f"{root}/README.md",
            f"{root}/__init__.py",
            f"{root}/action.yml",
            f"{root}/audit.py",
            f"{root}/examples/github-actions/apple-presubmit-audit.yml",
            f"{root}/pyproject.toml",
            f"{root}/requirements.txt",
            f"{root}/rule-catalog.json",
            (
                f"{root}/tests/fixtures/github-action-project/"
                "Fixture.xcodeproj/project.pbxproj"
            ),
            f"{root}/tests/fixtures/production-regressions/cases.json",
            f"{root}/tests/test_audit.py",
            f"{root}/tests/test_conditional_rules.py",
            f"{root}/tests/test_github_action.py",
            f"{root}/tests/test_packaging.py",
        }
        missing = required.difference(names)
        if missing:
            fail(f"sdist is missing source files: {sorted(missing)}")
        catalog_member = archive.getmember(f"{root}/rule-catalog.json")
        catalog_file = archive.extractfile(catalog_member)
        if catalog_file is None or catalog_file.read() != SOURCE_CATALOG:
            fail("sdist rule catalog differs from the source catalog")


def main(argv):
    paths = [Path(argument).resolve() for argument in argv]
    wheels = [path for path in paths if path.suffix == ".whl"]
    sdists = [path for path in paths if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(paths) != 2:
        fail("pass exactly one wheel and one .tar.gz sdist")
    verify_wheel(wheels[0])
    verify_sdist(sdists[0])
    catalog = json.loads(SOURCE_CATALOG)
    print(
        f"verified wheel and sdist: schema v{catalog['schema_version']}, "
        f"{len(catalog['rules'])} rule families"
    )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (
        AssertionError,
        KeyError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"distribution verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
