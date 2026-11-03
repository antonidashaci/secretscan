from pathlib import Path

from secretscan import RULES, entropy, redact, scan, scan_text


def find(text: str) -> list[str]:
    return [f.rule for f in scan_text(text, Path("x"), RULES)]


def test_catches_common_provider_tokens():
    assert find("key = 'AKIAIOSFODNN7EXAMPLE'") == ["AWS access key"]
    # Built from pieces: a literal live-format key here would be blocked by
    # GitHub's own push protection, which is the feature this tool imitates.
    assert find("STRIPE=" + "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc") == [
        "Stripe secret key"
    ]
    assert find("ghp_" + "a" * 36) == ["GitHub token"]
    assert find("-----BEGIN RSA PRIVATE KEY-----") == ["Private key block"]
    assert find("DB=postgres://admin:hunter2@db.internal:5432/app") == [
        "Database URL with password"
    ]


def test_placeholders_are_not_reported():
    assert find('password = "changeme"') == []
    assert find('api_key = "your-api-key-here"') == []
    assert find('token = "<YOUR_TOKEN>"') == []
    assert find('secret = "${ENV_SECRET}"') == []
    assert find('password = "aaaaaaaaaa"') == []


def test_high_entropy_assignment_is_reported():
    assert find("password = 'Gk8vQ2pLzR7nXw4T'") == ["Hardcoded password assignment"]


def test_inline_ignore_comment_silences_a_line():
    assert find("key = 'AKIAIOSFODNN7EXAMPLE'  # secretscan: ignore") == []


def test_minified_bundles_are_skipped():
    assert find("x" * 5000 + " AKIAIOSFODNN7EXAMPLE") == []


def test_secrets_are_redacted_in_output():
    out = redact("AKIAIOSFODNN7EXAMPLE")
    assert "IOSFODNN7" not in out
    assert out.startswith("AKIA")


def test_entropy_separates_random_from_repeated():
    assert entropy("aaaaaaaa") == 0.0
    assert entropy("Gk8vQ2pLzR7nXw4T") > 3.0


def test_scan_walks_a_tree_and_skips_binaries(tmp_path: Path):
    (tmp_path / "app.py").write_text("k='AKIAIOSFODNN7EXAMPLE'", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG AKIAIOSFODNN7EXAMPLE")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("k='AKIAIOSFODNN7EXAMPLE'", encoding="utf-8")

    findings = scan(tmp_path)
    assert [f.path.name for f in findings] == ["app.py"]


def test_ignore_patterns_are_honoured(tmp_path: Path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "a.py").write_text("k='AKIAIOSFODNN7EXAMPLE'", encoding="utf-8")
    assert scan(tmp_path, ignore=["fixtures/"]) == []
