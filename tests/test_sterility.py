"""The local configuration check reports only names and public rule details."""

import json
import traceback
from types import SimpleNamespace

import pytest

from promptproof import sterility
from promptproof.cli import main
from promptproof.sterility import EnvFileError, check, read_env_file

FAKE = "made-up-" + "violet-quasar-" + "57"


@pytest.mark.parametrize("kind", ["sk", "rk", "pk"])
def test_stripe_keys_under_any_name(kind):
    live_prefix = kind + "_live_"
    report = check({"CUSTOM_PAYMENT": live_prefix + FAKE})
    assert not report.ok
    assert report.live_count == 1
    (finding,) = report.findings
    assert (finding.name, finding.rule, finding.severity, finding.marker) == (
        "CUSTOM_PAYMENT",
        "stripe-key",
        "live",
        live_prefix,
    )
    assert not check({"STRIPE_API_KEY": kind + "_test_" + FAKE}).findings
    assert check({"PAYPAL_MODE": live_prefix + FAKE}).live_count == 1


@pytest.mark.parametrize(
    ("name", "live", "test", "rule"),
    [
        ("PAYPAL_MODE", "live", "sandbox", "paypal-mode"),
        ("PAYPAL_ENVIRONMENT", "production", "SANDBOX", "paypal-mode"),
        ("SQUARE_ENVIRONMENT", "production", "sandbox", "square-mode"),
        ("BRAINTREE_ENVIRONMENT", "production", "sandbox", "braintree-mode"),
        ("PADDLE_ENV", "live", "sandbox", "paddle-mode"),
        ("ADYEN_ENVIRONMENT", "live", "test", "adyen-mode"),
    ],
)
def test_provider_modes(name, live, test, rule):
    report = check({name: live})
    assert not report.ok
    assert report.findings[0].rule == rule
    assert report.findings[0].marker == live
    assert not check({name: test}).findings
    unknown = check({name: FAKE})
    assert unknown.ok and unknown.unknown_count == 1
    assert unknown.findings[0].rule == rule


@pytest.mark.parametrize(
    ("name", "live_host", "sandbox_host", "rule"),
    [
        ("PAYPAL_BASE_URL", "api-m.paypal.com", "api-m.sandbox.paypal.com", "paypal-endpoint"),
        ("SQUARE_API_URL", "connect.squareup.com", "connect.squareupsandbox.com", "square-endpoint"),
        ("PADDLE_API_URL", "api.paddle.com", "sandbox-api.paddle.com", "paddle-endpoint"),
    ],
)
def test_provider_endpoints(name, live_host, sandbox_host, rule):
    report = check({name: "https://" + live_host + "/v1"})
    assert not report.ok
    assert report.findings[0].rule == rule
    assert not check({name: "https://" + sandbox_host}).findings
    assert check({name: "https://" + live_host + ".example.invalid"}).unknown_count == 1


@pytest.mark.parametrize(
    ("name", "live", "test", "rule"),
    [
        ("CUSTOM_PAYMENT", "pdl_" + "live_apikey_", "pdl_" + "sdbx_apikey_", "paddle-key"),
        ("PUBLIC_PADDLE_CLIENT_TOKEN", "live_", "test_", "paddle-client-key"),
        ("ADYEN_CLIENT_KEY", "live_", "test_", "adyen-client-key"),
    ],
)
def test_provider_key_prefixes(name, live, test, rule):
    report = check({name: live + FAKE})
    assert not report.ok
    assert report.findings[0].rule == rule
    assert report.findings[0].marker == live
    assert not check({name: test + FAKE}).findings
    assert not check({"UNRELATED_CLIENT_KEY": "live_" + FAKE}).findings


@pytest.mark.parametrize(
    ("name", "provider"),
    [
        ("STRIPE_WEBHOOK_SECRET", "stripe"),
        ("PAYPAL_CLIENT_SECRET", "paypal"),
        ("SQUARE_ACCESS_TOKEN", "square"),
        ("BRAINTREE_PRIVATE_KEY", "braintree"),
        ("PADDLE_API_KEY", "paddle"),
        ("ADYEN_API_KEY", "adyen"),
        ("TWILIO_ACCOUNT_SID", "twilio"),
        ("TWILIO_AUTH_TOKEN", "twilio"),
        ("TWILIO_TEST_AUTH_TOKEN", "twilio"),
        ("SENDGRID_API_KEY", "sendgrid"),
        ("MAILGUN_API_KEY", "mailgun"),
        ("POSTMARK_SERVER_TOKEN", "postmark"),
        ("RESEND_API_KEY", "resend"),
        ("SLACK_BOT_TOKEN", "slack"),
        ("AWS_ACCESS_KEY_ID", "aws"),
        ("AWS_SECRET_ACCESS_KEY", "aws"),
        ("GOOGLE_API_KEY", "google"),
        ("GCP_ACCESS_TOKEN", "google"),
        ("GITHUB_TOKEN", "github"),
    ],
)
def test_opaque_credentials_require_review(name, provider):
    report = check({name: FAKE})
    assert report.ok and report.unknown_count == 1
    (finding,) = report.findings
    assert (finding.rule, finding.severity, finding.marker) == (provider + "-credential", "unknown", None)
    assert not check({name: "  ", name + "_LABEL": FAKE}).findings


@pytest.mark.parametrize(
    ("prefix", "provider"),
    [
        ("wh" + "sec_", "stripe"),
        ("SG" + ".", "sendgrid"),
        ("r" + "e_", "resend"),
        ("xox" + "b-", "slack"),
        ("xap" + "p-", "slack"),
        ("AK" + "IA", "aws"),
        ("AS" + "IA", "aws"),
        ("AI" + "za", "google"),
        ("ya" + "29.", "google"),
        ("gh" + "p_", "github"),
        ("github_" + "pat_", "github"),
    ],
)
def test_recognizable_prefix_alone_cannot_establish_environment(prefix, provider):
    report = check({"CUSTOM_CREDENTIAL": prefix + FAKE})
    assert report.ok and report.unknown_count == 1
    assert report.findings[0].rule == provider + "-credential"
    assert not check({"CUSTOM_CREDENTIAL": FAKE + prefix}).findings


def test_postmark_test_token_and_separate_provider_modes():
    assert not check({"POSTMARK_SERVER_TOKEN": "POSTMARK_" + "API_TEST"}).findings
    report = check({"PAYPAL_MODE": "sandbox", "PAYPAL_CLIENT_SECRET": FAKE})
    assert report.unknown_count == 1
    assert report.findings[0].name == "PAYPAL_CLIENT_SECRET"


@pytest.mark.parametrize(
    "name",
    [
        "NODE_ENV",
        "APP_ENV",
        "ENVIRONMENT",
        "RAILS_ENV",
        "ASPNETCORE_ENVIRONMENT",
        "VERCEL_ENV",
        "RAILWAY_ENVIRONMENT_NAME",
        "DOTNET_ENVIRONMENT",
        "DEPLOYMENT_ENV",
    ],
)
def test_production_environment_markers(name):
    report = check({name: "  Production  "})
    assert not report.ok
    (finding,) = report.findings
    assert (finding.rule, finding.marker) == ("production-environment", "production")
    assert not check({name: "preview"}).findings
    assert not check({name: "preproduction"}).findings


@pytest.mark.parametrize(
    ("name", "url", "marker"),
    [
        ("DATABASE_URL", "postgres://user@" + "cache-PROD.example.invalid/db", "prod"),
        ("POSTGRES_PRISMA_URL", "postgres://db.example.invalid/app_production", "production"),
        ("REDIS_URL", "rediss://preview-live.example.invalid/0", "live"),
        ("MONGODB_URI", "mongodb://127.0.0.1,db-prod.example.invalid/db", "prod"),
        ("MONGODB_URI", "mongodb+srv://db.example.invalid/app_%6Cive", "live"),
        ("DATABASE_URL", "postgres://localhost/app-prod", "prod"),
        ("BILLING_SERVICE_URL", "https://production.example.invalid/v1", "production"),
    ],
)
def test_production_host_or_database_markers(name, url, marker):
    report = check({name: url})
    assert not report.ok
    (finding,) = report.findings
    assert finding.marker == marker
    assert finding.rule == ("service-url" if "SERVICE" in name else "database-url")


@pytest.mark.parametrize(
    "url",
    [
        "postgres://localhost./db",
        "postgres://127.1.2.3/db",
        "postgres://[::1]:5432/db",
        "postgres://[::ffff:127.0.0.1]/db",
        "postgres://db.localhost/db",
        "postgres://db-test.example.invalid/db",
        "postgres://db.staging.example.invalid/db",
        "postgres://db_dev.example.invalid/db",
        "postgres://db.example.invalid/db_preview",
        "postgres://db.example.invalid/db.sandbox",
        "postgres://u:live@db.test.example.invalid/app?password=production#prod",
        "postgres://localhost,db-test.example.invalid/app",
    ],
)
def test_loopback_and_test_destinations(url):
    assert not check({"DATABASE_URL": url}).findings


@pytest.mark.parametrize(
    "url",
    [
        "postgres://productivity.example.invalid/app",
        "postgres://db.example.invalid/preproduction",
        "postgres://db.example.invalid/app?password=production#live",
        "postgres://prod:live@db.example.invalid/app",
        "postgres://localhost@remote.example.invalid/app",
        "postgres://localhost,remote.example.invalid/app",
        "postgres://[bad-host/app",
        "postgres://[bad-host/app-production",
        "postgres:///app",
        FAKE,
    ],
)
def test_ambiguous_database_destinations_are_unknown(url):
    report = check({"DATABASE_URL": url})
    assert report.ok and report.unknown_count == 1
    assert report.findings[0].marker is None


def test_service_url_uses_host_and_ignores_http_path():
    assert not check({"BILLING_API_URL": "https://dev.example.invalid/production"}).findings
    assert check({"BILLING_API_URL": "https://db.example.invalid/test"}).unknown_count == 1


@pytest.mark.parametrize(
    ("name", "remote", "local", "rule"),
    [
        ("SLACK_WEBHOOK_URL", "https://prod.example.invalid/" + FAKE, "http://127.0.0.1/" + FAKE, "webhook-url"),
        ("WEBHOOK_DELIVERY_ENDPOINT", "https://sandbox.example.invalid", "http://[::1]:8000", "webhook-url"),
        ("SMTP_HOST", "smtp.example.invalid:587", "localhost:1025", "mail-endpoint"),
        ("MAIL_SERVER", "smtp.prod.example.invalid", "::1", "mail-endpoint"),
        ("MAILER_DSN", "smtp://user:" + FAKE + "@smtp.example.invalid", "smtp://127.0.0.1", "mail-endpoint"),
    ],
)
def test_webhook_and_mail_endpoints(name, remote, local, rule):
    report = check({name: remote})
    assert report.ok and report.unknown_count == 1
    assert report.findings[0].rule == rule
    assert report.findings[0].marker is None
    assert not check({name: local}).findings


def test_allow_retains_findings_and_excludes_them_from_counts():
    config = {
        "MY_KEY": "rk_" + "live_" + FAKE,
        "AWS_SESSION_TOKEN": FAKE,
        "UNRELATED": FAKE,
        "EMPTY": "",
    }
    report = check(config, allow=["MY_KEY", "AWS_SESSION_TOKEN", "ABSENT"])
    assert report.checked_count == 4
    assert report.ok and report.live_count == report.unknown_count == 0
    assert {f.name: (f.severity, f.allowed) for f in report.findings} == {
        "MY_KEY": ("live", True),
        "AWS_SESSION_TOKEN": ("unknown", True),
    }
    assert not check(config, allow=["my_key"]).ok


def test_env_file_parsing(tmp_path):
    path = tmp_path / "input.env"
    lines = [
        "\ufeff# heading",
        "",
        "  export\tA =   first  # tail",
        "A=last",
        "HASH=before#after",
        "STARTS_HASH=#literal",
        "EMPTY=  # comment",
        "EMPTY_QUOTED=''",
        "SPACED='  value # and =  ' # tail",
        r"""DOUBLE="quote:\" slash:\\ tab:\t newline:\n keep:\q"# tail""",
        r"""SINGLE='slash:\\ quote:\' literal:\n'""",
        "LITERAL=${A} $(echo value)",
        "EQUALS=a=b=c",
        "UTF8=é",
    ]
    path.write_bytes("\r\n".join(lines).encode("utf-8"))
    assert read_env_file(path) == {
        "A": "last",
        "HASH": "before#after",
        "STARTS_HASH": "#literal",
        "EMPTY": "",
        "EMPTY_QUOTED": "",
        "SPACED": "  value # and =  ",
        "DOUBLE": 'quote:" slash:\\ tab:\t newline:\n keep:\\q',
        "SINGLE": "slash:\\ quote:' literal:\\n",
        "LITERAL": "${A} $(echo value)",
        "EQUALS": "a=b=c",
        "UTF8": "é",
    }


@pytest.mark.parametrize(
    ("bad_line", "message"),
    [
        (FAKE, "Expected KEY=value on line 2."),
        ("9NAME=" + FAKE, "Expected KEY=value on line 2."),
        ("BAD=" + FAKE + "\x00", "Expected KEY=value on line 2."),
        ('TOKEN="' + FAKE, "Invalid quoted value on line 2."),
        ("TOKEN='closed' " + FAKE, "Invalid quoted value on line 2."),
    ],
)
def test_malformed_env_file_errors_are_redacted(tmp_path, capsys, bad_line, message):
    path = tmp_path / "bad.env"
    path.write_text("# heading\n" + bad_line, encoding="utf-8")
    with pytest.raises(EnvFileError) as caught:
        read_env_file(path)
    assert str(caught.value) == message
    assert FAKE not in repr(caught.value) + "".join(traceback.format_exception(caught.value))
    assert main(["sterile-check", "--env-file", str(path), "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert message in captured.err
    assert "violet-quasar" not in captured.err


def test_bad_encoding_is_redacted(tmp_path, capsys):
    path = tmp_path / "bad-encoding.env"
    path.write_bytes(b"API_KEY=" + FAKE.encode() + b"\xff")
    with pytest.raises(EnvFileError) as caught:
        read_env_file(path)
    assert caught.value.__context__ is None
    assert FAKE not in repr(caught.value)
    assert main(["sterile-check", "--env-file", str(path)]) == 2
    assert "violet-quasar" not in capsys.readouterr().err


def test_cli_usage_errors(tmp_path, capsys):
    assert main(["sterile-check"]) == 2
    captured = capsys.readouterr()
    assert "requires --env-file or --environment" in captured.err
    for path in (tmp_path, tmp_path / FAKE, "\x00" + FAKE):
        assert main(["sterile-check", "--env-file", str(path)]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Could not read the env file" in captured.err
        assert FAKE not in captured.err


@pytest.mark.parametrize("json_output", [False, True], ids=["plain", "json"])
def test_report_and_cli_output_redact_values(tmp_path, capsys, json_output):
    secrets = (
        "pretend-" + "key-turquoise-81",
        "pretend-" + "pass-amber-42",
        "pretend-" + "host-copper-43",
        "pretend-" + "db-lilac-44",
        "pretend-" + "query-ruby-45",
        "pretend-" + "hook-teal-46",
    )
    key, password, host, database, query, hook = secrets
    config = {
        "PAYMENT_KEY": "sk_" + "live_" + key,
        "DATABASE_URL": f"postgres://user:{password}@prod-{host}.example.invalid/{database}?token={query}",
        "WEBHOOK_URL": "https://hooks.example.invalid/" + hook,
    }
    report = check(config, allow=["PAYMENT_KEY"])
    path = tmp_path / "preview.env"
    path.write_text("\n".join(f"{name}={value}" for name, value in config.items()), encoding="utf-8")
    flags = ["--json"] if json_output else []
    assert main(["sterile-check", "--env-file", str(path), "--allow", "PAYMENT_KEY", *flags]) == 1
    captured = capsys.readouterr()
    for value in (*config.values(), *secrets, *(secret.removeprefix("pretend-") for secret in secrets)):
        assert value not in captured.out + captured.err + repr(report)
    assert captured.err == ""
    if json_output:
        data = json.loads(captured.out)
        assert data["ok"] is False
        assert (data["live_count"], data["unknown_count"], data["checked_count"]) == (1, 1, 3)
        assert {f["name"]: f["allowed"] for f in data["findings"]} == {
            "DATABASE_URL": False,
            "PAYMENT_KEY": True,
            "WEBHOOK_URL": False,
        }
    else:
        lines = captured.out.splitlines()
        assert len(lines) == 4
        assert "allowed by the owner" in lines[1] and "sk_live_" in lines[1]
        assert "Checked 3 variable(s). 1 live, 1 unknown" in lines[-1]


def test_cli_checks_all_sources_independently(tmp_path, monkeypatch, capsys):
    older = tmp_path / "older.env"
    newer = tmp_path / "newer.env"
    older.write_text("STRIPE_KEY=sk_" + "live_" + FAKE, encoding="utf-8")
    newer.write_text("STRIPE_KEY=sk_" + "test_" + FAKE, encoding="utf-8")
    monkeypatch.setattr(sterility, "os", SimpleNamespace(environ={"APP_ENV": "production", "RESEND_API_KEY": FAKE}))
    assert main(["sterile-check", "--environment", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert (data["live_count"], data["unknown_count"], data["checked_count"]) == (1, 1, 2)
    args = ["sterile-check", "--env-file", str(older), str(newer), "--environment", "--json"]
    assert main(args) == 1
    data = json.loads(capsys.readouterr().out)
    assert (data["live_count"], data["unknown_count"], data["checked_count"]) == (2, 1, 4)
    assert main([*args, "--allow", "STRIPE_KEY", "APP_ENV", "--allow", "RESEND_API_KEY"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] and len(data["findings"]) == 3
    assert all(f["allowed"] for f in data["findings"])
    assert main(["sterile-check", "--env-file", str(newer)]) == 0
    assert "0 live, 0 unknown" in capsys.readouterr().out
    assert main(["sterile-check", "--environment", "--allow", "APP_ENV"]) == 0
    assert "0 live, 1 unknown" in capsys.readouterr().out
