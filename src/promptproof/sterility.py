"""Check a test deployment's supplied configuration for known production signals.

A clean report means no unallowed live signal matched. It cannot establish which
configuration the deployment actually uses or whether an opaque credential or
endpoint belongs to production. The check runs locally and never contacts a service.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Collection, Mapping
from dataclasses import asdict, dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Literal
from urllib.parse import unquote

from promptproof.exits import EXIT_CHECK_FAILED, EXIT_FAILED, EXIT_OK


@dataclass(frozen=True)
class _Match:
    rule: str
    severity: Literal["live", "unknown"]
    reason: str
    marker: str | None = None


@dataclass(frozen=True, kw_only=True)
class Finding(_Match):
    name: str
    allowed: bool = False


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    checked_count: int

    @property
    def live_count(self) -> int:
        return sum(f.severity == "live" and not f.allowed for f in self.findings)

    @property
    def unknown_count(self) -> int:
        return sum(f.severity == "unknown" and not f.allowed for f in self.findings)

    @property
    def ok(self) -> bool:
        return self.live_count == 0


class EnvFileError(ValueError):
    """An env file could not be read or parsed."""


_ASSIGNMENT = re.compile(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)")
_QUOTED = re.compile(r"""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\s*(?:#.*)?""")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


def _env_value(raw: str, number: int) -> str:
    value = raw.lstrip()
    if value.startswith(('"', "'")):
        quoted = _QUOTED.fullmatch(value)
        if quoted is None:
            raise EnvFileError(f"Invalid quoted value on line {number}.")
        double, single = quoted.groups()
        if single is not None:
            return re.sub(r"\\(['\\])", r"\1", single)
        return re.sub(r"\\(.)", lambda m: _ESCAPES.get(m[1], m[0]), double)
    if raw[:1].isspace() and value.startswith("#"):
        return ""
    return re.split(r"\s+#", value, maxsplit=1)[0].rstrip()


def read_env_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Read literal UTF-8 assignments without executing or interpolating them."""
    try:
        with Path(path).open(encoding="utf-8-sig") as source:
            variables = {}
            for number, line in enumerate(source, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                assignment = _ASSIGNMENT.fullmatch(line)
                if assignment is None or "\x00" in line:
                    raise EnvFileError(f"Expected KEY=value on line {number}.")
                name, raw = assignment.groups()
                variables[name] = _env_value(raw, number)
            return variables
    except EnvFileError:
        raise
    except (OSError, ValueError):
        # A decoder or OS error can include bytes or other user-controlled text.
        pass
    raise EnvFileError("Could not read the env file as UTF-8.")


_PRODUCTION_MARKERS = ("prod", "production", "live")
_TEST_MARKERS = ("test", "staging", "dev", "preview", "sandbox")
_ENVIRONMENT_NAMES = {
    "NODE_ENV",
    "APP_ENV",
    "ENV",
    "ENVIRONMENT",
    "RAILS_ENV",
    "RACK_ENV",
    "FLASK_ENV",
    "ASPNETCORE_ENVIRONMENT",
    "DOTNET_ENVIRONMENT",
    "VERCEL_ENV",
    "VERCEL_TARGET_ENV",
    "RAILWAY_ENVIRONMENT_NAME",
    "RAILWAY_ENVIRONMENT",
    "DEPLOY_ENV",
    "DEPLOYMENT_ENV",
    "CONTEXT",  # Netlify deployment context
}

# These are application variable aliases for the providers' documented mode settings.
_MODES = (
    # https://developer.paypal.com/api/rest/requests/
    ("paypal", {"PAYPAL_MODE", "PAYPAL_ENV", "PAYPAL_ENVIRONMENT"}, ("live", "production"), ("sandbox",)),
    # https://developer.squareup.com/docs/devtools/sandbox/overview
    ("square", {"SQUARE_ENV", "SQUARE_ENVIRONMENT", "SQUARE_MODE"}, ("production",), ("sandbox",)),
    # https://developer.paypal.com/braintree/docs/start/go-live/node/
    ("braintree", {"BRAINTREE_ENV", "BRAINTREE_ENVIRONMENT"}, ("production",), ("sandbox",)),
    # https://developer.paddle.com/sdks/sandbox/
    ("paddle", {"PADDLE_ENV", "PADDLE_ENVIRONMENT"}, ("live", "production"), ("sandbox",)),
    # https://docs.adyen.com/development-resources/client-side-authentication
    ("adyen", {"ADYEN_ENV", "ADYEN_ENVIRONMENT"}, ("live",), ("test",)),
)

# The documented hosts identify the selected payment API, independently of its credentials.
_PAYMENT_ENDPOINTS = {
    "PAYPAL": ("api-m.paypal.com", "api-m.sandbox.paypal.com"),
    "SQUARE": ("connect.squareup.com", "connect.squareupsandbox.com"),
    "PADDLE": ("api.paddle.com", "sandbox-api.paddle.com"),
}

# Those with a distinctive documented prefix can also be recognized under arbitrary names.
# https://docs.stripe.com/keys
_STRIPE_LIVE = ("sk_live_", "rk_live_", "pk_live_")
_STRIPE_TEST = ("sk_test_", "rk_test_", "pk_test_")
# https://developer.paddle.com/api-reference/about/authentication/
_PADDLE_LIVE = "pdl_live_apikey_"
_PADDLE_TEST = "pdl_sdbx_apikey_"

# These formats or names identify a credential but lack a documented live/test
# discriminator. Each is unknown, even when a separate mode setting is present.
_OPAQUE_CREDENTIALS = (
    # https://docs.stripe.com/keys (includes webhook signing secrets)
    ("Stripe", r"STRIPE_(?:.*_)?(?:KEY|TOKEN|SECRET)", ("whsec_",)),
    # https://developer.paypal.com/api/rest/requests/
    ("PayPal", r"PAYPAL_(?:.*_)?(?:CLIENT_ID|SECRET|TOKEN)", ()),
    # https://developer.squareup.com/docs/build-basics/access-tokens
    ("Square", r"SQUARE_(?:.*_)?(?:ACCESS_TOKEN|APPLICATION_ID|APP_ID|SECRET)", ()),
    # https://developer.paypal.com/braintree/articles/control-panel/important-gateway-credentials/
    ("Braintree", r"BRAINTREE_(?:.*_)?(?:PUBLIC_KEY|PRIVATE_KEY|MERCHANT_ID|TOKEN)", ()),
    # https://developer.paddle.com/api-reference/about/authentication/ (legacy API keys)
    ("Paddle", r"PADDLE_(?:.*_)?(?:KEY|TOKEN|SECRET)", ()),
    # https://docs.adyen.com/development-resources/api-credentials
    ("Adyen", r"ADYEN_(?:.*_)?(?:KEY|TOKEN|SECRET|PASSWORD)", ()),
    # https://www.twilio.com/docs/iam/test-credentials
    ("Twilio", r"TWILIO_(?:.*_)?(?:ACCOUNT_SID|AUTH_TOKEN|API_KEY|API_KEY_SID|API_SECRET)", ()),
    # https://help.twilio.com/articles/10284917001627
    ("SendGrid", r"SENDGRID_(?:.*_)?(?:KEY|TOKEN)", ("SG.",)),
    # https://documentation.mailgun.com/docs/mailgun/api-reference/mg-auth
    ("Mailgun", r"MAILGUN_(?:.*_)?(?:KEY|TOKEN|PASSWORD)", ()),
    # https://postmarkapp.com/developer/user-guide/sandbox-mode
    ("Postmark", r"POSTMARK_(?:.*_)?(?:KEY|TOKEN|PASSWORD)", ()),
    # https://github.com/resend/resend-cli#authentication
    ("Resend", r"RESEND_(?:.*_)?(?:KEY|TOKEN)", ("re_",)),
    # https://docs.slack.dev/authentication/tokens/
    ("Slack", r"SLACK_(?:.*_)?(?:TOKEN|SECRET)", ("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxe-", "xapp-")),
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
    ("AWS", r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN)", ("AKIA", "ASIA")),
    # https://docs.cloud.google.com/endpoints/docs/openapi/get-started-app-engine
    # https://developers.google.com/android-publisher/authorization
    ("Google", r"(?:GOOGLE|GCP|GEMINI)_(?:.*_)?(?:KEY|TOKEN|CLIENT_SECRET|CREDENTIALS)", ("AIza", "ya29.")),
    # https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/github-credential-types
    (
        "GitHub",
        r"(?:GITHUB|GH)_(?:.*_)?(?:TOKEN|PAT|PRIVATE_KEY|CLIENT_SECRET)",
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    ),
)
_CREDENTIAL_RULES = tuple(
    (provider, re.compile(r"(?:^|_)" + names + "$"), prefixes) for provider, names, prefixes in _OPAQUE_CREDENTIALS
)

_DATABASE_URL = re.compile(
    r"(?:^|_)(?:DATABASE|DB|POSTGRES(?:QL)?|PG|MYSQL|MARIADB|MSSQL|SQLSERVER|SQLALCHEMY|"
    r"REDIS|VALKEY|MONGO(?:DB)?|AMQP|RABBITMQ|MEMCACHED|ELASTICSEARCH|OPENSEARCH)"
    r"_(?:[A-Z0-9]+_)*(?:URL|URI|DSN|CONNECTION_STRING)(?:_|$)"
)
_SERVICE_URL = re.compile(r"(?:^|_)(?:SERVICE|API|BASE)_(?:URL|URI)$")
_WEBHOOK_URL = re.compile(r"(?:^|_)WEBHOOK(?:_.*)?_(?:URL|URI|ENDPOINT)$")
_MAIL_ENDPOINT = re.compile(
    r"(?:^|_)(?:SMTP|MAIL|EMAIL|MAILER)(?:_SMTP|_SERVER|_TRANSPORT)?_(?:HOST|SERVER|URL|URI|DSN|ENDPOINT)$"
)
_URL = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*:)?//([^/?#]+)(/[^?#]*)?(?:[?#].*)?")
_HOST_PORT = re.compile(r"(\[[0-9A-Fa-f:.]+\]|[\w.-]+)(?::[0-9]+)?")


def _hosts(authority: str) -> tuple[str, ...]:
    hosts = []
    for address in authority.rsplit("@", 1)[-1].split(","):
        match = _HOST_PORT.fullmatch(address)
        if match is None:
            return ()
        hosts.append(match[1].strip("[]").lower().rstrip("."))
    return tuple(hosts)


def _loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ip_address(host)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return (mapped or address).is_loopback


def _words(value: str) -> set[str]:
    return set(re.findall(r"[^\W_]+", value.lower()))


def _endpoint(name: str, value: str) -> _Match | None:
    is_webhook = _WEBHOOK_URL.search(name)
    is_mail = _MAIL_ENDPOINT.search(name)
    is_database = _DATABASE_URL.search(name)
    if not (is_webhook or is_mail or is_database or _SERVICE_URL.search(name)):
        return None

    # Parse only the authority and path. Avoid URL parsers that cache raw URLs.
    url = _URL.fullmatch(value)
    hosts = _hosts(url[1]) if url else ()
    if is_webhook or is_mail:
        if is_mail and url is None:
            host = value.lower().rstrip(".")
            hosts = (host,) if _loopback(host) else _hosts(host)
        if hosts and all(map(_loopback, hosts)):
            return None
        rule, kind = ("webhook-url", "webhook") if is_webhook else ("mail-endpoint", "outbound mail")
        return _Match(rule, "unknown", f"No loopback destination could be established for this {kind} setting.")

    provider = name.partition("_")[0]
    if provider in _PAYMENT_ENDPOINTS and len(hosts) == 1:
        live, sandbox = _PAYMENT_ENDPOINTS[provider]
        if hosts[0] == sandbox:
            return None
        if hosts[0] == live:
            return _Match(f"{provider.lower()}-endpoint", "live", "This is the provider's documented production host.")

    database = unquote(url[2][1:].partition("/")[0]) if is_database and hosts and url and url[2] else ""
    database_words = _words(database)
    host_words = [_words(host) for host in hosts]
    words = database_words.union(*host_words)
    rule = "database-url" if is_database else "service-url"
    for marker in _PRODUCTION_MARKERS:
        if marker in words:
            return _Match(rule, "live", "The host or database name has a production marker.", marker)
    test_markers = set(_TEST_MARKERS)
    if hosts and (
        database_words & test_markers or all(_loopback(host) or parts & test_markers for host, parts in zip(hosts, host_words))
    ):
        return None
    return _Match(rule, "unknown", "The host or database name gives no clear environment signal.")


def _match(name: str, value: str) -> _Match | None:
    for prefix in _STRIPE_LIVE:
        if value.startswith(prefix):
            return _Match("stripe-key", "live", "Stripe identifies this prefix as live mode.", prefix)
    if value.startswith(_STRIPE_TEST + (_PADDLE_TEST,)):
        return None
    if value.startswith(_PADDLE_LIVE):
        return _Match("paddle-key", "live", "Paddle identifies this API key prefix as live mode.", _PADDLE_LIVE)

    for provider, names, live, test in _MODES:
        if name in names:
            mode = value.lower()
            for marker in live:
                if mode == marker:
                    return _Match(f"{provider}-mode", "live", "This mode selects the provider's production environment.", marker)
            if mode in test:
                return None
            return _Match(f"{provider}-mode", "unknown", "This mode does not identify a documented provider environment.")
    if name in _ENVIRONMENT_NAMES:
        for marker in _PRODUCTION_MARKERS:
            if value.lower() == marker:
                return _Match("production-environment", "live", "This setting declares a production environment.", marker)

    # Both client-key formats use generic prefixes, so require the provider in the name.
    # https://developer.paddle.com/paddle-js/about/client-side-tokens/
    # https://docs.adyen.com/development-resources/client-side-authentication
    for suffix, provider in (("PADDLE_CLIENT_TOKEN", "Paddle"), ("ADYEN_CLIENT_KEY", "Adyen")):
        if name == suffix or name.endswith("_" + suffix):
            if value.startswith("test_"):
                return None
            if value.startswith("live_"):
                return _Match(
                    f"{provider.lower()}-client-key", "live", f"{provider} identifies this client prefix as live mode.", "live_"
                )

    # https://postmarkapp.com/developer/api/overview (public no-delivery test value)
    if name in {"POSTMARK_API_KEY", "POSTMARK_API_TOKEN", "POSTMARK_SERVER_TOKEN", "POSTMARK_SERVER_API_TOKEN"}:
        if value == "POSTMARK_API_TEST":
            return None

    endpoint = _endpoint(name, value)
    if endpoint is not None:
        return endpoint
    for provider, names, prefixes in _CREDENTIAL_RULES:
        if names.search(name) or value.startswith(prefixes):
            return _Match(
                f"{provider.lower()}-credential",
                "unknown",
                f"The {provider} credential does not identify a live or test environment.",
            )
    return None


def check(variables: Mapping[str, str], allow: Collection[str] = ()) -> Report:
    """Report clues about production wiring without retaining any input values."""
    allowed = set(allow)
    findings = []
    for name, raw in sorted(variables.items()):
        value = raw.strip()
        if value and (match := _match(name.upper(), value)) is not None:
            findings.append(
                Finding(
                    match.rule,
                    match.severity,
                    match.reason,
                    match.marker,
                    name=name,
                    allowed=name in allowed,
                )
            )
    return Report(tuple(findings), len(variables))


def _command(args: argparse.Namespace) -> int:
    if not args.env_file and not args.environment:
        print("error: sterile-check requires --env-file or --environment.", file=sys.stderr)
        return EXIT_FAILED
    reports = []
    for number, path in enumerate(args.env_file, 1):
        try:
            reports.append(check(read_env_file(path), args.allow))
        except EnvFileError as error:
            print(f"error: --env-file #{number}. {error}", file=sys.stderr)
            return EXIT_FAILED
    if args.environment:
        reports.append(check(os.environ, args.allow))
    report = Report(
        tuple(f for source in reports for f in source.findings),
        sum(source.checked_count for source in reports),
    )
    if args.json:
        print(
            json.dumps(
                {
                    **asdict(report),
                    "live_count": report.live_count,
                    "unknown_count": report.unknown_count,
                    "ok": report.ok,
                },
                indent=2,
            )
        )
    else:
        for finding in report.findings:
            name = finding.name if finding.name.isprintable() else ascii(finding.name)
            marker = f" ({finding.marker})" if finding.marker is not None else ""
            allowed = " (allowed by the owner)" if finding.allowed else ""
            print(f"{name} [{finding.rule}, {finding.severity}]{marker}{allowed}. {finding.reason}")
        print(
            f"Checked {report.checked_count} variable(s). {report.live_count} live, "
            f"{report.unknown_count} unknown, {sum(f.allowed for f in report.findings)} allowed by the owner."
        )
    return EXIT_OK if report.ok else EXIT_CHECK_FAILED


def register(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser("sterile-check", help="check test deployment settings for production signals")
    parser.add_argument("--env-file", action="extend", nargs="+", default=[], metavar="PATH")
    parser.add_argument("--environment", action="store_true", help="check the current process environment")
    parser.add_argument(
        "--allow",
        action="extend",
        nargs="+",
        default=[],
        metavar="NAME",
        help="mark findings for these exact variable names as allowed by the owner",
    )
    parser.add_argument("--json", action="store_true", help="write a JSON report")
    parser.set_defaults(handler=_command)
