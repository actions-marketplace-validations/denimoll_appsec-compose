"""Generate the synthetic, line-labelled secrets corpus.

SYNTHETIC — every "secret" here is random bytes in the shape of a real
credential format. None was ever issued by a provider, so none is live. They
are generated at benchmark time (seeded, so byte-for-byte reproducible) and
never committed: a repository that shipped them would trip its own secret
scanning and GitHub push protection, and nothing in this file is a credential
until the generator runs.

Why synthetic: the one openly licensed, line-labelled real-world dataset,
Samsung CredData (Apache-2.0 metadata, per-repo licenses for the files), is
built by cloning ~300 repositories (19M lines) and then *obfuscates* every
value — fixed-format keys are replaced by provider example values, which
Gitleaks deliberately allowlists. Scoring a pattern scanner on it would
measure the obfuscation as much as the scanner. SecretBench is access-on-request
under a data agreement. See benchmark/RESULTS.md for what this costs us.

The corpus has two kinds of labelled lines:

- `secret` — a credential in a realistic context (config, code, CI, k8s).
  Missing one is a false negative.
- `decoy`  — something a careless scanner flags: provider example keys,
  placeholders, env-var references, hashes, UUIDs, public keys. Flagging one
  is a false positive.

Every other line is ordinary code; a finding on it is an unlabelled FP.
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import string

GENERATOR_VERSION = "1"
SEED = 20261102

UPPER = string.ascii_uppercase
ALNUM = string.ascii_letters + string.digits
B32 = string.ascii_uppercase + "234567"
B64 = string.ascii_letters + string.digits + "+/"
URLSAFE = string.ascii_letters + string.digits + "_-"
HEX = "0123456789abcdef"

# Assembled, not written out, so this file itself matches no secret rule.
_PEM = "-----{} {}-----"
_PRIV = "PRIVATE" + " KEY"


class _File:
    def __init__(self, path: str):
        self.path, self.lines, self.labels = path, [], []

    def add(self, text: str = "", label: str | None = None, kind: str | None = None):
        """Append one or more lines; label the whole span if asked."""
        start = len(self.lines) + 1
        self.lines.extend(text.split("\n"))
        if label:
            self.labels.append({"file": self.path, "line_start": start,
                                "line_end": len(self.lines), "label": label,
                                "kind": kind})


def _r(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _pem_body(rng: random.Random, prefix: str, lines: int) -> list[str]:
    body = prefix + _r(rng, B64, 64 * lines - len(prefix))
    return [body[i:i + 64] for i in range(0, len(body), 64)]


def build(seed: int = SEED) -> tuple[dict[str, str], list[dict]]:
    """Return ({relative path: content}, labels)."""
    rng = random.Random(seed)
    files: list[_File] = []

    def new(path: str) -> _File:
        f = _File(path)
        files.append(f)
        return f

    # -- Python settings module ------------------------------------------
    f = new("app/settings.py")
    f.add('"""Application settings."""\nimport os\n')
    f.add(f'AWS_ACCESS_KEY_ID = "AKIA{_r(rng, B32, 16)}"', "secret", "aws-access-key-id")
    f.add(f'AWS_SECRET_ACCESS_KEY = "{_r(rng, B64, 40)}"', "secret", "aws-secret-access-key")
    f.add(f'DB_PASSWORD = "{_r(rng, ALNUM, 18)}"', "secret", "generic-password")
    f.add(f'SECRET_KEY = "{_r(rng, ALNUM + "!@#%^&*(-_=+)", 50)}"', "secret", "django-secret-key")
    f.add('GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]', "decoy", "env-reference")
    f.add('SENTRY_DSN = os.getenv("SENTRY_DSN", "")', "decoy", "env-reference")
    # The AWS documentation's example key pair: published, inert, everywhere.
    f.add('EXAMPLE_KEY_ID = "AKIA' + 'IOSFODNN7EXAMPLE"  # from the AWS docs',
          "decoy", "aws-docs-example")
    f.add('EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/' + 'bPxRfiCYEXAMPLEKEY"  # from the AWS docs',
          "decoy", "aws-docs-example")
    f.add('API_KEY = "YOUR_API_KEY_HERE"', "decoy", "placeholder")
    f.add('ADMIN_PASSWORD = "changeme"  # overridden in production', "decoy", "low-entropy-password")
    f.add('TOKEN_URL = "https://oauth2.googleapis.com/token"', "decoy", "keyword-not-secret")
    f.add('\nDEBUG = False\nALLOWED_HOSTS = ["api.example.com"]\nTIME_ZONE = "UTC"')

    # -- dotenv -------------------------------------------------------------
    f = new("deploy/.env.production")
    f.add("# production environment")
    f.add(f"STRIPE_SECRET_KEY=sk_live_{_r(rng, ALNUM, 24)}", "secret", "stripe-secret-key")
    f.add(f"SENDGRID_API_KEY=SG.{_r(rng, URLSAFE, 22)}.{_r(rng, URLSAFE, 43)}", "secret", "sendgrid-api-key")
    f.add(f"TWILIO_API_KEY=SK{_r(rng, HEX, 32)}", "secret", "twilio-api-key")
    f.add(f"OPENAI_API_KEY=sk-proj-{_r(rng, URLSAFE, 74)}T3BlbkFJ{_r(rng, URLSAFE, 74)}",
          "secret", "openai-api-key")
    f.add(f"ANTHROPIC_API_KEY=sk-ant-api03-{_r(rng, URLSAFE, 93)}AA", "secret", "anthropic-api-key")
    f.add("PAYPAL_CLIENT_SECRET=${PAYPAL_CLIENT_SECRET}", "decoy", "template-variable")
    f.add("SMTP_PASSWORD=********", "decoy", "masked")
    f.add("LOG_LEVEL=info\nPORT=8080")

    # -- JavaScript client ----------------------------------------------------
    f = new("web/src/client.js")
    f.add("import axios from 'axios';\n")
    f.add(f"const GITHUB_PAT = 'ghp_{_r(rng, ALNUM, 36)}';", "secret", "github-pat")
    f.add(f"const GH_FINE_GRAINED = 'github_pat_{_r(rng, ALNUM, 22)}_{_r(rng, ALNUM, 59)}';",
          "secret", "github-fine-grained-pat")
    f.add(f"const MAPS_KEY = 'AIza{_r(rng, URLSAFE, 35)}';", "secret", "google-api-key")
    f.add(f"const SLACK_WEBHOOK = 'https://hooks.slack.com/services/T{_r(rng, UPPER + string.digits, 8)}"
          f"/B{_r(rng, UPPER + string.digits, 8)}/{_r(rng, ALNUM, 24)}';", "secret", "slack-webhook")
    f.add("const PLACEHOLDER_PAT = 'ghp_" + "x" * 36 + "';", "decoy", "placeholder")
    u = f"{rng.getrandbits(128):032x}"
    f.add(f"const TRACE_ID = '{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}';",
          "decoy", "uuid")
    f.add("\nexport async function getUser(id) {\n  return axios.get(`/api/users/${id}`);\n}")

    # -- .npmrc ------------------------------------------------------------------
    f = new("web/.npmrc")
    f.add("registry=https://registry.npmjs.org/")
    f.add(f"//registry.npmjs.org/:_authToken=npm_{_r(rng, ALNUM, 36)}", "secret", "npm-token")

    # -- CI config ----------------------------------------------------------------
    f = new(".gitlab-ci.yml")
    f.add("stages: [build]\n\nbuild:\n  stage: build\n  variables:")
    f.add(f"    GITLAB_TOKEN: glpat-{_r(rng, URLSAFE, 20)}", "secret", "gitlab-pat")
    f.add(f"    SLACK_BOT_TOKEN: xoxb-{rng.randrange(10**11, 10**12)}-{rng.randrange(10**12, 10**13)}-{_r(rng, ALNUM, 24)}",
          "secret", "slack-bot-token")
    f.add("    DEPLOY_TOKEN: $CI_DEPLOY_TOKEN", "decoy", "template-variable")
    f.add("  script:\n    - make build")

    # -- Private keys -------------------------------------------------------------
    f = new("deploy/id_rsa")
    key = [_PEM.format("BEGIN", "RSA " + _PRIV),
           *_pem_body(rng, "MIIEowIBAAKCAQEA", 25),
           _PEM.format("END", "RSA " + _PRIV)]
    f.add("\n".join(key), "secret", "rsa-private-key")

    f = new("deploy/gcp-service-account.json")
    body = "\\n".join(_pem_body(rng, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", 25))
    pk = (_PEM.format("BEGIN", _PRIV) + "\\n" + body + "\\n" + _PEM.format("END", _PRIV) + "\\n")
    # The whole key file is one credential: an engine pointing at its `type`
    # line has found the same secret as one pointing at `private_key`.
    f.add("\n".join([
        "{",
        '  "type": "service_account",',
        '  "project_id": "acme-prod",',
        f'  "private_key_id": "{_r(rng, HEX, 40)}",',
        f'  "private_key": "{pk}",',
        '  "client_email": "deployer@acme-prod.iam.gserviceaccount.com"',
        "}"]), "secret", "gcp-service-account-key")

    f = new("deploy/server.pub.pem")
    pub = [_PEM.format("BEGIN", "PUBLIC KEY"),
           *_pem_body(rng, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 6),
           _PEM.format("END", "PUBLIC KEY")]
    f.add("\n".join(pub), "decoy", "public-key")

    # -- Java service ---------------------------------------------------------------
    f = new("service/src/main/java/com/acme/Billing.java")
    f.add("package com.acme;\n\nimport java.sql.Connection;\nimport java.sql.DriverManager;\n")
    f.add("public class Billing {")
    f.add(f'    private static final String API_SECRET = "{_r(rng, ALNUM, 32)}";', "secret", "generic-api-secret")
    f.add(f'    private static final String DB_URL = "jdbc:postgresql://db.internal:5432/billing?user=billing&password={_r(rng, ALNUM, 16)}";',
          "secret", "connection-string-password")
    f.add('    private static final String PASSWORD_PARAM = "password";', "decoy", "keyword-not-secret")
    f.add('\n    Connection connect() throws Exception {\n        return DriverManager.getConnection(DB_URL);\n    }\n}')

    # -- Python worker ------------------------------------------------------------------
    f = new("worker/tasks.py")
    f.add("import hashlib\nimport requests\n")
    f.add(f'BROKER_URL = "amqp://worker:{_r(rng, ALNUM, 20)}@rabbitmq.internal:5672//"',
          "secret", "url-embedded-password")
    f.add(f'DATABASE_URL = "postgres://app:{_r(rng, ALNUM, 20)}@db.internal:5432/app"',
          "secret", "url-embedded-password")
    jwt = ".".join([_b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()),
                    _b64url(json.dumps({"sub": "svc-worker", "iat": 1767225600,
                                        "role": "admin"}).encode()),
                    _b64url(rng.randbytes(32))])
    f.add(f'SERVICE_JWT = "{jwt}"', "secret", "jwt")
    f.add(f'PASSWORD_SALT_TEST_VECTOR = "{_r(rng, HEX, 32)}"  # RFC test vector', "decoy", "test-vector")
    f.add("\n\ndef fetch(url):\n    return requests.get(url, timeout=10).json()")

    # -- Infra --------------------------------------------------------------------------
    f = new("k8s/secret.yaml")
    # Labelled as the whole Secret object: Gitleaks' kubernetes rule reports
    # the `kind: Secret` line, its generic rule the value line — same secret.
    f.add("apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-db\ntype: Opaque\ndata:\n"
          f"  password: {base64.b64encode(_r(rng, ALNUM, 20).encode()).decode()}",
          "secret", "k8s-secret-base64")

    f = new("docker-compose.yml")
    f.add("services:\n  db:\n    image: postgres:16\n    environment:")
    f.add(f"      POSTGRES_PASSWORD: {_r(rng, ALNUM, 20)}", "secret", "generic-password")
    f.add("  cache:\n    image: redis:7")

    f = new("infra/storage.tf")
    f.add('resource "azurerm_storage_account" "logs" {\n  name = "acmelogs"\n}\n')
    f.add('locals {')
    f.add(f'  storage_conn = "DefaultEndpointsProtocol=https;AccountName=acmelogs;AccountKey={_r(rng, B64, 86)}==;EndpointSuffix=core.windows.net"',
          "secret", "azure-storage-key")
    f.add("}")

    # -- High-entropy things that are not secrets ---------------------------------------
    f = new("release/SHA256SUMS")  # not dist/: a default exclude
    for name in ("app-linux-amd64.tar.gz", "app-darwin-arm64.tar.gz"):
        f.add(f"{hashlib.sha256(rng.randbytes(64)).hexdigest()}  {name}", "decoy", "checksum")

    f = new("CHANGELOG.md")
    f.add("# Changelog\n\n## 1.4.2\n")
    f.add(f"- Fix token refresh race (commit {_r(rng, HEX, 40)})", "decoy", "commit-sha")
    f.add("- Bump dependencies")

    f = new("web/package-lock.json")
    integrity = "sha512-" + base64.b64encode(rng.randbytes(64)).decode()
    f.add('{\n  "name": "web",\n  "lockfileVersion": 3,\n  "packages": {\n    "node_modules/left-pad": {\n      "version": "1.3.0",')
    f.add(f'      "integrity": "{integrity}"', "decoy", "integrity-hash")
    f.add("    }\n  }\n}")

    f = new("web/src/logo.css")
    f.add(f'.logo {{ background: url("data:image/png;base64,{base64.b64encode(rng.randbytes(60)).decode()}"); }}',
          "decoy", "data-uri")

    contents = {f.path: "\n".join(f.lines) + "\n" for f in files}
    labels = [lab for f in files for lab in f.labels]
    return contents, labels
