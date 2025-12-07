#!/usr/bin/env python3
"""
pallas-vault-manager

BigQuery-backed secret catalog with KMS encryption and Secret Manager sync.

- Secrets are stored as KMS-encrypted ciphertext in BigQuery (no plaintext at rest).
- This tool is intended for local, human-only use on macOS devices that are MDM/Jamf enrolled.
- CI usage is blocked by IAM convention (no service-account access to KMS+BQ+SM) rather than TTY hacks.
"""

import argparse
import base64
import json
import os
import platform
import sys
import uuid
import warnings
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from getpass import getpass
from typing import Any, Dict, List, Optional, Tuple

from pyfiglet import Figlet
from google.api_core.exceptions import NotFound
from google.cloud import bigquery
from google.cloud import kms_v1
from google.cloud import secretmanager_v1
import google.auth
from google.auth.transport.requests import AuthorizedSession

try:
    import pyperclip  # optional, best-effort clipboard clearing
except ImportError:  # pragma: no cover - optional dependency
    pyperclip = None

# ---------------------------------------------------------------------------
# Colors / terminal formatting
# ---------------------------------------------------------------------------

COLOR_RESET = "\033[0m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[34m"  # neutral blue instead of bright cyan
COLOR_BOLD = "\033[1m"

# Suppress noisy ADC user-creds warning (quota project)
warnings.filterwarnings(
    "ignore",
    message="Your application has authenticated using end user credentials from Google Cloud SDK without a quota project",
    category=UserWarning,
)

# ---------------------------------------------------------------------------
# Config file helpers
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.expanduser("~"), ".config", "pallas-vault-manager", "config.json"
)
CONFIG_PATH = DEFAULT_CONFIG_PATH


def set_config_path(path: Optional[str]) -> None:
    """Override global CONFIG_PATH (supports -C / --config)."""
    global CONFIG_PATH
    if path:
        CONFIG_PATH = os.path.expanduser(path)


def load_config() -> Dict[str, Any]:
    """Load JSON config from disk, or return empty dict if missing/broken."""
    if not os.path.isfile(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"{COLOR_RED}ERROR loading config {CONFIG_PATH}: {e}{COLOR_RESET}", file=sys.stderr)
        return {}


def save_config(cfg: Dict[str, Any]) -> None:
    """
    Persist config and lock permissions.

    Config file is the only local state; we chmod 0600 to reduce leakage.
    """
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)

    # Enforce 0600 on config file
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except PermissionError:
        print(
            f"{COLOR_YELLOW}Warning: could not chmod 600 on {CONFIG_PATH}. "
            f"Check file permissions manually.{COLOR_RESET}",
            file=sys.stderr,
        )


def get_cfg(
    cfg: Dict[str, Any],
    key: str,
    env_var: Optional[str] = None,
    required: bool = True,
) -> Optional[str]:
    """
    Get a config value with optional env var fallback.

    Precedence: config[key] -> env_var -> error (if required).
    """
    if key in cfg and cfg[key]:
        return cfg[key]
    if env_var:
        v = os.getenv(env_var)
        if v:
            return v
    if required:
        print(
            f"{COLOR_RED}Missing required config value '{key}'. "
            f"Run 'pallas-vault-manager configure' first.{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)
    return None


def prompt_with_default(prompt: str, default: Optional[str]) -> str:
    """Prompt with an optional default, treating empty input as 'accept default'."""
    if default:
        text = f"{prompt} [{default}]: "
    else:
        text = f"{prompt}: "
    val = input(text).strip()
    return val or (default or "")


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    """Simple Y/N prompt with default."""
    suffix = "[Y/n]" if default else "[y/N]"
    resp = input(f"{prompt} {suffix} ").strip().lower()
    if not resp:
        return default
    return resp in ("y", "yes")


# ---------------------------------------------------------------------------
# ASCII banner / header
# ---------------------------------------------------------------------------

_figlet = Figlet(font="slant")


def print_banner(command: str, cfg: Optional[Dict[str, Any]] = None) -> None:
    """Render a banner + basic config context at the top of each run."""
    title = "Pallas Vault Manager"
    art = _figlet.renderText(title)
    for line in art.splitlines():
        print(f"{COLOR_CYAN}{line.center(100)}{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'=' * 100}{COLOR_RESET}")
    print("Command           : {}".format(command))
    print("-" * 100)
    if cfg:
        org_id = cfg.get("gcp_org_id", "<not set>")
        bq_project = cfg.get("bq_project", "<not set>")
        bq_dataset = cfg.get("bq_dataset", "<not set>")
        bq_table = cfg.get("bq_table", "<not set>")
        kms_project = cfg.get("kms_project", "<not set>")
        kms_location = cfg.get("kms_location", "<not set>")
        kms_keyring = cfg.get("kms_keyring", "<not set>")
        kms_key = cfg.get("kms_key", "<not set>")
        fq_table = f"{bq_project}.{bq_dataset}.{bq_table}"
        kms_res = (
            f"projects/{kms_project}/locations/{kms_location}/"
            f"keyRings/{kms_keyring}/cryptoKeys/{kms_key}"
        )
        # These values stay white for readability
        print(f"  Config file     : {CONFIG_PATH}")
        print(f"  GCP Org ID      : {org_id}")
        print(f"  BigQuery        : {fq_table}")
        print(f"  KMS key         : {kms_res}")
    print(f"{COLOR_CYAN}{'=' * 100}{COLOR_RESET}")
    print()


# ---------------------------------------------------------------------------
# Secret input helpers (hidden multi-line, size limits, clipboard clearing)
# ---------------------------------------------------------------------------

MAX_SECRET_BYTES = 65536
MAX_SECRET_LINES = 2048


def clear_clipboard_if_possible() -> None:
    """Best-effort clipboard clearing after secret entry."""
    if pyperclip is None:
        return
    try:
        pyperclip.copy("")
    except Exception:
        # Best-effort only; failure is non-fatal.
        pass


def prompt_multiline_secret() -> str:
    """
    Hidden multi-line secret input.

    Uses getpass() per line so value never echoes; ENTER on an empty line to finish.
    """
    print("Enter secret value (hidden, multi-line).")
    print("Press ENTER on an empty line to finish.")
    lines: List[str] = []
    line_count = 0
    while True:
        line = getpass("")
        if line == "":
            break
        lines.append(line)
        line_count += 1
        if line_count > MAX_SECRET_LINES:
            print(
                f"{COLOR_RED}Secret exceeds maximum allowed lines "
                f"({MAX_SECRET_LINES}). Aborting.{COLOR_RESET}",
                file=sys.stderr,
            )
            # Clear in-memory copy before exit
            for i in range(len(lines)):
                lines[i] = ""
            raise SystemExit(1)
    secret = "\n".join(lines)
    # Best-effort wipe of intermediate buffers
    for i in range(len(lines)):
        lines[i] = ""
    return secret


def ensure_secret_size_ok(plaintext: str) -> None:
    """Guardrail: limit secret size so KMS calls don't blow up on us."""
    size = len(plaintext.encode("utf-8"))
    if size > MAX_SECRET_BYTES:
        print(
            f"{COLOR_RED}Secret is too large for KMS (size={size} bytes, "
            f"limit={MAX_SECRET_BYTES}). Aborting.{COLOR_RESET}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def clear_sensitive_text(*vars_to_clear: Any) -> None:
    """
    Best-effort zeroing of Python string variables.

    Not perfect (Python internals keep copies), but avoids obvious reuse.
    """
    for var in vars_to_clear:
        if isinstance(var, str):
            var = ""  # noqa: F841 (intentional)
    # Can't truly zero Python internals, but this avoids obvious reuse.


# ---------------------------------------------------------------------------
# Environment / Identity / Network guardrails
# ---------------------------------------------------------------------------


def ensure_macos_and_mdm_enrolled() -> None:
    """
    Ensure we are on macOS and MDM-enrolled.

    Uses `profiles status -type enrollment`. Hard-fails if not enrolled.
    """
    if platform.system() != "Darwin":
        print(f"{COLOR_RED}This tool is restricted to macOS clients.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)

    try:
        proc = subprocess.run(
            ["profiles", "status", "-type", "enrollment"],
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:
        print(
            f"{COLOR_RED}Cannot run 'profiles' to verify MDM enrollment: {e}{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    if "MDM enrollment: Yes" not in out and "Enrolled via DEP: Yes" not in out:
        print(
            f"{COLOR_RED}Mac does not appear MDM-enrolled. Aborting.{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)


def get_adc_session(scopes: List[str]) -> Tuple[AuthorizedSession, str, Optional[str]]:
    """
    Return an AuthorizedSession plus (email, display_name) of the caller.

    This is the canonical identity used for 'created_by' and logs.
    """
    creds, _ = google.auth.default(scopes=scopes)
    session = AuthorizedSession(creds)

    resp = session.get("https://www.googleapis.com/oauth2/v2/userinfo")
    if resp.status_code != 200:
        print(f"{COLOR_RED}Failed to get userinfo: {resp.status_code} {resp.text}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    data = resp.json()
    email = data.get("email")
    name = data.get("name")
    if not email:
        print(f"{COLOR_RED}Could not determine ADC user email.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    return session, email, name


def ensure_org_access(cfg: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """
    Verify ADC identity is a human and has access to the configured org.

    Blocks service accounts and identities that can't see org/<org_id>.
    """
    org_id = get_cfg(cfg, "gcp_org_id", required=True)
    scopes = [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]
    session, email, name = get_adc_session(scopes)

    if email.endswith("gserviceaccount.com"):
        print(
            f"{COLOR_RED}This tool must be run as a human user, not a service account "
            f"({email}). Aborting.{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    url = f"https://cloudresourcemanager.googleapis.com/v1/organizations/{org_id}"
    resp = session.get(url)
    if resp.status_code != 200:
        print(
            f"{COLOR_RED}ADC user '{email}' cannot access org '{org_id}': "
            f"HTTP {resp.status_code} {resp.text}{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)
    return email, name


# ---------------------------------------------------------------------------
# Cloudflare WARP verification (client-side posture)
# ---------------------------------------------------------------------------


def is_warp_cli_installed() -> bool:
    """
    Best-effort check that Cloudflare WARP CLI (warp-cli) is installed.

    We don't trust this alone for connectivity; it just proves the client
    is present on the machine.
    """
    candidates = [
        ["warp-cli"],
        ["/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli"],
    ]
    for cmd in candidates:
        try:
            proc = subprocess.run(
                cmd + ["--version"],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            continue
        if proc.returncode == 0 or proc.stdout or proc.stderr:
            return True
    return False


def ensure_cloudflare_warp_connected_via_trace(require_gateway: bool = True) -> None:
    """
    Ensure Cloudflare WARP is installed *and* traffic is actually going
    through WARP by calling the Cloudflare trace URL.

    - Validates warp and (optionally) gateway flags in the trace response.
    - Still only client-side assurance; backend enforcement should complement this.
    """
    if not is_warp_cli_installed():
        print(
            f"{COLOR_RED}Cloudflare WARP client (warp-cli) does not appear to be installed on this system.{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    url = "https://www.cloudflare.com/cdn-cgi/trace"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        print(
            f"{COLOR_RED}Failed to reach Cloudflare trace endpoint ({url}): {e}{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(
            f"{COLOR_RED}Unexpected error while calling Cloudflare trace endpoint: {e}{COLOR_RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    warp_status: Optional[str] = None
    gateway_status: Optional[str] = None

    # Parse key-value 'trace' output (warp=, gateway=, etc.)
    for line in body.splitlines():
        if line.startswith("warp="):
            warp_status = line.split("=", 1)[1].strip().lower()
        elif line.startswith("gateway="):
            gateway_status = line.split("=", 1)[1].strip().lower()

    # Accept common variants: on, plus, warp, 1
    valid_warp = {"on", "plus", "warp", "1"}
    if warp_status not in valid_warp:
        print(
            f"{COLOR_RED}Cloudflare trace indicates WARP is not active (warp={warp_status!r}).{COLOR_RESET}",
            file=sys.stderr,
        )
        print("Cloudflare trace response:")
        print(body.rstrip())
        sys.exit(1)

    if require_gateway:
        valid_gateway = {"on", "1"}
        if gateway_status not in valid_gateway:
            print(
                f"{COLOR_RED}Cloudflare trace indicates Gateway/Teams is not active (gateway={gateway_status!r}).{COLOR_RESET}",
                file=sys.stderr,
            )
            print("Cloudflare trace response:")
            print(body.rstrip())
            sys.exit(1)

    print(
        f"{COLOR_GREEN}Cloudflare WARP connectivity verified via trace URL "
        f"(warp={warp_status}, gateway={gateway_status}).{COLOR_RESET}"
    )


# ---------------------------------------------------------------------------
# KMS helpers (encryption, rotation status, round-trip test)
# ---------------------------------------------------------------------------


def kms_client() -> kms_v1.KeyManagementServiceClient:
    """Thin wrapper for KMS client construction."""
    return kms_v1.KeyManagementServiceClient()


def kms_key_name(cfg: Dict[str, Any]) -> str:
    """Build the fully-qualified KMS key name from config."""
    proj = get_cfg(cfg, "kms_project", "KMS_PROJECT")
    loc = get_cfg(cfg, "kms_location", "KMS_LOCATION")
    ring = get_cfg(cfg, "kms_keyring", "KMS_KEYRING")
    key = get_cfg(cfg, "kms_key", "KMS_KEY")
    return f"projects/{proj}/locations/{loc}/keyRings/{ring}/cryptoKeys/{key}"


def encrypt_with_kms(cfg: Dict[str, Any], plaintext: str) -> str:
    """Encrypt plaintext with KMS and return base64 ciphertext."""
    ensure_secret_size_ok(plaintext)
    client = kms_client()
    name = kms_key_name(cfg)
    resp = client.encrypt(request={"name": name, "plaintext": plaintext.encode("utf-8")})
    ct_b64 = base64.b64encode(resp.ciphertext).decode("ascii")
    clear_sensitive_text(plaintext)
    return ct_b64


def decrypt_with_kms(cfg: Dict[str, Any], ciphertext_b64: str) -> bytes:
    """Decrypt base64 ciphertext via KMS and return raw bytes."""
    client = kms_client()
    name = kms_key_name(cfg)
    ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"))
    resp = client.decrypt(request={"name": name, "ciphertext": ciphertext})
    return resp.plaintext


def print_kms_rotation_status(cfg: Dict[str, Any]) -> None:
    """Show KMS key rotation period and age of the primary version."""
    client = kms_client()
    name = kms_key_name(cfg)
    key = client.get_crypto_key(request={"name": name})

    print("KMS key details:")
    print(f"  Resource name: {name}")

    rotation_period = getattr(key, "rotation_period", None)
    if rotation_period:
        days = None
        if isinstance(rotation_period, timedelta):
            days = rotation_period.days
        elif hasattr(rotation_period, "seconds") and hasattr(rotation_period, "nanos"):
            total_seconds = rotation_period.seconds + rotation_period.nanos / 1e9
            days = int(total_seconds // 86400)
        if days is not None:
            print(f"  Rotation period: {days} days")
        else:
            print(f"  Rotation period: {rotation_period}")
    else:
        print(f"{COLOR_YELLOW}  Rotation: DISABLED (no rotation_period set){COLOR_RESET}")

    primary = getattr(key, "primary", None)
    if primary and primary.create_time:
        created = primary.create_time
        if hasattr(created, "seconds") and hasattr(created, "nanos"):
            ts = created.seconds + created.nanos / 1e9
            created_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        else:
            if getattr(created, "tzinfo", None) is None:
                created_dt = created.replace(tzinfo=timezone.utc)
            else:
                created_dt = created.astimezone(timezone.utc)

        days_since = (datetime.now(timezone.utc) - created_dt).days
        if days_since < 90:
            color = COLOR_GREEN
        elif days_since < 180:
            color = COLOR_YELLOW
        else:
            color = COLOR_RED

        print(f"  Primary version: {primary.name}")
        print(f"  Primary created: {created_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Days since primary created: {color}{days_since} days{COLOR_RESET}")
    else:
        print(f"{COLOR_YELLOW}  No primary version info available.{COLOR_RESET}")


def test_kms_roundtrip(cfg: Dict[str, Any]) -> None:
    """
    Health-check: encrypt + decrypt a static test string.

    Hard-fails the run if KMS isn't working as expected.
    """
    try:
        ct = encrypt_with_kms(cfg, "pallas-vault-manager-test")
        pt = decrypt_with_kms(cfg, ct).decode("utf-8")
        if pt != "pallas-vault-manager-test":
            raise RuntimeError("round-trip mismatch")
        clear_sensitive_text(pt)
        print(f"{COLOR_GREEN}KMS encrypt/decrypt test successful.{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}KMS test failed: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# BigQuery helpers (catalog access)
# ---------------------------------------------------------------------------


def bq_client(cfg: Dict[str, Any]) -> bigquery.Client:
    """Construct a BigQuery client pinned to the configured BQ project."""
    project = get_cfg(cfg, "bq_project", "BQ_PROJECT")
    return bigquery.Client(project=project)


def bq_table_info(cfg: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Return (project, dataset, table, fq_table) for the secrets catalog."""
    proj = get_cfg(cfg, "bq_project", "BQ_PROJECT")
    dataset = get_cfg(cfg, "bq_dataset", "BQ_DATASET")
    table = get_cfg(cfg, "bq_table", "BQ_TABLE")
    fq = f"{proj}.{dataset}.{table}"
    return proj, dataset, table, fq


def test_bq_connection(cfg: Dict[str, Any]) -> None:
    """Simple SELECT 1 connectivity check for BigQuery."""
    client = bq_client(cfg)
    try:
        job = client.query("SELECT 1 AS ok")
        _ = list(job.result())
        print(f"{COLOR_GREEN}BigQuery connectivity verified (project = {client.project}).{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}BigQuery connectivity test failed: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)


def insert_catalog_row(cfg: Dict[str, Any], row: Dict[str, Any]) -> None:
    """
    Insert a row using a load job (avoids streaming buffer issues).

    We block on job.result() so the row is visible immediately (for --sync-now).
    """
    client = bq_client(cfg)
    proj, dataset, table, fq_table = bq_table_info(cfg)
    table_ref = client.dataset(dataset).table(table)

    job = client.load_table_from_json(
        [row],
        table_ref,
        job_config=bigquery.LoadJobConfig(write_disposition="WRITE_APPEND"),
    )
    try:
        job.result()
    except Exception as e:
        print(f"{COLOR_RED}BigQuery load job failed on {fq_table}: {e}{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)


def query_unsynced_rows(cfg: Dict[str, Any], args: argparse.Namespace) -> List[Dict[str, Any]]:
    """
    Query unsynced, active secrets from the catalog.

    Supports filtering by bundle_id / secret_id and a LIMIT.
    """
    _, _, _, fq_table = bq_table_info(cfg)
    client = bq_client(cfg)

    where_clauses = ["is_active = TRUE", "last_synced_at IS NULL"]
    params: List[bigquery.ScalarQueryParameter] = []

    if getattr(args, "bundle_id", None):
        where_clauses.append("bundle_id = @bundle_id")
        params.append(bigquery.ScalarQueryParameter("bundle_id", "STRING", args.bundle_id))
    if getattr(args, "secret_id", None):
        where_clauses.append("secret_id = @secret_id")
        params.append(bigquery.ScalarQueryParameter("secret_id", "STRING", args.secret_id))

    where_sql = " AND ".join(where_clauses)

    query = f"""
    SELECT
      secret_record_id,
      bundle_id,
      secret_id,
      target_project,
      ciphertext_b64,
      allowed_service_accounts,
      created_by,
      created_at
    FROM `{fq_table}`
    WHERE {where_sql}
    ORDER BY created_at ASC
    """

    if getattr(args, "limit", None) is not None:
        query += "\n    LIMIT @limit"
        params.append(bigquery.ScalarQueryParameter("limit", "INT64", args.limit))

    job = client.query(
        query,
        job_config=bigquery.QueryJobConfig(query_parameters=params),
    )
    rows = list(job.result())

    results: List[Dict[str, Any]] = []
    for r in rows:
        results.append(
            {
                "secret_record_id": r["secret_record_id"],
                "bundle_id": r["bundle_id"],
                "secret_id": r["secret_id"],
                "target_project": r["target_project"],
                "ciphertext_b64": r["ciphertext_b64"],
                "allowed_service_accounts": r["allowed_service_accounts"],
                "created_by": r["created_by"],
                "created_at": r["created_at"],
            }
        )
    return results


def mark_rows_synced(cfg: Dict[str, Any], record_ids: List[str]) -> None:
    """
    Bulk-mark rows as synced by secret_record_id.

    This uses UNNEST(@ids) to update many rows in a single query.
    """
    if not record_ids:
        return
    client = bq_client(cfg)
    _, _, _, fq_table = bq_table_info(cfg)

    query = f"""
    UPDATE `{fq_table}`
    SET last_synced_at = CURRENT_TIMESTAMP()
    WHERE secret_record_id IN UNNEST(@ids)
      AND last_synced_at IS NULL
    """
    job = client.query(
        query,
        job_config=bigquery.QueryJobConfig(
            query_parameters=[bigquery.ArrayQueryParameter("ids", "STRING", record_ids)]
        ),
    )
    job.result()


# ---------------------------------------------------------------------------
# Secret Manager helpers (secret existence, versions, IAM for SAs)
# ---------------------------------------------------------------------------


def sm_client() -> secretmanager_v1.SecretManagerServiceClient:
    """Thin wrapper for Secret Manager client."""
    return secretmanager_v1.SecretManagerServiceClient()


def test_sm_permissions_for_create(project_id: str) -> bool:
    """
    Best-effort check for secretmanager.secrets.create.

    We don't fail the whole flow if the permission check itself fails.
    """
    client = sm_client()
    resource = f"projects/{project_id}"
    perms = ["secretmanager.secrets.create"]
    try:
        resp = client.test_iam_permissions(
            request={"resource": resource, "permissions": perms}
        )
    except Exception:
        # Best-effort hint only; don't block on failure to test.
        return True
    return "secretmanager.secrets.create" in resp.permissions


def test_sm_permissions_for_add_version(project_id: str, secret_id: str) -> bool:
    """Best-effort check for secretmanager.versions.add."""
    client = sm_client()
    resource = f"projects/{project_id}/secrets/{secret_id}"
    perms = ["secretmanager.versions.add"]
    try:
        resp = client.test_iam_permissions(
            request={"resource": resource, "permissions": perms}
        )
    except Exception:
        return True
    return "secretmanager.versions.add" in resp.permissions


def ensure_secret_exists(
    project_id: str,
    secret_id: str,
    auto_create: bool,
    regions_cache: Dict[str, List[str]],
) -> str:
    """
    Ensure the Secret Manager secret exists.

    - If it exists: return name.
    - If missing and auto_create is False: ask whether to create.
    - If missing and auto_create is True: create without prompting.
    """
    client = sm_client()
    parent = f"projects/{project_id}"
    name = f"{parent}/secrets/{secret_id}"

    # Try get
    try:
        client.get_secret(request={"name": name})
        return name
    except NotFound:
        pass

    print(f"{COLOR_YELLOW}Secret not found: {name}{COLOR_RESET}")

    if not auto_create:
        if not prompt_yes_no(f"Create Secret Manager secret {name}?", default=False):
            raise RuntimeError("User declined to create missing secret.")

    if not test_sm_permissions_for_create(project_id):
        raise RuntimeError(
            f"No permission to create secrets in project {project_id} "
            f"(missing secretmanager.secrets.create)."
        )

    # Ask once per project which regions to use; cache for the session.
    if project_id in regions_cache:
        regions = regions_cache[project_id]
    else:
        default_regions = "us-central1,us-east1,us-west1"
        ans = input(
            f"Enter comma-separated Secret Manager regions for project {project_id} "
            f"(default: {default_regions}): "
        ).strip()
        if not ans:
            ans = default_regions
        regions = [r.strip() for r in ans.split(",") if r.strip()]
        if not regions:
            raise RuntimeError("No valid regions provided for Secret Manager replication.")
        regions_cache[project_id] = regions

    replication = secretmanager_v1.Replication(
        user_managed=secretmanager_v1.Replication.UserManaged(
            replicas=[
                secretmanager_v1.Replication.UserManaged.Replica(location=r)
                for r in regions
            ]
        )
    )
    secret = secretmanager_v1.Secret(replication=replication)
    client.create_secret(
        request={"parent": parent, "secret_id": secret_id, "secret": secret}
    )
    print(f"{COLOR_GREEN}Created Secret Manager secret: {name}{COLOR_RESET}")
    return name


def add_secret_version_to_sm(project_id: str, secret_id: str, payload: bytes) -> str:
    """
    Add a new secret version in Secret Manager for the given payload.

    Warns if we appear to be missing secretmanager.versions.add.
    """
    if not test_sm_permissions_for_add_version(project_id, secret_id):
        print(
            f"{COLOR_YELLOW}Warning: missing secretmanager.versions.add on "
            f"projects/{project_id}/secrets/{secret_id} (attempting anyway).{COLOR_RESET}"
        )
    client = sm_client()
    name = f"projects/{project_id}/secrets/{secret_id}"
    try:
        resp = client.add_secret_version(
            request={"parent": name, "payload": {"data": payload}}
        )
    except Exception as e:
        raise RuntimeError(f"Failed to add secret version for {name}: {e}") from e
    version_id = resp.name.split("/")[-1]
    print(f"{COLOR_GREEN}Secret version added: {name} (version {version_id}){COLOR_RESET}")
    return version_id


def ensure_secret_iam_for_allowed_sas(
    project_id: str,
    secret_id: str,
    allowed_sas_str: str,
) -> None:
    """
    Ensure that any allowed service accounts have roles/secretmanager.secretAccessor
    on the given secret.

    - allowed_sas_str: comma-separated list of service account emails.
    - Additive-only: never removes existing IAM members.
    """
    if not allowed_sas_str:
        return

    raw_items = [s.strip() for s in allowed_sas_str.split(",")]
    emails = [s for s in raw_items if s]
    if not emails:
        return

    client = sm_client()
    resource = f"projects/{project_id}/secrets/{secret_id}"

    try:
        policy = client.get_iam_policy(request={"resource": resource})
    except Exception as e:
        raise RuntimeError(f"Failed to get IAM policy for {resource}: {e}") from e

    target_role = "roles/secretmanager.secretAccessor"
    binding = None
    for b in policy.bindings:
        if b.role == target_role:
            binding = b
            break

    if binding is None:
        binding = policy.bindings.add()
        binding.role = target_role

    existing_members = set(binding.members)
    new_members = set(existing_members)

    sa_members = {f"serviceAccount:{email}" for email in emails}
    new_members.update(sa_members)

    if new_members == existing_members:
        # Nothing new to add
        return

    binding.members.clear()
    binding.members.extend(sorted(new_members))

    try:
        client.set_iam_policy(request={"resource": resource, "policy": policy})
        print(
            f"{COLOR_GREEN}Updated IAM on {resource} to grant "
            f"roles/secretmanager.secretAccessor to: {', '.join(sorted(sa_members))}.{COLOR_RESET}"
        )
    except Exception as e:
        raise RuntimeError(f"Failed to update IAM policy for {resource}: {e}") from e


# ---------------------------------------------------------------------------
# Env/access checks with compliance mapping
# ---------------------------------------------------------------------------


def run_env_and_access_checks(cfg: Dict[str, Any], label: str) -> Tuple[str, Optional[str]]:
    """
    Full paranoid health checks: used for 'configure' and 'test'.

    Each step:
      - runs a guardrail (platform, WARP, identity, BQ, KMS),
      - then prints a one-line PCI/GDPR/SOC2/NIST mapping (informational only).
    """
    print_banner(label, cfg)

    # 1) Platform + MDM enrollment
    print(f"{COLOR_CYAN}[1/5] Platform and Jamf enrollment check{COLOR_RESET}")
    ensure_macos_and_mdm_enrolled()
    print(f"      Status: {COLOR_GREEN}OK{COLOR_RESET}")
    print(
        f"      {COLOR_CYAN}Compliance:{COLOR_RESET} "
        "PCI DSS 2.2, 7.2.2; GDPR 25, 32(1)(b); SOC 2 CC6.1, CC6.7; "
        "NIST SP 800-53 Rev. 5 CM-6, AC-6"
    )
    print()

    # 1b) Cloudflare WARP connectivity (client-side via URL)
    print(f"{COLOR_CYAN}[1b] Cloudflare WARP connectivity check{COLOR_RESET}")
    ensure_cloudflare_warp_connected_via_trace(require_gateway=True)
    print(f"      Status: {COLOR_GREEN}OK{COLOR_RESET}")
    print(
        f"      {COLOR_CYAN}Compliance:{COLOR_RESET} "
        "PCI DSS 4.1, 4.2; GDPR 32(1)(a),(b); SOC 2 CC6.6, CC6.7; "
        "NIST SP 800-53 Rev. 5 SC-7, SC-8, SC-13, AC-17"
    )
    print()

    # 2) Identity + org access (human ADC, org-scoped)
    print(f"{COLOR_CYAN}[2/5] Identity and organization access check{COLOR_RESET}")
    actor_email, actor_name = ensure_org_access(cfg)
    identity_str = actor_email if not actor_name else f"{actor_name} <{actor_email}>"
    print(f"      Status: {COLOR_GREEN}OK{COLOR_RESET} (user: {identity_str})")
    print(
        f"      {COLOR_CYAN}Compliance:{COLOR_RESET} "
        "PCI DSS 7.2.2, 8.3.1; GDPR 5(1)(f), 32(1)(b); SOC 2 CC6.2, CC6.3; "
        "NIST SP 800-53 Rev. 5 AC-2, AC-3, IA-2"
    )
    print()

    # 3) BigQuery connectivity (catalog reachable under correct project)
    print(f"{COLOR_CYAN}[3/5] BigQuery connectivity test{COLOR_RESET}")
    test_bq_connection(cfg)
    print(
        f"      {COLOR_CYAN}Compliance:{COLOR_RESET} "
        "PCI DSS 3.4, 10.2.2; GDPR 32(1)(b),(d); SOC 2 CC6.6, CC7.2; "
        "NIST SP 800-53 Rev. 5 SC-28, AU-2"
    )
    print()

    # 4) KMS round-trip (encrypt/decrypt functional)
    print(f"{COLOR_CYAN}[4/5] KMS encrypt/decrypt round-trip test{COLOR_RESET}")
    test_kms_roundtrip(cfg)
    print(
        f"      {COLOR_CYAN}Compliance:{COLOR_RESET} "
        "PCI DSS 3.5.1, 3.6.1; GDPR 32(1)(a); SOC 2 CC6.6, CC6.8; "
        "NIST SP 800-53 Rev. 5 SC-12, SC-13"
    )
    print()

    # 5) KMS rotation status (key lifecycle)
    print(f"{COLOR_CYAN}[5/5] KMS rotation status{COLOR_RESET}")
    print_kms_rotation_status(cfg)
    print(
        f"      {COLOR_CYAN}Compliance:{COLOR_RESET} "
        "PCI DSS 3.6.1, 3.6.4; GDPR 32(1)(d); SOC 2 CC3.2, CC6.8; "
        "NIST SP 800-53 Rev. 5 SC-12, CM-6"
    )
    print()

    return actor_email, actor_name


# ---------------------------------------------------------------------------
# Enroll flow (BQ catalog only; no SM writes unless --sync-now)
# ---------------------------------------------------------------------------


def enroll_secret(
    args: argparse.Namespace,
    cfg: Dict[str, Any],
    actor_email: str,
    actor_name: Optional[str],
) -> None:
    """
    Enroll a new secret into BigQuery (KMS-encrypted).

    - Does not touch Secret Manager unless --sync-now is set.
    - Treats BQ as the only source of truth for ciphertext and metadata.
    """
    _, dataset, table, fq_table = bq_table_info(cfg)

    bundle_id = args.bundle_id or input("Bundle ID (e.g. TENANT_X1_BUNDLE): ").strip()
    target_project = args.target_project or input("Target GCP project for Secret Manager: ").strip()
    secret_id = args.secret_id or input("Secret ID (Secret Manager name): ").strip()

    if not bundle_id:
        print(f"{COLOR_RED}bundle_id is required.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    if not target_project:
        print(f"{COLOR_RED}target_project is required.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)
    if not secret_id:
        print(f"{COLOR_RED}secret_id is required.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)

    # Optional per-secret allow-list of service account emails.
    allowed_sas_str = args.allowed_service_accounts
    if allowed_sas_str is None:
        allowed_sas_str = input(
            "Allowed service accounts (comma-separated emails, optional, ENTER to skip): "
        ).strip() or None

    comment = args.comment
    if comment is None:
        comment = input("Comment/description (optional, ENTER to skip): ").strip() or None

    # Secret value can come from a file or interactive hidden input.
    if args.file:
        with open(args.file, "rb") as f:
            plaintext = f.read().decode("utf-8")
    else:
        plaintext = prompt_multiline_secret()

    clear_clipboard_if_possible()

    if not plaintext:
        print(f"{COLOR_RED}Secret value is empty, aborting.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)

    ciphertext_b64 = encrypt_with_kms(cfg, plaintext)
    now = datetime.now(timezone.utc)

    record_id = str(uuid.uuid4())
    created_by = actor_email if not actor_name else f"{actor_name} <{actor_email}>"

    # Single canonical catalog row for this secret version metadata.
    row = {
        "secret_record_id": record_id,
        "bundle_id": bundle_id,
        "secret_id": secret_id,
        "target_project": target_project,
        "ciphertext_b64": ciphertext_b64,
        "allowed_service_accounts": allowed_sas_str,
        "comment": comment,
        "is_active": True,
        "created_by": created_by,
        "created_at": now.isoformat(),
        "last_synced_at": None,
    }

    insert_catalog_row(cfg, row)

    print(f"{COLOR_GREEN}Enrolled secret:{COLOR_RESET}")
    print(f"  Bundle ID      : {bundle_id}")
    print(f"  Secret ID      : {secret_id}")
    print(f"  Target project : {target_project}")
    if allowed_sas_str:
        print(f"  Allowed SAs    : {allowed_sas_str}")
    print(f"  Catalog table  : {fq_table}")

    # Optional immediate SM sync of this single record.
    if args.sync_now:
        print("\nSyncing this secret immediately (non-interactive, this record only):")
        regions_cache: Dict[str, List[str]] = {}
        try:
            synced_id = sync_single_row(
                cfg,
                row,
                auto_create=args.auto_create,
                regions_cache=regions_cache,
            )
            if synced_id:
                print("Updating BigQuery catalog to mark rows as synced...")
                mark_rows_synced(cfg, [synced_id])
                print(f"{COLOR_GREEN}BigQuery catalog update completed. Rows affected: 1.{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_RED}Immediate sync failed: {e}{COLOR_RESET}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Sync flow (BQ -> Secret Manager)
# ---------------------------------------------------------------------------


def sync_single_row(
    cfg: Dict[str, Any],
    row: Dict[str, Any],
    auto_create: bool,
    regions_cache: Dict[str, List[str]],
) -> Optional[str]:
    """
    Sync a single catalog row into Secret Manager.

    Returns the secret_record_id so the caller can mark it synced in BigQuery.
    """
    plaintext = decrypt_with_kms(cfg, row["ciphertext_b64"])
    project_id = row["target_project"]
    secret_id = row["secret_id"]
    bundle_id = row["bundle_id"]
    record_id = row["secret_record_id"]
    allowed_sas_str = row.get("allowed_service_accounts")

    print(
        "Syncing secret:\n"
        f"  Bundle ID      : {bundle_id}\n"
        f"  Secret ID      : {secret_id}\n"
        f"  Target project : {project_id}"
    )

    ensure_secret_exists(
        project_id,
        secret_id,
        auto_create=auto_create,
        regions_cache=regions_cache,
    )

    # If we have allowed service accounts, ensure they are bound as secretAccessor.
    if allowed_sas_str:
        ensure_secret_iam_for_allowed_sas(project_id, secret_id, allowed_sas_str)

    add_secret_version_to_sm(project_id, secret_id, plaintext)
    clear_sensitive_text(plaintext)

    print(f"{COLOR_GREEN}Secret sync completed:{COLOR_RESET}")
    print(f"  Bundle ID      : {bundle_id}")
    print(f"  Secret ID      : {secret_id}")
    print(f"  Target project : {project_id}")
    print(f"  Secret name    : projects/{project_id}/secrets/{secret_id}\n")

    return record_id


def sync_secrets(args: argparse.Namespace, cfg: Dict[str, Any]) -> None:
    """
    Interactive sync from BQ catalog into Secret Manager.

    - Shows pending secrets.
    - Lets the user pick 'all' or a subset.
    - Adds SM versions and then marks rows as synced.
    """
    if args.limit is not None and args.limit <= 0:
        print(f"{COLOR_RED}--limit must be a positive integer{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)

    rows = query_unsynced_rows(cfg, args)
    if not rows:
        print(f"{COLOR_GREEN}No unsynced secrets found.{COLOR_RESET}")
        return

    print("Pending secrets eligible for sync:")
    for idx, r in enumerate(rows, start=1):
        created_at = r["created_at"]
        ts_str = (
            created_at.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(created_at, datetime)
            else str(created_at)
        )
        print(
            f"  [{idx}] Bundle: {r['bundle_id']} | "
            f"Secret: {r['secret_id']} | "
            f"Project: {r['target_project']} | "
            f"Created by: {r['created_by']} at {ts_str}"
        )

    if args.dry_run:
        print(f"{COLOR_YELLOW}Dry run: not syncing anything.{COLOR_RESET}")
        return

    selection = input(
        "Enter selection to sync (for example 'all' or '1,3,5'; press ENTER for all): "
    ).strip()
    if not selection or selection.lower() == "all":
        indices = list(range(1, len(rows) + 1))
    else:
        try:
            indices = [int(x.strip()) for x in selection.split(",") if x.strip()]
        except ValueError:
            print(f"{COLOR_RED}Invalid selection, aborting.{COLOR_RESET}", file=sys.stderr)
            sys.exit(1)

    indices = sorted(set(indices))
    for i in indices:
        if i < 1 or i > len(rows):
            print(f"{COLOR_RED}Invalid index {i}{COLOR_RESET}", file=sys.stderr)
            sys.exit(1)

    regions_cache: Dict[str, List[str]] = {}
    successful_ids: List[str] = []
    for i in indices:
        r = rows[i - 1]
        try:
            synced_id = sync_single_row(
                cfg,
                r,
                auto_create=args.auto_create,
                regions_cache=regions_cache,
            )
            if synced_id:
                successful_ids.append(synced_id)
        except Exception as e:
            print(
                f"{COLOR_RED}Error syncing record '{r['secret_record_id']}': {e}{COLOR_RESET}",
                file=sys.stderr,
            )

    if successful_ids:
        print("Updating BigQuery catalog to mark rows as synced...")
        mark_rows_synced(cfg, successful_ids)
        print(
            f"{COLOR_GREEN}BigQuery catalog update completed. "
            f"Rows affected: {len(successful_ids)}.{COLOR_RESET}"
        )


# ---------------------------------------------------------------------------
# Self-test / configure wrappers (high-verbosity mode)
# ---------------------------------------------------------------------------


def configure_interactive() -> None:
    """
    Interactive configure: set config, then run full env/access tests.

    This is the 'onboarding' path for the tool; safe to re-run at any time.
    """
    # Ask for config path first, so we can override default
    default_path = CONFIG_PATH or DEFAULT_CONFIG_PATH
    new_path = prompt_with_default("Config file path", default_path)
    set_config_path(new_path)

    existing = load_config()
    cfg: Dict[str, Any] = dict(existing)

    # BigQuery
    cfg["bq_project"] = prompt_with_default(
        "BigQuery project (for secrets catalog)", cfg.get("bq_project")
    )
    cfg["bq_dataset"] = prompt_with_default(
        "BigQuery dataset", cfg.get("bq_dataset", "pallas_inventory_ds")
    )
    cfg["bq_table"] = prompt_with_default(
        "BigQuery table", cfg.get("bq_table", "secrets_catalog_tbl")
    )

    # KMS
    cfg["kms_project"] = prompt_with_default(
        "KMS project", cfg.get("kms_project") or cfg["bq_project"]
    )
    cfg["kms_location"] = prompt_with_default(
        "KMS location", cfg.get("kms_location") or "us-central1"
    )
    cfg["kms_keyring"] = prompt_with_default(
        "KMS keyring", cfg.get("kms_keyring") or "secrets-keyring"
    )
    cfg["kms_key"] = prompt_with_default(
        "KMS key", cfg.get("kms_key") or "secrets-key"
    )

    # Org
    cfg["gcp_org_id"] = prompt_with_default(
        "GCP Org ID (for org access check)", cfg.get("gcp_org_id")
    )

    save_config(cfg)
    print()

    actor_email, actor_name = run_env_and_access_checks(cfg, "configure")
    identity_str = actor_email if not actor_name else f"{actor_name} <{actor_email}>"
    print(f"{COLOR_GREEN}Self-test completed successfully (user: {identity_str}).{COLOR_RESET}")


def run_self_tests(cfg: Dict[str, Any]) -> None:
    """
    Run the full env/access test suite without changing any data.

    Equivalent to configure's checks, but without re-prompting for config.
    """
    actor_email, actor_name = run_env_and_access_checks(cfg, "test")
    identity_str = actor_email if not actor_name else f"{actor_name} <{actor_email}>"
    print(f"{COLOR_GREEN}Self-test completed successfully (user: {identity_str}).{COLOR_RESET}")


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Define CLI surface and parse arguments."""
    parser = argparse.ArgumentParser(
        prog="pallas-vault-manager",
        description="BigQuery-backed KMS-encrypted secrets enrollment and sync tool",
        usage="pallas-vault-manager [OPTIONS] <command> [ARGS]",
    )
    parser.add_argument(
        "-C", "--config",
        help=f"Path to config file (default: {DEFAULT_CONFIG_PATH})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # configure
    subparsers.add_parser("configure", help="Interactive configure (BQ/KMS/org/MDM/WARP checks)")

    # test
    subparsers.add_parser("test", help="Run self-tests (no changes) and exit")

    # enroll
    p_enroll = subparsers.add_parser("enroll", help="Enroll a new secret into BigQuery (KMS-encrypted)")
    p_enroll.add_argument("-B", "--bundle-id", help="Bundle ID (matches bundles_tbl.bundle_id)")
    p_enroll.add_argument("-p", "--target-project", help="Target GCP project for Secret Manager")
    p_enroll.add_argument("-i", "--secret-id", help="Secret Manager secret id (name)")
    p_enroll.add_argument("-c", "--comment", help="Comment/description (optional)")
    p_enroll.add_argument("-f", "--file", help="Read secret value from file (UTF-8)")
    p_enroll.add_argument(
        "-S", "--allowed-service-accounts",
        help="Comma-separated list of allowed service account emails (optional)",
    )
    p_enroll.add_argument(
        "-A", "--auto-create",
        action="store_true",
        help="Allow creating Secret Manager secrets if missing (no prompt)",
    )
    p_enroll.add_argument(
        "--sync-now",
        action="store_true",
        help="Immediately sync this secret to Secret Manager after enroll",
    )

    # sync
    p_sync = subparsers.add_parser("sync", help="Sync unsynced secrets from BigQuery to Secret Manager")
    p_sync.add_argument("-B", "--bundle-id", help="Filter by bundle id")
    p_sync.add_argument("-i", "--secret-id", help="Filter by secret id")
    p_sync.add_argument(
        "-d", "--dry-run",
        action="store_true",
        help="Dry run (show what would be synced but do nothing)",
    )
    p_sync.add_argument(
        "-A", "--auto-create",
        action="store_true",
        help="Allow creating Secret Manager secrets if missing (no prompt)",
    )
    p_sync.add_argument(
        "-L", "--limit",
        type=int,
        help="Maximum number of unsynced secrets to list and sync",
    )

    return parser.parse_args()


def main() -> None:
    """
    Top-level entrypoint.

    Flow:
      - Parse args / config path.
      - For 'configure': prompt + tests.
      - For 'test': load config + tests.
      - For 'enroll'/'sync': run hard guardrails then perform the mutation.
    """
    try:
        args = parse_args()
        set_config_path(args.config)

        if args.command == "configure":
            configure_interactive()
            return

        cfg = load_config()
        if not cfg:
            print(
                f"{COLOR_RED}No config found. Run 'pallas-vault-manager configure' first.{COLOR_RESET}",
                file=sys.stderr,
            )
            sys.exit(1)

        if args.command == "test":
            run_self_tests(cfg)
            return

        # For enroll/sync: light but strict checks (no compliance spam).
        # This maintains CI-resistance and device posture requirements.
        print_banner(args.command, cfg)

        ensure_macos_and_mdm_enrolled()
        ensure_cloudflare_warp_connected_via_trace(require_gateway=True)
        actor_email, actor_name = ensure_org_access(cfg)
        test_bq_connection(cfg)
        test_kms_roundtrip(cfg)

        if args.command == "enroll":
            enroll_secret(args, cfg, actor_email, actor_name)
        elif args.command == "sync":
            sync_secrets(args, cfg)
        else:
            print(f"{COLOR_RED}Unknown command {args.command}{COLOR_RESET}", file=sys.stderr)
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}Interrupted by user.{COLOR_RESET}")
        sys.exit(130)


if __name__ == "__main__":
    main()
