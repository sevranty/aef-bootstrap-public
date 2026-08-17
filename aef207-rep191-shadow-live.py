#!/usr/bin/env python3
"""AEF#207 live actuator for the authorized one-shot REP#191 SHADOW.

This file is intentionally self-contained so an exact checked public copy can be
executed on the accepted worker before the private GitHub repository is available.
It performs one bounded transition only:

browser auth -> GET-only staging -> bounded enrollment -> one SHADOW -> evidence -> STOP.

It contains no ACTIVE, dispatch, scheduler-cutover, provider or source-mutation path.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

TASK_ID = "AEF#207"
PARENT_TASK_ID = "AEF#61"
UMBRELLA_TASK_ID = "AEF#56"
DECISION_ID = "AEF61-REP191-PROTECTED-SHADOW-V1"
WORKER_ID = "digitalocean:592813728"
DROPLET_ID = "592813728"
RESOURCE_CLASS = "tiny"

BOOTSTRAP_STATUS = Path("/usr/local/sbin/aef-bootstrap-v5.py")
BOOTSTRAP_DRIVER = 5
BOOTSTRAP_RELEASE_SHA256 = "a1eee6efa50b367d7ef2ffade4833fbf2b670c9b6476a7173d0679de663a33ce"
BOOTSTRAP_USER_DATA_SHA256 = "965b22a82997a2fd5eda6c05ed0bfae54c8526c9350fcf41104faaa0310c0928"
PUBLIC_IPV4 = "164.90.226.172"
REGION = "fra1"

GH_EXECUTABLE = Path("/opt/aef/capabilities/github-cli/2.97.0/bin/gh")
GH_VERSION = "2.97.0"
GH_BINARY_SHA256 = "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409"
GH_HOME = Path("/var/lib/aef/credentials/github/rep191")

AEF_REPOSITORY_API = "repos/sevranty/agent-execution-fabric"
AEF_CAPSULE_PATH = "activation/rep191-shadow-activation-v1.json"
AEF_CAPSULE_SHA256 = "d083c5b30357ef2a82bdaa404d9515d7c37b2e58b61d3b1716c1c6fdfcfdc8a1"
AEF_PREPARED_REGISTRY_PATH = "registry/prepared-jobs-v1.json"

REPORT_REPOSITORY_API = "repos/sevranty/report"
REPORT_REVISION = "30030684822f473c62ff8aadb420f5ee51a430ae"
REPORT_BUNDLE_ID = "rep191-lifeops-refresh-shadow-v2"
REPORT_BUNDLE_SHA256 = "4747fef2258a3b83f3b314286f50b7adb830a2c2b56ae1961953c01ede565f09"
REPORT_ENTRYPOINT = "scripts/rep191_portable/__main__.py"

RELEASE_PARENT = Path("/opt/aef/workloads/rep191/releases")
RELEASE_NAME = f"{REPORT_BUNDLE_ID}-{REPORT_BUNDLE_SHA256[:16]}"
SHADOW_CONFIG = Path("/etc/aef/jobs/rep191-shadow-v1.json")
STATE_ROOT = Path("/var/lib/aef/state/rep191")
OWNERSHIP_PATH = STATE_ROOT / "ownership.json"
MACHINE_PROFILE_PATH = STATE_ROOT / "machine-profile.json"
ENROLLMENT_PATH = STATE_ROOT / "worker-enrollment.json"
TERMINAL_EVIDENCE_PATH = STATE_ROOT / "shadow-result.json"
ENROLLMENT_ID = "enrollment-aef61-rep191-shadow-worker05-v1"

OWNERSHIP = {
    "schema_version": 1,
    "resource_id": "rep191-lifeops-refresh",
    "generation": 1,
    "owner_id": "owner-local-rep191",
    "fencing_token": "3552fa47788ee3c2c0298060fdc41079365e06660cf25202becd38b3eb3ebba3",
    "previous_state_sha256": None,
    "transition_reason": "initial",
    "predecessor_stopped_observed": False,
    "predecessor_fence_verified": False,
}
SHADOW_CONFIG_VALUE = {
    "schema_version": 1,
    "mode": "SHADOW",
    "gh_executable": str(GH_EXECUTABLE),
    "gh_home": str(GH_HOME),
    "state_root": str(STATE_ROOT),
    "ownership_reference": "ownership.json",
    "worker_id": WORKER_ID,
}
MACHINE_PROFILE = {
    "schema_version": 1,
    "worker_id": WORKER_ID,
    "resource_class": RESOURCE_CLASS,
    "capacity": {"ram_mb": 512, "cpu_millicores": 1000, "disk_mb": 10240},
    "capabilities": ["python3", "filesystem-state", "github-api"],
    "network_modes": ["none", "outbound-https"],
    "max_timeout_seconds": 3600,
    "max_concurrency": 1,
    "bootstrap": {
        "driver_version": BOOTSTRAP_DRIVER,
        "release_sha256": BOOTSTRAP_RELEASE_SHA256,
        "user_data_sha256": BOOTSTRAP_USER_DATA_SHA256,
    },
    "github_cli": {
        "version": GH_VERSION,
        "binary_sha256": GH_BINARY_SHA256,
    },
}
MACHINE_PROFILE_SHA256 = "c254d1684142d2ecf10a4c8ea1f87d50cb420ba648f40c88e6e17037edd67fc0"

EXPECTED_FILES = [
    {"path": "scripts/rep191_portable/__init__.py", "bytes": 904, "sha256": "1df9c7cf3ab5ab0f9b1a2a4e46dc645ac2f4166591a9ad33ac2bad56029e4ee9", "mode": "0444"},
    {"path": "scripts/rep191_portable/__main__.py", "bytes": 6891, "sha256": "400ea368187b2e53b65baed7d86e71c13110e73a381fc73aae8df81477e1c79e", "mode": "0444"},
    {"path": "scripts/rep191_portable/core.py", "bytes": 23477, "sha256": "3a263dfc5235a7118d130c4790811fc5f4bce5809b93bf00ccc79f88a94fa227", "mode": "0444"},
    {"path": "scripts/rep191_portable/filesystem.py", "bytes": 13789, "sha256": "b918265d8f9ea20c292b8c90aab8d8b1abde015daa45ee20a106e3f7b796a466", "mode": "0444"},
    {"path": "scripts/rep191_portable/github_auth.py", "bytes": 13431, "sha256": "ac02668d4a16eb1537dc7a8906c59a242f2a9256954daf0648a86ee80b50da5d", "mode": "0444"},
    {"path": "scripts/rep191_portable/runtime.py", "bytes": 1403, "sha256": "00fd5f1de4189fc7c9dedbe3099c0cac2f0326ce73333afdc48ccf6baa7483f7", "mode": "0444"},
    {"path": "scripts/rep191_portable/scheduler.py", "bytes": 8381, "sha256": "96d54362d330d08b2d2caaba7fe7b8551326158537e35188ed16178d0ffdf9a9", "mode": "0444"},
    {"path": "scripts/rep191_portable/remote_mutation.py", "bytes": 18761, "sha256": "677739c596474f53b3d16adc3d10d70a3e076b0c29ad5e1598d4aa43f74ddfe8", "mode": "0444"},
    {"path": "scripts/rep191_portable/remote_worker.py", "bytes": 15090, "sha256": "53aa41b7c128bdf4cf91ce340c6ec5827d5f98a67e5cdf2cd2a0e22811084609", "mode": "0444"},
]

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_RELATIVE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
FORBIDDEN_EVIDENCE_KEYS = {
    "token", "access_token", "oauth_token", "password", "secret", "cookie",
    "credentials", "credential", "private_key", "api_key",
}


class LiveActuatorError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise LiveActuatorError("CANONICAL_JSON_INVALID") from error


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(value: str) -> Path:
    if not isinstance(value, str) or SAFE_RELATIVE_RE.fullmatch(value) is None:
        raise LiveActuatorError("UNSAFE_PATH", str(value))
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise LiveActuatorError("UNSAFE_PATH", value)
    return path


def _regular_file(path: Path, code: str) -> os.stat_result:
    try:
        meta = path.lstat()
    except OSError as error:
        raise LiveActuatorError(code, str(path)) from error
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise LiveActuatorError(code, str(path))
    return meta


def _directory(path: Path, code: str, *, private: bool = False) -> os.stat_result:
    try:
        meta = path.lstat()
    except OSError as error:
        raise LiveActuatorError(code, str(path)) from error
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise LiveActuatorError(code, str(path))
    if private and meta.st_mode & 0o077:
        raise LiveActuatorError("PRIVATE_DIRECTORY_PERMISSIONS_INVALID", str(path))
    return meta


def ensure_directory_chain(base: Path, target: Path, mode: int) -> None:
    base = Path(base)
    target = Path(target)
    _directory(base, "BASE_DIRECTORY_INVALID")
    try:
        relative = target.relative_to(base)
    except ValueError as error:
        raise LiveActuatorError("PATH_CONTAINMENT_FAILED", str(target)) from error
    current = base
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            _directory(current, "DIRECTORY_CHAIN_INVALID")
        else:
            os.mkdir(current, mode=mode)
    os.chmod(target, mode)


def validate_self_hash(expected: str | None) -> str:
    actual = sha256_file(Path(__file__).resolve())
    if expected is not None:
        if SHA256_RE.fullmatch(expected) is None or actual != expected:
            raise LiveActuatorError("SELF_CHECKSUM_MISMATCH")
    return actual


def validate_machine_profile_constant() -> None:
    if sha256_bytes(canonical_json_bytes(MACHINE_PROFILE)) != MACHINE_PROFILE_SHA256:
        raise LiveActuatorError("MACHINE_PROFILE_IDENTITY_DRIFT")


def bootstrap_preflight() -> dict[str, Any]:
    _regular_file(BOOTSTRAP_STATUS, "BOOTSTRAP_STATUS_UNAVAILABLE")
    try:
        result = subprocess.run(
            [str(BOOTSTRAP_STATUS), "--status-json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LiveActuatorError("BOOTSTRAP_STATUS_FAILED") from error
    if result.returncode != 0:
        raise LiveActuatorError("BOOTSTRAP_STATUS_FAILED")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LiveActuatorError("BOOTSTRAP_STATUS_INVALID") from error
    expected = {
        "driver_version": BOOTSTRAP_DRIVER,
        "overall": "PASS",
        "phase": "READY",
        "release_sha256": BOOTSTRAP_RELEASE_SHA256,
        "dispatch_enabled": False,
        "service_installed": False,
    }
    for key, wanted in expected.items():
        if value.get(key) != wanted:
            raise LiveActuatorError("BOOTSTRAP_IDENTITY_DRIFT", key)
    metadata = value.get("metadata")
    if not isinstance(metadata, dict):
        raise LiveActuatorError("BOOTSTRAP_IDENTITY_DRIFT", "metadata")
    if metadata.get("id") != DROPLET_ID:
        raise LiveActuatorError("WORKER_IDENTITY_DRIFT", "droplet id")
    if metadata.get("public_ipv4") != PUBLIC_IPV4 or metadata.get("region") != REGION:
        raise LiveActuatorError("WORKER_IDENTITY_DRIFT", "provider metadata")
    if metadata.get("user_data_sha256") != BOOTSTRAP_USER_DATA_SHA256:
        raise LiveActuatorError("BOOTSTRAP_IDENTITY_DRIFT", "user-data")
    capabilities = value.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) != 1:
        raise LiveActuatorError("GITHUB_CAPABILITY_DRIFT")
    capability = capabilities[0]
    if (
        not isinstance(capability, dict)
        or capability.get("capability_id") != "github-cli"
        or capability.get("status") != "PASS"
        or capability.get("version") != GH_VERSION
        or capability.get("binary_sha256") != GH_BINARY_SHA256
        or capability.get("provides") != ["github-api"]
    ):
        raise LiveActuatorError("GITHUB_CAPABILITY_DRIFT")
    return {
        "status": "PASS",
        "driver_version": BOOTSTRAP_DRIVER,
        "release_sha256": BOOTSTRAP_RELEASE_SHA256,
        "worker_id": WORKER_ID,
    }


def validate_github_cli() -> None:
    meta = _regular_file(GH_EXECUTABLE, "GITHUB_CLI_UNAVAILABLE")
    if not meta.st_mode & stat.S_IXUSR:
        raise LiveActuatorError("GITHUB_CLI_NOT_EXECUTABLE")
    if sha256_file(GH_EXECUTABLE) != GH_BINARY_SHA256:
        raise LiveActuatorError("GITHUB_CLI_CHECKSUM_DRIFT")
    result = subprocess.run(
        [str(GH_EXECUTABLE), "version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", "")},
    )
    first = result.stdout.splitlines()[0] if result.stdout else ""
    if result.returncode != 0 or not first.startswith(f"gh version {GH_VERSION}"):
        raise LiveActuatorError("GITHUB_CLI_VERSION_DRIFT")


def protected_env() -> dict[str, str]:
    # REP#214 GitHubCliAuthAdapter treats the protected reference as HOME and
    # lets gh resolve its normal config location beneath that private root.
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(GH_HOME),
        "GH_PAGER": "cat",
        "NO_COLOR": "1",
    }


def prepare_protected_home() -> None:
    ensure_directory_chain(Path("/var/lib/aef"), GH_HOME, 0o700)
    meta = _directory(GH_HOME, "PROTECTED_HOME_INVALID", private=True)
    if meta.st_uid not in {0, os.geteuid()}:
        raise LiveActuatorError("PROTECTED_HOME_OWNER_INVALID")


def github_auth_ok() -> bool:
    result = subprocess.run(
        [str(GH_EXECUTABLE), "auth", "status", "--hostname", "github.com"],
        check=False,
        capture_output=True,
        timeout=20,
        env=protected_env(),
    )
    return result.returncode == 0


def browser_auth() -> dict[str, Any]:
    prepare_protected_home()
    if github_auth_ok():
        return {"status": "PASS", "browser_action_used": False}
    print("GitHub: завершите вход в браузере по инструкции gh. Токен сюда не вставляйте.", flush=True)
    result = subprocess.run(
        [
            str(GH_EXECUTABLE),
            "auth",
            "login",
            "--hostname",
            "github.com",
            "--git-protocol",
            "https",
            "--web",
            "--skip-ssh-key",
        ],
        check=False,
        env=protected_env(),
    )
    if result.returncode != 0 or not github_auth_ok():
        raise LiveActuatorError("GITHUB_BROWSER_AUTH_BLOCKED")
    return {"status": "PASS", "browser_action_used": True}


def gh_api_json(endpoint: str) -> Any:
    try:
        result = subprocess.run(
            [str(GH_EXECUTABLE), "api", "--method", "GET", endpoint],
            check=False,
            capture_output=True,
            timeout=40,
            env=protected_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LiveActuatorError("GITHUB_GET_FAILED", endpoint) from error
    if result.returncode != 0:
        raise LiveActuatorError("GITHUB_GET_FAILED", endpoint)
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveActuatorError("GITHUB_RESPONSE_INVALID", endpoint) from error


def decode_contents(record: Any, label: str) -> bytes:
    if not isinstance(record, dict) or record.get("type") != "file" or record.get("encoding") != "base64":
        raise LiveActuatorError("GITHUB_CONTENTS_INVALID", label)
    content = record.get("content")
    if not isinstance(content, str):
        raise LiveActuatorError("GITHUB_CONTENTS_INVALID", label)
    try:
        return base64.b64decode("".join(content.split()), validate=True)
    except (ValueError, TypeError) as error:
        raise LiveActuatorError("GITHUB_CONTENTS_INVALID", label) from error


def verify_current_aef_control_plane() -> dict[str, Any]:
    branch = gh_api_json(f"{AEF_REPOSITORY_API}/branches/main")
    current = branch.get("commit", {}).get("sha") if isinstance(branch, dict) else None
    if not isinstance(current, str) or SHA40_RE.fullmatch(current) is None:
        raise LiveActuatorError("AEF_MAIN_UNAVAILABLE")
    capsule_record = gh_api_json(f"{AEF_REPOSITORY_API}/contents/{AEF_CAPSULE_PATH}?ref={current}")
    capsule_bytes = decode_contents(capsule_record, AEF_CAPSULE_PATH)
    if sha256_bytes(capsule_bytes) != AEF_CAPSULE_SHA256:
        raise LiveActuatorError("AEF_CAPSULE_DRIFT")
    prepared_record = gh_api_json(
        f"{AEF_REPOSITORY_API}/contents/{AEF_PREPARED_REGISTRY_PATH}?ref={current}"
    )
    prepared_bytes = decode_contents(prepared_record, AEF_PREPARED_REGISTRY_PATH)
    try:
        registry = json.loads(prepared_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveActuatorError("PREPARED_REGISTRY_INVALID") from error
    validate_prepared_registry(registry)
    return {"status": "PASS", "aef_main": current}


def validate_prepared_registry(registry: Any) -> None:
    if not isinstance(registry, dict):
        raise LiveActuatorError("PREPARED_REGISTRY_INVALID")
    if registry.get("registry_status") != "prepared-disabled" or registry.get("dispatch_enabled") is not False:
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "root")
    jobs = registry.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 1 or not isinstance(jobs[0], dict):
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "jobs")
    job = jobs[0]
    checks = {
        "job_id": "report.rep191-lifeops-refresh.shadow",
        "resource_class": RESOURCE_CLASS,
        "credential_class": "github-reference",
    }
    for key, expected in checks.items():
        if job.get(key) != expected:
            raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", key)
    source = job.get("source")
    bundle = job.get("bundle")
    schedule = job.get("schedule")
    activation = job.get("activation")
    if not isinstance(source, dict) or source.get("repository") != "https://github.com/sevranty/report":
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "source")
    if source.get("revision") != REPORT_REVISION or source.get("entrypoint") != REPORT_ENTRYPOINT:
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "source identity")
    if not isinstance(bundle, dict) or bundle.get("bundle_id") != REPORT_BUNDLE_ID or bundle.get("sha256") != REPORT_BUNDLE_SHA256:
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "bundle")
    if schedule != {"kind": "manual", "interval_seconds": None}:
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "schedule")
    if job.get("write_scope") != ["metadata:aef61-shadow-evidence"]:
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "write_scope")
    if not isinstance(activation, dict) or activation.get("state") != "prepared-disabled":
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "activation")
    if activation.get("dispatch_enabled") is not False or activation.get("current_scheduler_owner") != "owner-local-rep191":
        raise LiveActuatorError("PREPARED_REGISTRY_DRIFT", "activation safety")


def fetch_report_file(record: Mapping[str, Any]) -> bytes:
    path = str(record["path"])
    _safe_relative(path)
    response = gh_api_json(f"{REPORT_REPOSITORY_API}/contents/{path}?ref={REPORT_REVISION}")
    data = decode_contents(response, path)
    if len(data) != record["bytes"]:
        raise LiveActuatorError("BUNDLE_SIZE_MISMATCH", path)
    if sha256_bytes(data) != record["sha256"]:
        raise LiveActuatorError("BUNDLE_CHECKSUM_MISMATCH", path)
    return data


def validate_release(root: Path, records: Sequence[Mapping[str, Any]] = EXPECTED_FILES) -> dict[str, Any]:
    root = Path(root)
    _directory(root, "RELEASE_INVALID")
    expected = {str(item["path"]) for item in records}
    observed: set[str] = set()
    for path in root.rglob("*"):
        if path.is_dir():
            if path.is_symlink():
                raise LiveActuatorError("RELEASE_INVALID", str(path))
            continue
        if path.is_symlink() or not path.is_file():
            raise LiveActuatorError("RELEASE_INVALID", str(path))
        observed.add(path.relative_to(root).as_posix())
    if observed != expected:
        raise LiveActuatorError("RELEASE_FILESET_DRIFT")
    for item in records:
        target = root / item["path"]
        meta = _regular_file(target, "RELEASE_FILE_INVALID")
        if stat.S_IMODE(meta.st_mode) != 0o444:
            raise LiveActuatorError("RELEASE_MODE_DRIFT", item["path"])
        if meta.st_size != item["bytes"] or sha256_file(target) != item["sha256"]:
            raise LiveActuatorError("RELEASE_CONTENT_DRIFT", item["path"])
    return {"status": "PASS", "file_count": len(expected), "release": str(root)}


def _freeze_directories(root: Path) -> None:
    directories = [root, *(path for path in root.rglob("*") if path.is_dir())]
    for path in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        if path.is_symlink():
            raise LiveActuatorError("RELEASE_DIRECTORY_INVALID", str(path))
        path.chmod(0o555)


def stage_report_bundle(
    parent: Path = RELEASE_PARENT,
    *,
    base: Path = Path("/opt/aef"),
    fetcher=fetch_report_file,
    records: Sequence[Mapping[str, Any]] = EXPECTED_FILES,
) -> dict[str, Any]:
    parent = Path(parent)
    base = Path(base)
    _directory(base, "AEF_OPT_ROOT_INVALID")
    ensure_directory_chain(base, parent, 0o755)
    final = parent / RELEASE_NAME
    if final.exists() or final.is_symlink():
        result = validate_release(final, records)
        return {**result, "publication": "RECONCILED_EXISTING"}
    stage = Path(tempfile.mkdtemp(prefix=".aef207-stage-", dir=parent))
    try:
        for item in records:
            data = fetcher(item)
            relative = _safe_relative(item["path"])
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o444)
        validate_release(stage, records)
        _freeze_directories(stage)
        os.replace(stage, final)
        result = validate_release(final, records)
        return {**result, "publication": "ATOMIC_NEW"}
    except Exception:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        raise


def _assert_no_secret_keys(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_EVIDENCE_KEYS or any(
                term in normalized for term in ("password", "oauth_token", "access_token", "private_key", "cookie")
            ):
                raise LiveActuatorError("SECRET_SHAPED_EVIDENCE_FORBIDDEN", f"{path}.{key}")
            _assert_no_secret_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_secret_keys(item, f"{path}[{index}]")


def _private_parent(path: Path, base: Path) -> None:
    ensure_directory_chain(base, path.parent, 0o700)


def materialize_exact_private_json(path: Path, value: Mapping[str, Any], base: Path) -> str:
    expected = canonical_json_bytes(value)
    _private_parent(path, base)
    if path.exists() or path.is_symlink():
        meta = _regular_file(path, "PRIVATE_STATE_INVALID")
        if stat.S_IMODE(meta.st_mode) != 0o600:
            raise LiveActuatorError("PRIVATE_STATE_MODE_DRIFT", str(path))
        if path.read_bytes() != expected:
            raise LiveActuatorError("PRIVATE_STATE_DRIFT", str(path))
        return "RECONCILED_EXISTING"
    temp = path.with_name(path.name + ".tmp-aef207")
    if temp.exists() or temp.is_symlink():
        raise LiveActuatorError("PRIVATE_STATE_TEMP_EXISTS", str(temp))
    with temp.open("xb") as handle:
        handle.write(expected)
        handle.flush()
        os.fsync(handle.fileno())
    temp.chmod(0o600)
    os.replace(temp, path)
    return "CREATED"


def materialize_shadow_state() -> dict[str, Any]:
    validate_machine_profile_constant()
    ownership_state = materialize_exact_private_json(OWNERSHIP_PATH, OWNERSHIP, Path("/var/lib/aef"))
    profile_state = materialize_exact_private_json(
        MACHINE_PROFILE_PATH, MACHINE_PROFILE, Path("/var/lib/aef")
    )
    config_state = materialize_exact_private_json(SHADOW_CONFIG, SHADOW_CONFIG_VALUE, Path("/etc/aef"))
    return {
        "status": "PASS",
        "ownership": ownership_state,
        "machine_profile": profile_state,
        "config": config_state,
        "machine_profile_sha256": MACHINE_PROFILE_SHA256,
    }


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_enrollment(value: Any) -> dict[str, Any]:
    expected_keys = {
        "schema_version", "enrollment_id", "worker_id", "generation",
        "state", "machine_profile_sha256", "observed_at",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise LiveActuatorError("ENROLLMENT_INVALID")
    if value.get("schema_version") != "1":
        raise LiveActuatorError("ENROLLMENT_INVALID", "schema_version")
    if value.get("enrollment_id") != ENROLLMENT_ID or value.get("worker_id") != WORKER_ID:
        raise LiveActuatorError("ENROLLMENT_IDENTITY_DRIFT")
    if value.get("generation") != 1 or value.get("state") != "active":
        raise LiveActuatorError("ENROLLMENT_STATE_DRIFT")
    if value.get("machine_profile_sha256") != MACHINE_PROFILE_SHA256:
        raise LiveActuatorError("ENROLLMENT_PROFILE_DRIFT")
    observed = value.get("observed_at")
    if not isinstance(observed, str) or not observed.endswith("Z"):
        raise LiveActuatorError("ENROLLMENT_INVALID", "observed_at")
    try:
        dt.datetime.fromisoformat(observed[:-1] + "+00:00")
    except ValueError as error:
        raise LiveActuatorError("ENROLLMENT_INVALID", "observed_at") from error
    return value


def materialize_enrollment() -> dict[str, Any]:
    _private_parent(ENROLLMENT_PATH, Path("/var/lib/aef"))
    if ENROLLMENT_PATH.exists() or ENROLLMENT_PATH.is_symlink():
        meta = _regular_file(ENROLLMENT_PATH, "ENROLLMENT_INVALID")
        if stat.S_IMODE(meta.st_mode) != 0o600:
            raise LiveActuatorError("ENROLLMENT_MODE_DRIFT")
        try:
            existing = json.loads(ENROLLMENT_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LiveActuatorError("ENROLLMENT_INVALID") from error
        validate_enrollment(existing)
        return {**existing, "materialization": "RECONCILED_EXISTING"}
    value = {
        "schema_version": "1",
        "enrollment_id": ENROLLMENT_ID,
        "worker_id": WORKER_ID,
        "generation": 1,
        "state": "active",
        "machine_profile_sha256": MACHINE_PROFILE_SHA256,
        "observed_at": utc_now(),
    }
    _assert_no_secret_keys(value)
    data = canonical_json_bytes(value)
    temp = ENROLLMENT_PATH.with_name(ENROLLMENT_PATH.name + ".tmp-aef207")
    with temp.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    temp.chmod(0o600)
    os.replace(temp, ENROLLMENT_PATH)
    return {**value, "materialization": "CREATED"}


SHADOW_LOADER = r"""
import json
import runpy
import sys
release = sys.argv[1]
sys.path.insert(0, release)
sys.argv = ["scripts.rep191_portable", "live-shadow"]
runpy.run_module("scripts.rep191_portable", run_name="__main__")
""".strip()


def validate_shadow_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise LiveActuatorError("SHADOW_RESULT_INVALID")
    if result.get("status") not in {"NO_CHANGE", "CHANGED_SHADOW"}:
        raise LiveActuatorError("SHADOW_RESULT_INVALID", "status")
    required = {
        "mode": "SHADOW",
        "mutation_performed": False,
        "github_mutation_performed": False,
        "remote_worker_id": WORKER_ID,
        "shared_owner_id_observed": "owner-local-rep191",
        "shared_generation_observed": 1,
        "shared_fence_observed": OWNERSHIP["fencing_token"],
    }
    for key, expected in required.items():
        if result.get(key) != expected:
            raise LiveActuatorError("SHADOW_SAFETY_EVIDENCE_FAILED", key)
    for key in ("lifeops_source_revision", "report_source_revision"):
        value = result.get(key)
        if not isinstance(value, str) or SHA40_RE.fullmatch(value) is None:
            raise LiveActuatorError("SHADOW_RESULT_INVALID", key)
    count = result.get("candidate_file_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 2:
        raise LiveActuatorError("SHADOW_RESULT_INVALID", "candidate_file_count")
    _assert_no_secret_keys(result)
    return result


def terminal_evidence_if_present() -> dict[str, Any] | None:
    if not TERMINAL_EVIDENCE_PATH.exists() and not TERMINAL_EVIDENCE_PATH.is_symlink():
        return None
    meta = _regular_file(TERMINAL_EVIDENCE_PATH, "TERMINAL_EVIDENCE_INVALID")
    if stat.S_IMODE(meta.st_mode) != 0o600:
        raise LiveActuatorError("TERMINAL_EVIDENCE_MODE_DRIFT")
    try:
        value = json.loads(TERMINAL_EVIDENCE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LiveActuatorError("TERMINAL_EVIDENCE_INVALID") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("decision_id") != DECISION_ID:
        raise LiveActuatorError("TERMINAL_EVIDENCE_INVALID")
    if (
        value.get("worker_id") != WORKER_ID
        or value.get("bundle_sha256") != REPORT_BUNDLE_SHA256
        or value.get("report_revision") != REPORT_REVISION
        or value.get("credential_values_observed") is not False
    ):
        raise LiveActuatorError("TERMINAL_EVIDENCE_INVALID", "identity")
    validate_shadow_result(value.get("shadow_result"))
    if (
        value.get("remote_dispatch_enabled") is not False
        or value.get("scheduler_cutover_performed") is not False
        or value.get("owner_local_scheduler_changed") is not False
        or value.get("digitalocean_changed") is not False
        or value.get("active_mode_enabled") is not False
    ):
        raise LiveActuatorError("TERMINAL_EVIDENCE_INVALID", "safety")
    return value


def execute_shadow(release: Path) -> dict[str, Any]:
    existing = terminal_evidence_if_present()
    if existing is not None:
        return {"status": "PASS", "terminal_evidence": existing, "execution": "RECONCILED_EXISTING"}
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "-B", "-c", SHADOW_LOADER, str(release)],
        check=False,
        capture_output=True,
        timeout=620,
        env={"PATH": os.environ.get("PATH", "")},
    )
    if result.returncode != 0:
        raise LiveActuatorError("SHADOW_EXECUTION_BLOCKED")
    try:
        shadow_result = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveActuatorError("SHADOW_RESULT_INVALID") from error
    validate_shadow_result(shadow_result)
    return {"status": "PASS", "shadow_result": shadow_result, "execution": "NEW"}


def write_terminal_evidence(
    *,
    self_sha256: str,
    auth: Mapping[str, Any],
    aef: Mapping[str, Any],
    stage: Mapping[str, Any],
    enrollment: Mapping[str, Any],
    shadow_result: Mapping[str, Any],
) -> dict[str, Any]:
    evidence = {
        "schema_version": 1,
        "task_id": TASK_ID,
        "parent_task_id": PARENT_TASK_ID,
        "decision_id": DECISION_ID,
        "actuator_sha256": self_sha256,
        "observed_at": utc_now(),
        "worker_id": WORKER_ID,
        "resource_class": RESOURCE_CLASS,
        "aef_main_observed": aef["aef_main"],
        "report_revision": REPORT_REVISION,
        "bundle_id": REPORT_BUNDLE_ID,
        "bundle_sha256": REPORT_BUNDLE_SHA256,
        "github_browser_auth": "PASS",
        "browser_action_used": bool(auth["browser_action_used"]),
        "credential_values_observed": False,
        "staged_release": stage["release"],
        "staging_publication": stage["publication"],
        "machine_profile_sha256": MACHINE_PROFILE_SHA256,
        "enrollment": {
            "enrollment_id": enrollment["enrollment_id"],
            "generation": enrollment["generation"],
            "state": enrollment["state"],
            "machine_profile_sha256": enrollment["machine_profile_sha256"],
            "materialization": enrollment["materialization"],
        },
        "shadow_result": dict(shadow_result),
        "remote_dispatch_enabled": False,
        "scheduler_cutover_performed": False,
        "owner_local_scheduler_changed": False,
        "digitalocean_changed": False,
        "active_mode_enabled": False,
    }
    _assert_no_secret_keys(evidence)
    _private_parent(TERMINAL_EVIDENCE_PATH, Path("/var/lib/aef"))
    if TERMINAL_EVIDENCE_PATH.exists() or TERMINAL_EVIDENCE_PATH.is_symlink():
        raise LiveActuatorError("TERMINAL_EVIDENCE_ALREADY_EXISTS")
    temp = TERMINAL_EVIDENCE_PATH.with_name(TERMINAL_EVIDENCE_PATH.name + ".tmp-aef207")
    with temp.open("xb") as handle:
        handle.write(canonical_json_bytes(evidence))
        handle.flush()
        os.fsync(handle.fileno())
    temp.chmod(0o600)
    os.replace(temp, TERMINAL_EVIDENCE_PATH)
    return evidence


def repository_validate() -> dict[str, Any]:
    validate_machine_profile_constant()
    if len(EXPECTED_FILES) != 9 or any(item["mode"] != "0444" for item in EXPECTED_FILES):
        raise LiveActuatorError("BUNDLE_CONTRACT_DRIFT")
    if DECISION_ID != "AEF61-REP191-PROTECTED-SHADOW-V1":
        raise LiveActuatorError("DECISION_ID_DRIFT")
    return {
        "status": "PASS",
        "task_id": TASK_ID,
        "decision_id": DECISION_ID,
        "worker_id": WORKER_ID,
        "bundle_sha256": REPORT_BUNDLE_SHA256,
        "file_count": len(EXPECTED_FILES),
        "machine_profile_sha256": MACHINE_PROFILE_SHA256,
        "active_mode_available": False,
        "remote_dispatch_available": False,
        "scheduler_cutover_available": False,
    }


def live_run(expected_self_sha256: str | None) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise LiveActuatorError("ROOT_REQUIRED")
    self_sha = validate_self_hash(expected_self_sha256)
    repository_validate()
    bootstrap = bootstrap_preflight()
    validate_github_cli()
    existing = terminal_evidence_if_present()
    if existing is not None:
        return {
            "status": "PASS",
            "result": "ALREADY_COMPLETED",
            "terminal_evidence_path": str(TERMINAL_EVIDENCE_PATH),
            "shadow_result": existing["shadow_result"],
            "remote_dispatch_enabled": False,
            "scheduler_cutover_performed": False,
        }
    auth = browser_auth()
    aef = verify_current_aef_control_plane()
    stage = stage_report_bundle()
    state = materialize_shadow_state()
    enrollment = materialize_enrollment()
    shadow = execute_shadow(Path(stage["release"]))
    shadow_result = shadow.get("shadow_result")
    if shadow_result is None:
        evidence = shadow.get("terminal_evidence")
        if not isinstance(evidence, dict):
            raise LiveActuatorError("SHADOW_RESULT_INVALID")
        return {
            "status": "PASS",
            "result": "ALREADY_COMPLETED",
            "terminal_evidence_path": str(TERMINAL_EVIDENCE_PATH),
            "shadow_result": evidence["shadow_result"],
            "remote_dispatch_enabled": False,
            "scheduler_cutover_performed": False,
        }
    terminal = write_terminal_evidence(
        self_sha256=self_sha,
        auth=auth,
        aef=aef,
        stage=stage,
        enrollment=enrollment,
        shadow_result=shadow_result,
    )
    return {
        "status": "PASS",
        "result": "ONE_SHOT_SHADOW_COMPLETE",
        "worker_id": WORKER_ID,
        "bootstrap": bootstrap,
        "aef_main_observed": aef["aef_main"],
        "state_materialization": state,
        "enrollment_id": enrollment["enrollment_id"],
        "terminal_evidence_path": str(TERMINAL_EVIDENCE_PATH),
        "shadow_result": terminal["shadow_result"],
        "remote_dispatch_enabled": False,
        "scheduler_cutover_performed": False,
        "stop_before_active": True,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AEF#207 one-shot REP#191 SHADOW live actuator")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--self-sha256")
    run = sub.add_parser("run")
    run.add_argument("--self-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.command == "validate":
            result = repository_validate()
            if args.self_sha256 is not None:
                result["self_sha256"] = validate_self_hash(args.self_sha256)
        elif args.command == "run":
            result = live_run(args.self_sha256)
        else:
            raise LiveActuatorError("COMMAND_INVALID")
    except LiveActuatorError as error:
        print(pretty_json({"status": "BLOCKED", "code": error.code, "detail": error.detail}), end="")
        return 2
    print(pretty_json(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
