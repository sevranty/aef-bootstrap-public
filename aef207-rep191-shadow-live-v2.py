#!/usr/bin/env python3
"""AEF#207 diagnostic-safe v2 actuator for one bounded REP#191 SHADOW retry.

The v2 successor never repeats v1 staging or enrollment writes. It validates the
already-materialized immutable release and local state read-only, preserves a
bounded sanitized REP#214 child failure cause, executes the child at most once,
and writes terminal evidence only after a successful SHADOW result.

No ACTIVE mode, remote dispatch, scheduler cutover, provider mutation, source
mutation, credential-value output, or automatic retry path exists here.
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
import stat
import subprocess
from typing import Any, Mapping, Sequence

TASK_ID = "AEF#207"
PARENT_TASK_ID = "AEF#61"
UMBRELLA_TASK_ID = "AEF#56"
DECISION_ID = "AEF61-REP191-PROTECTED-SHADOW-V2"
V1_DECISION_ID = "AEF61-REP191-PROTECTED-SHADOW-V1"
WORKER_ID = "digitalocean:592813728"
RESOURCE_CLASS = "tiny"

GH_EXECUTABLE = Path("/opt/aef/capabilities/github-cli/2.97.0/bin/gh")
GH_VERSION = "2.97.0"
GH_BINARY_SHA256 = "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409"
GH_HOME = Path("/var/lib/aef/credentials/github/rep191")
AEF_REPOSITORY_API = "repos/sevranty/agent-execution-fabric"
AEF_V2_DESCRIPTOR_PATH = "activation/aef61-rep191-shadow-live-v2.json"
AEF_PREPARED_REGISTRY_PATH = "registry/prepared-jobs-v1.json"

REPORT_REVISION = "30030684822f473c62ff8aadb420f5ee51a430ae"
REPORT_BUNDLE_ID = "rep191-lifeops-refresh-shadow-v2"
REPORT_BUNDLE_SHA256 = "4747fef2258a3b83f3b314286f50b7adb830a2c2b56ae1961953c01ede565f09"
REPORT_ENTRYPOINT = "scripts/rep191_portable/__main__.py"
RELEASE_PATH = Path("/opt/aef/workloads/rep191/releases") / f"{REPORT_BUNDLE_ID}-{REPORT_BUNDLE_SHA256[:16]}"
SHADOW_CONFIG = Path("/etc/aef/jobs/rep191-shadow-v1.json")
CANONICAL_STATE_ROOT = Path("/var/lib/aef/state/rep191")
STATE_ROOT = CANONICAL_STATE_ROOT
OWNERSHIP_PATH = STATE_ROOT / "ownership.json"
MACHINE_PROFILE_PATH = STATE_ROOT / "machine-profile.json"
ENROLLMENT_PATH = STATE_ROOT / "worker-enrollment.json"
V1_TERMINAL_PATH = STATE_ROOT / "shadow-result.json"
V2_TERMINAL_PATH = STATE_ROOT / "shadow-result-v2.json"
ENROLLMENT_ID = "enrollment-aef61-rep191-shadow-worker05-v1"
MACHINE_PROFILE_SHA256 = "c254d1684142d2ecf10a4c8ea1f87d50cb420ba648f40c88e6e17037edd67fc0"
OWNERSHIP_FENCE = "3552fa47788ee3c2c0298060fdc41079365e06660cf25202becd38b3eb3ebba3"
EXPECTED_OWNERSHIP = {
    "schema_version": 1,
    "resource_id": "rep191-lifeops-refresh",
    "generation": 1,
    "owner_id": "owner-local-rep191",
    "fencing_token": OWNERSHIP_FENCE,
    "previous_state_sha256": None,
    "transition_reason": "initial",
    "predecessor_stopped_observed": False,
    "predecessor_fence_verified": False,
}
EXPECTED_SHADOW_CONFIG = {
    "schema_version": 1,
    "mode": "SHADOW",
    "gh_executable": str(GH_EXECUTABLE),
    "gh_home": str(GH_HOME),
    "state_root": str(CANONICAL_STATE_ROOT),
    "ownership_reference": "ownership.json",
    "worker_id": WORKER_ID,
}

EXPECTED_FILES = [
    ("scripts/rep191_portable/__init__.py", 904, "1df9c7cf3ab5ab0f9b1a2a4e46dc645ac2f4166591a9ad33ac2bad56029e4ee9"),
    ("scripts/rep191_portable/__main__.py", 6891, "400ea368187b2e53b65baed7d86e71c13110e73a381fc73aae8df81477e1c79e"),
    ("scripts/rep191_portable/core.py", 23477, "3a263dfc5235a7118d130c4790811fc5f4bce5809b93bf00ccc79f88a94fa227"),
    ("scripts/rep191_portable/filesystem.py", 13789, "b918265d8f9ea20c292b8c90aab8d8b1abde015daa45ee20a106e3f7b796a466"),
    ("scripts/rep191_portable/github_auth.py", 13431, "ac02668d4a16eb1537dc7a8906c59a242f2a9256954daf0648a86ee80b50da5d"),
    ("scripts/rep191_portable/runtime.py", 1403, "00fd5f1de4189fc7c9dedbe3099c0cac2f0326ce73333afdc48ccf6baa7483f7"),
    ("scripts/rep191_portable/scheduler.py", 8381, "96d54362d330d08b2d2caaba7fe7b8551326158537e35188ed16178d0ffdf9a9"),
    ("scripts/rep191_portable/remote_mutation.py", 18761, "677739c596474f53b3d16adc3d10d70a3e076b0c29ad5e1598d4aa43f74ddfe8"),
    ("scripts/rep191_portable/remote_worker.py", 15090, "53aa41b7c128bdf4cf91ce340c6ec5827d5f98a67e5cdf2cd2a0e22811084609"),
]

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHILD_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
MAX_CHILD_STDERR_BYTES = 8192
MAX_CHILD_DETAIL_CHARS = 512
SUSPICIOUS_RE = re.compile(
    r"(?i)(ghp_|github_pat_|-----BEGIN [A-Z ]*PRIVATE KEY-----|authorization\s*:|"
    r"(?:token|password|secret|cookie|api[_-]?key)\s*[=:])"
)
FORBIDDEN_KEYS = {
    "token", "access_token", "oauth_token", "password", "secret", "cookie",
    "credentials", "credential", "private_key", "api_key",
}

SHADOW_LOADER = r"""
import runpy
import sys
release = sys.argv[1]
sys.path.insert(0, release)
sys.argv = ["scripts.rep191_portable", "live-shadow"]
runpy.run_module("scripts.rep191_portable", run_name="__main__")
""".strip()


class ActuatorError(RuntimeError):
    def __init__(
        self,
        code: str,
        detail: str = "",
        *,
        cause: Mapping[str, Any] | None = None,
        partial_state: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.cause = dict(cause) if cause is not None else None
        self.partial_state = dict(partial_state) if partial_state is not None else None


class ChildDiagnosticError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ActuatorError("CANONICAL_JSON_INVALID") from error


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha_file(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _regular_file(path: Path, code: str) -> os.stat_result:
    try:
        meta = path.lstat()
    except OSError as error:
        raise ActuatorError(code, str(path)) from error
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise ActuatorError(code, str(path))
    return meta


def _directory(path: Path, code: str) -> os.stat_result:
    try:
        meta = path.lstat()
    except OSError as error:
        raise ActuatorError(code, str(path)) from error
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise ActuatorError(code, str(path))
    return meta


def _secure_private_directory(path: Path, code: str) -> os.stat_result:
    meta = _directory(path, code)
    if stat.S_IMODE(meta.st_mode) & 0o077 or meta.st_uid not in {0, os.geteuid()}:
        raise ActuatorError(code, str(path))
    return meta


def _no_secret_keys(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_KEYS or any(
                fragment in normalized
                for fragment in (
                    "password",
                    "oauth_token",
                    "access_token",
                    "private_key",
                    "cookie",
                )
            ):
                raise ActuatorError(
                    "SECRET_SHAPED_EVIDENCE_FORBIDDEN", f"{path}.{key}"
                )
            _no_secret_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _no_secret_keys(item, f"{path}[{index}]")


def validate_self_hash(expected: str | None) -> tuple[str, str]:
    path = Path(__file__).resolve()
    actual_sha256 = sha256_file(path)
    if expected is not None and (
        SHA256_RE.fullmatch(expected) is None or actual_sha256 != expected
    ):
        raise ActuatorError("SELF_CHECKSUM_MISMATCH")
    return actual_sha256, git_blob_sha_file(path)


def repository_validate() -> dict[str, Any]:
    if len(EXPECTED_FILES) != 9 or DECISION_ID != "AEF61-REP191-PROTECTED-SHADOW-V2":
        raise ActuatorError("REPOSITORY_CONTRACT_DRIFT")
    return {
        "status": "PASS",
        "task_id": TASK_ID,
        "decision_id": DECISION_ID,
        "historical_v1_decision_id": V1_DECISION_ID,
        "worker_id": WORKER_ID,
        "bundle_sha256": REPORT_BUNDLE_SHA256,
        "file_count": 9,
        "max_child_stderr_bytes": MAX_CHILD_STDERR_BYTES,
        "max_child_detail_chars": MAX_CHILD_DETAIL_CHARS,
        "reconcile_only_available": True,
        "automatic_retry_available": False,
        "active_mode_available": False,
        "remote_dispatch_available": False,
        "scheduler_cutover_available": False,
    }


def protected_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(GH_HOME),
        "GH_PAGER": "cat",
        "NO_COLOR": "1",
    }


def validate_github_cli() -> None:
    meta = _regular_file(GH_EXECUTABLE, "GITHUB_CLI_UNAVAILABLE")
    if not meta.st_mode & stat.S_IXUSR or sha256_file(GH_EXECUTABLE) != GH_BINARY_SHA256:
        raise ActuatorError("GITHUB_CLI_IDENTITY_DRIFT")
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
        raise ActuatorError("GITHUB_CLI_VERSION_DRIFT")


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
    _secure_private_directory(GH_HOME, "PROTECTED_HOME_INVALID")
    if github_auth_ok():
        return {"status": "PASS", "browser_action_used": False}
    print(
        "GitHub: завершите вход в браузере по инструкции gh. Токен сюда не вставляйте.",
        flush=True,
    )
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
        raise ActuatorError("GITHUB_BROWSER_AUTH_BLOCKED")
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
        raise ActuatorError("GITHUB_GET_FAILED", endpoint) from error
    if result.returncode != 0:
        raise ActuatorError("GITHUB_GET_FAILED", endpoint)
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActuatorError("GITHUB_RESPONSE_INVALID", endpoint) from error


def decode_contents(record: Any, label: str) -> bytes:
    if (
        not isinstance(record, dict)
        or record.get("type") != "file"
        or record.get("encoding") != "base64"
        or not isinstance(record.get("content"), str)
    ):
        raise ActuatorError("GITHUB_CONTENTS_INVALID", label)
    try:
        return base64.b64decode("".join(record["content"].split()), validate=True)
    except (ValueError, TypeError) as error:
        raise ActuatorError("GITHUB_CONTENTS_INVALID", label) from error


def validate_prepared_registry(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or value.get("registry_status") != "prepared-disabled"
        or value.get("dispatch_enabled") is not False
    ):
        raise ActuatorError("PREPARED_REGISTRY_DRIFT", "root")
    jobs = value.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 1 or not isinstance(jobs[0], dict):
        raise ActuatorError("PREPARED_REGISTRY_DRIFT", "jobs")
    job = jobs[0]
    activation = job.get("activation")
    source = job.get("source")
    bundle = job.get("bundle")
    if (
        job.get("job_id") != "report.rep191-lifeops-refresh.shadow"
        or job.get("resource_class") != RESOURCE_CLASS
        or job.get("credential_class") != "github-reference"
        or job.get("write_scope") != ["metadata:aef61-shadow-evidence"]
        or job.get("schedule") != {"kind": "manual", "interval_seconds": None}
        or not isinstance(activation, dict)
        or activation.get("state") != "prepared-disabled"
        or activation.get("dispatch_enabled") is not False
        or activation.get("current_scheduler_owner") != "owner-local-rep191"
        or not isinstance(source, dict)
        or source.get("repository") != "https://github.com/sevranty/report"
        or source.get("revision") != REPORT_REVISION
        or source.get("entrypoint") != REPORT_ENTRYPOINT
        or not isinstance(bundle, dict)
        or bundle.get("bundle_id") != REPORT_BUNDLE_ID
        or bundle.get("sha256") != REPORT_BUNDLE_SHA256
    ):
        raise ActuatorError("PREPARED_REGISTRY_DRIFT", "job")


def verify_current_aef_control_plane(
    self_sha256: str, self_blob_sha: str
) -> dict[str, Any]:
    branch = gh_api_json(f"{AEF_REPOSITORY_API}/branches/main")
    current = branch.get("commit", {}).get("sha") if isinstance(branch, dict) else None
    if not isinstance(current, str) or SHA40_RE.fullmatch(current) is None:
        raise ActuatorError("AEF_MAIN_UNAVAILABLE")

    descriptor_bytes = decode_contents(
        gh_api_json(
            f"{AEF_REPOSITORY_API}/contents/{AEF_V2_DESCRIPTOR_PATH}?ref={current}"
        ),
        AEF_V2_DESCRIPTOR_PATH,
    )
    try:
        descriptor = json.loads(descriptor_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActuatorError("AEF_V2_DESCRIPTOR_INVALID") from error

    actuator = descriptor.get("actuator") if isinstance(descriptor, dict) else None
    authorization = (
        descriptor.get("authorization") if isinstance(descriptor, dict) else None
    )
    source = descriptor.get("source") if isinstance(descriptor, dict) else None
    safety = descriptor.get("safety") if isinstance(descriptor, dict) else None
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("task_id") != TASK_ID
        or descriptor.get("parent_task_id") != PARENT_TASK_ID
        or descriptor.get("decision_id") != DECISION_ID
        or descriptor.get("decision_state") != "accepted"
        or not isinstance(actuator, dict)
        or actuator.get("path") != "control/aef61_rep191_shadow_live_v2.py"
        or actuator.get("git_blob_sha") != self_blob_sha
        or actuator.get("sha256") != self_sha256
        or actuator.get("public_identity_state") != "published-verified"
        or not isinstance(authorization, dict)
        or authorization.get("public_byte_identity_required") is not True
        or authorization.get("explicit_owner_authorization_required") is not True
        or authorization.get("live_retry_authorized") is not True
        or not isinstance(source, dict)
        or source.get("repository") != "https://github.com/sevranty/report"
        or source.get("revision") != REPORT_REVISION
        or source.get("bundle_id") != REPORT_BUNDLE_ID
        or source.get("bundle_sha256") != REPORT_BUNDLE_SHA256
        or source.get("entrypoint") != REPORT_ENTRYPOINT
        or source.get("entrypoint_args") != ["live-shadow"]
        or source.get("file_count") != 9
        or not isinstance(safety, dict)
        or safety.get("github_api_method") != "GET"
        or safety.get("active_mode_allowed") is not False
        or safety.get("remote_dispatch_allowed") is not False
        or safety.get("scheduler_cutover_allowed") is not False
        or safety.get("owner_local_scheduler_change_allowed") is not False
        or safety.get("digitalocean_change_allowed") is not False
        or safety.get("source_mutation_allowed") is not False
        or safety.get("local_reconcile_mutation_allowed") is not False
        or safety.get("automatic_retry_allowed") is not False
        or safety.get("stop_after_shadow") is not True
    ):
        raise ActuatorError("AEF_V2_AUTHORIZATION_OR_IDENTITY_INVALID")

    registry_bytes = decode_contents(
        gh_api_json(
            f"{AEF_REPOSITORY_API}/contents/{AEF_PREPARED_REGISTRY_PATH}?ref={current}"
        ),
        AEF_PREPARED_REGISTRY_PATH,
    )
    try:
        registry = json.loads(registry_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActuatorError("PREPARED_REGISTRY_INVALID") from error
    validate_prepared_registry(registry)
    return {"status": "PASS", "aef_main": current, "v2_authorization": "accepted"}


def _read_private_json(path: Path, code: str) -> Any:
    meta = _regular_file(path, code)
    if stat.S_IMODE(meta.st_mode) != 0o600:
        raise ActuatorError(code, f"{path}: mode")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActuatorError(code, f"{path}: json") from error


def validate_release(root: Path = RELEASE_PATH) -> dict[str, Any]:
    _directory(root, "RELEASE_INVALID")
    expected = {path for path, _, _ in EXPECTED_FILES}
    observed: set[str] = set()
    for item in root.rglob("*"):
        if item.is_dir():
            if item.is_symlink():
                raise ActuatorError("RELEASE_INVALID", str(item))
            continue
        if item.is_symlink() or not item.is_file():
            raise ActuatorError("RELEASE_INVALID", str(item))
        observed.add(item.relative_to(root).as_posix())
    if observed != expected:
        raise ActuatorError("RELEASE_FILESET_DRIFT")
    for relative, size, digest in EXPECTED_FILES:
        target = root / relative
        meta = _regular_file(target, "RELEASE_FILE_INVALID")
        if (
            stat.S_IMODE(meta.st_mode) != 0o444
            or meta.st_size != size
            or sha256_file(target) != digest
        ):
            raise ActuatorError("RELEASE_CONTENT_DRIFT", relative)
    return {"status": "PASS", "release": str(root), "file_count": len(expected)}


def validate_shadow_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("status") not in {
        "NO_CHANGE",
        "CHANGED_SHADOW",
    }:
        raise ActuatorError("SHADOW_RESULT_INVALID")
    required = {
        "mode": "SHADOW",
        "mutation_performed": False,
        "github_mutation_performed": False,
        "remote_worker_id": WORKER_ID,
        "shared_owner_id_observed": "owner-local-rep191",
        "shared_generation_observed": 1,
        "shared_fence_observed": OWNERSHIP_FENCE,
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            raise ActuatorError("SHADOW_SAFETY_EVIDENCE_FAILED", key)
    for key in ("lifeops_source_revision", "report_source_revision"):
        if not isinstance(value.get(key), str) or SHA40_RE.fullmatch(value[key]) is None:
            raise ActuatorError("SHADOW_RESULT_INVALID", key)
    count = value.get("candidate_file_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 2:
        raise ActuatorError("SHADOW_RESULT_INVALID", "candidate_file_count")
    _no_secret_keys(value)
    return value


def _terminal(path: Path, decision_id: str) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    value = _read_private_json(path, "TERMINAL_EVIDENCE_INVALID")
    if (
        not isinstance(value, dict)
        or value.get("decision_id") != decision_id
        or value.get("worker_id") != WORKER_ID
        or value.get("bundle_sha256") != REPORT_BUNDLE_SHA256
        or value.get("report_revision") != REPORT_REVISION
    ):
        raise ActuatorError("TERMINAL_EVIDENCE_INVALID", "identity")
    validate_shadow_result(value.get("shadow_result"))
    return value


def reconcile_local_state(
    *,
    release_path: Path = RELEASE_PATH,
    shadow_config_path: Path = SHADOW_CONFIG,
    ownership_path: Path = OWNERSHIP_PATH,
    machine_profile_path: Path = MACHINE_PROFILE_PATH,
    enrollment_path: Path = ENROLLMENT_PATH,
    v1_terminal_path: Path = V1_TERMINAL_PATH,
    v2_terminal_path: Path = V2_TERMINAL_PATH,
) -> dict[str, Any]:
    release = validate_release(release_path)
    config = _read_private_json(shadow_config_path, "SHADOW_CONFIG_INVALID")
    if config != EXPECTED_SHADOW_CONFIG:
        raise ActuatorError("SHADOW_CONFIG_DRIFT")

    ownership = _read_private_json(ownership_path, "OWNERSHIP_INVALID")
    if ownership != EXPECTED_OWNERSHIP:
        raise ActuatorError("OWNERSHIP_DRIFT")

    profile = _read_private_json(machine_profile_path, "MACHINE_PROFILE_INVALID")
    if (
        hashlib.sha256(canonical_json_bytes(profile)).hexdigest()
        != MACHINE_PROFILE_SHA256
        or profile.get("worker_id") != WORKER_ID
    ):
        raise ActuatorError("MACHINE_PROFILE_IDENTITY_DRIFT")

    enrollment = _read_private_json(enrollment_path, "ENROLLMENT_INVALID")
    expected_enrollment_keys = {
        "schema_version",
        "enrollment_id",
        "worker_id",
        "generation",
        "state",
        "machine_profile_sha256",
        "observed_at",
    }
    if (
        set(enrollment) != expected_enrollment_keys
        or enrollment.get("schema_version") != "1"
        or enrollment.get("enrollment_id") != ENROLLMENT_ID
        or enrollment.get("worker_id") != WORKER_ID
        or enrollment.get("generation") != 1
        or enrollment.get("state") != "active"
        or enrollment.get("machine_profile_sha256") != MACHINE_PROFILE_SHA256
    ):
        raise ActuatorError("ENROLLMENT_STATE_DRIFT")
    observed_at = enrollment.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
        raise ActuatorError("ENROLLMENT_INVALID", "observed_at")
    try:
        dt.datetime.fromisoformat(observed_at[:-1] + "+00:00")
    except ValueError as error:
        raise ActuatorError("ENROLLMENT_INVALID", "observed_at") from error

    summary = {
        "status": "PASS",
        "release": {
            "path": release["release"],
            "file_count": release["file_count"],
            "bundle_sha256": REPORT_BUNDLE_SHA256,
        },
        "shadow_config": "EXACT",
        "ownership": {
            "generation": ownership["generation"],
            "owner_id": ownership["owner_id"],
            "predecessor_stopped_observed": ownership[
                "predecessor_stopped_observed"
            ],
            "predecessor_fence_verified": ownership[
                "predecessor_fence_verified"
            ],
        },
        "machine_profile_sha256": MACHINE_PROFILE_SHA256,
        "enrollment": {
            "enrollment_id": enrollment["enrollment_id"],
            "generation": enrollment["generation"],
            "state": enrollment["state"],
            "machine_profile_sha256": enrollment["machine_profile_sha256"],
        },
        "terminal_v1_present": _terminal(v1_terminal_path, V1_DECISION_ID)
        is not None,
        "terminal_v2_present": _terminal(v2_terminal_path, DECISION_ID)
        is not None,
        "child_executed": False,
        "mutation_performed": False,
    }
    _no_secret_keys(summary)
    return summary


def parse_child_blocked(stderr: bytes) -> dict[str, str]:
    if not isinstance(stderr, (bytes, bytearray)) or len(stderr) < 2:
        raise ChildDiagnosticError("stderr-empty-or-type")
    if len(stderr) > MAX_CHILD_STDERR_BYTES:
        raise ChildDiagnosticError("stderr-oversize")
    try:
        text = bytes(stderr).decode("utf-8")
        value = json.loads(text)
    except UnicodeDecodeError as error:
        raise ChildDiagnosticError("stderr-not-utf8") from error
    except json.JSONDecodeError as error:
        raise ChildDiagnosticError("stderr-not-json") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"code", "detail", "status"}
        or value.get("status") != "BLOCKED"
    ):
        raise ChildDiagnosticError("stderr-contract")
    code, detail = value.get("code"), value.get("detail")
    if not isinstance(code, str) or CHILD_CODE_RE.fullmatch(code) is None:
        raise ChildDiagnosticError("stderr-code")
    if (
        not isinstance(detail, str)
        or len(detail) > MAX_CHILD_DETAIL_CHARS
        or any(ord(ch) < 0x20 and ch not in "\t\n" for ch in detail)
        or SUSPICIOUS_RE.search(detail)
    ):
        raise ChildDiagnosticError("stderr-detail-rejected")
    return {"status": "BLOCKED", "code": code, "detail": detail}


def _rejected_cause(reason: str) -> dict[str, str]:
    return {
        "status": "BLOCKED",
        "code": "CHILD_DIAGNOSTIC_REJECTED",
        "detail": reason,
    }


def execute_shadow_once(
    release: Path, partial_state: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["/usr/bin/python3", "-I", "-B", "-c", SHADOW_LOADER, str(release)],
            check=False,
            capture_output=True,
            timeout=620,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except subprocess.TimeoutExpired as error:
        raise ActuatorError(
            "SHADOW_EXECUTION_BLOCKED",
            "pinned REP#214 child timed out",
            cause=_rejected_cause("child-timeout"),
            partial_state=partial_state,
        ) from error
    except OSError as error:
        raise ActuatorError(
            "SHADOW_EXECUTION_BLOCKED",
            "pinned REP#214 child could not start",
            cause=_rejected_cause("child-start-failed"),
            partial_state=partial_state,
        ) from error
    if result.returncode != 0:
        try:
            cause = parse_child_blocked(result.stderr)
        except ChildDiagnosticError as error:
            cause = _rejected_cause(str(error))
        raise ActuatorError(
            "SHADOW_EXECUTION_BLOCKED",
            "pinned REP#214 child returned non-zero",
            cause=cause,
            partial_state=partial_state,
        )
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActuatorError(
            "SHADOW_RESULT_INVALID",
            "child success payload",
            partial_state=partial_state,
        ) from error
    return validate_shadow_result(value)


def _write_terminal(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ActuatorError("TERMINAL_EVIDENCE_ALREADY_EXISTS")
    parent_meta = _secure_private_directory(path.parent, "STATE_ROOT_INVALID")
    if stat.S_IMODE(parent_meta.st_mode) & 0o077:
        raise ActuatorError("STATE_ROOT_PERMISSIONS_INVALID")
    _no_secret_keys(value)
    temp = path.with_name(path.name + ".tmp-aef207-v2")
    if temp.exists() or temp.is_symlink():
        raise ActuatorError("TERMINAL_EVIDENCE_TEMP_EXISTS")
    with temp.open("xb") as handle:
        handle.write(canonical_json_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())
    temp.chmod(0o600)
    os.replace(temp, path)


def write_terminal_evidence(
    self_sha256: str,
    auth: Mapping[str, Any],
    aef: Mapping[str, Any],
    reconciliation: Mapping[str, Any],
    shadow_result: Mapping[str, Any],
    path: Path = V2_TERMINAL_PATH,
) -> dict[str, Any]:
    evidence = {
        "schema_version": 2,
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
        "local_reconciliation": dict(reconciliation),
        "shadow_result": dict(shadow_result),
        "remote_dispatch_enabled": False,
        "scheduler_cutover_performed": False,
        "owner_local_scheduler_changed": False,
        "digitalocean_changed": False,
        "active_mode_enabled": False,
        "automatic_retry_used": False,
    }
    _write_terminal(path, evidence)
    return evidence


def reconcile_run(expected_self_sha256: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ActuatorError("ROOT_REQUIRED")
    self_sha256, self_blob = validate_self_hash(expected_self_sha256)
    repository_validate()
    return {
        "status": "PASS",
        "result": "READ_ONLY_RECONCILIATION",
        "actuator_sha256": self_sha256,
        "actuator_git_blob_sha": self_blob,
        "state": reconcile_local_state(),
        "child_executed": False,
        "mutation_performed": False,
    }


def live_run(expected_self_sha256: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise ActuatorError("ROOT_REQUIRED")
    self_sha256, self_blob = validate_self_hash(expected_self_sha256)
    repository_validate()
    validate_github_cli()

    existing_v2 = _terminal(V2_TERMINAL_PATH, DECISION_ID)
    if existing_v2 is not None:
        return {
            "status": "PASS",
            "result": "ALREADY_COMPLETED_V2",
            "shadow_result": existing_v2["shadow_result"],
            "remote_dispatch_enabled": False,
            "scheduler_cutover_performed": False,
        }
    existing_v1 = _terminal(V1_TERMINAL_PATH, V1_DECISION_ID)
    if existing_v1 is not None:
        return {
            "status": "PASS",
            "result": "ALREADY_COMPLETED_V1",
            "shadow_result": existing_v1["shadow_result"],
            "remote_dispatch_enabled": False,
            "scheduler_cutover_performed": False,
        }

    pre_auth_reconciliation = reconcile_local_state()
    if (
        pre_auth_reconciliation["terminal_v1_present"]
        or pre_auth_reconciliation["terminal_v2_present"]
    ):
        raise ActuatorError("TERMINAL_EVIDENCE_RACE")

    auth = browser_auth()
    aef = verify_current_aef_control_plane(self_sha256, self_blob)

    reconciliation = reconcile_local_state()
    if reconciliation["terminal_v1_present"] or reconciliation["terminal_v2_present"]:
        raise ActuatorError("TERMINAL_EVIDENCE_RACE")

    shadow_result = execute_shadow_once(
        Path(reconciliation["release"]["path"]), reconciliation
    )
    terminal = write_terminal_evidence(
        self_sha256, auth, aef, reconciliation, shadow_result
    )
    return {
        "status": "PASS",
        "result": "ONE_SHOT_SHADOW_V2_COMPLETE",
        "worker_id": WORKER_ID,
        "aef_main_observed": aef["aef_main"],
        "terminal_evidence_path": str(V2_TERMINAL_PATH),
        "shadow_result": terminal["shadow_result"],
        "remote_dispatch_enabled": False,
        "scheduler_cutover_performed": False,
        "automatic_retry_used": False,
        "stop_before_active": True,
    }


def error_document(error: ActuatorError) -> dict[str, Any]:
    value: dict[str, Any] = {
        "status": "BLOCKED",
        "code": error.code,
        "detail": error.detail,
    }
    if error.cause is not None:
        value["cause"] = error.cause
    if error.partial_state is not None:
        value["partial_state"] = error.partial_state
    _no_secret_keys(value)
    return value


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AEF#207 diagnostic-safe REP#191 SHADOW actuator v2"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--self-sha256")
    reconcile = sub.add_parser("reconcile")
    reconcile.add_argument("--self-sha256", required=True)
    run = sub.add_parser("run")
    run.add_argument("--self-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if args.command == "validate":
            result = repository_validate()
            if args.self_sha256 is not None:
                result["self_sha256"], result["git_blob_sha"] = validate_self_hash(
                    args.self_sha256
                )
        elif args.command == "reconcile":
            result = reconcile_run(args.self_sha256)
        elif args.command == "run":
            result = live_run(args.self_sha256)
        else:
            raise ActuatorError("COMMAND_INVALID")
    except ActuatorError as error:
        print(pretty_json(error_document(error)), end="")
        return 2
    print(pretty_json(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
