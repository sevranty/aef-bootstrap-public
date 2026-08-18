#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence

_SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from runtime.worker.release import RELEASE_SOURCE_PATHS, build_release_manifest


SOURCE_ROOT = Path("/opt/aef/bootstrap-source-v6")
SOURCE_MANIFEST_PATH = Path("/etc/aef/bootstrap-source-v6.json")
FIRSTBOOT_PATH = "bootstrap/aef_worker_v6_firstboot.py"
PROFILE_PATH = "profiles/worker-v6-default.json"
PUBLIC_YAML_NAME = "aef-worker-v6.yaml"
PUBLIC_MANIFEST_NAME = "aef-worker-v6-manifest.json"
PREPARED_JOB = "report.rep191-lifeops-refresh.shadow"
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


class BootstrapBuildError(RuntimeError):
    pass


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _mapping(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise BootstrapBuildError(f"mapping required: {path}")
    return value


def _safe_source(repository_root: Path, relative: str) -> Path:
    if (
        not relative
        or relative.startswith("/")
        or ".." in Path(relative).parts
        or "\x00" in relative
    ):
        raise BootstrapBuildError(f"unsafe source path: {relative}")
    candidate = repository_root / relative
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise BootstrapBuildError(f"source missing: {relative}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise BootstrapBuildError(f"source invalid: {relative}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(repository_root.resolve(strict=True))
    except ValueError as error:
        raise BootstrapBuildError(f"source escapes repository: {relative}") from error
    return resolved


def collect_source_paths(repository_root: Path) -> tuple[str, ...]:
    root = repository_root.resolve(strict=True)
    profile = _mapping(_safe_source(root, PROFILE_PATH))
    required = set(RELEASE_SOURCE_PATHS)
    required.add(FIRSTBOOT_PATH)
    required.add(PROFILE_PATH)
    for key in (
        "path_contract_source",
        "capability_set_source",
        "jobs_registry_source",
        "prepared_jobs_registry_source",
    ):
        value = profile.get(key)
        if not isinstance(value, str):
            raise BootstrapBuildError(f"profile source invalid: {key}")
        required.add(value)
    capability_set = _mapping(
        _safe_source(root, str(profile["capability_set_source"]))
    )
    external = capability_set.get("external_registry_source")
    if not isinstance(external, str):
        raise BootstrapBuildError("external capability registry invalid")
    required.add(external)
    builtins = capability_set.get("builtins")
    if not isinstance(builtins, list):
        raise BootstrapBuildError("builtin capabilities invalid")
    for item in builtins:
        if not isinstance(item, Mapping) or not isinstance(item.get("source_path"), str):
            raise BootstrapBuildError("builtin capability source invalid")
        required.add(str(item["source_path"]))
    return tuple(sorted(required))


def build_source_manifest(
    repository_root: Path, *, source_revision: str
) -> Mapping[str, Any]:
    if _SHA40_RE.fullmatch(source_revision) is None:
        raise BootstrapBuildError("source_revision must be a lowercase 40-hex commit")
    root = repository_root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    for relative in collect_source_paths(root):
        source = _safe_source(root, relative)
        data = source.read_bytes()
        records.append(
            {
                "path": relative,
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "mode": "0444",
            }
        )
    unsigned: dict[str, Any] = {
        "schema_version": 1,
        "task_id": "AEF#61",
        "source_revision": source_revision,
        "files": records,
    }
    return {
        **unsigned,
        "inventory_sha256": sha256_bytes(canonical_bytes(unsigned)),
    }


def render_cloud_config(
    repository_root: Path,
    *,
    source_revision: str,
    source_manifest: Mapping[str, Any],
) -> bytes:
    root = repository_root.resolve(strict=True)
    lines = [
        "#cloud-config",
        "package_update: false",
        "package_upgrade: false",
        "write_files:",
    ]
    for record in source_manifest["files"]:
        relative = str(record["path"])
        data = _safe_source(root, relative).read_bytes()
        if sha256_bytes(data) != record["sha256"]:
            raise BootstrapBuildError(f"source changed during build: {relative}")
        encoded = base64.b64encode(data).decode("ascii")
        lines.extend(
            [
                f"  - path: {SOURCE_ROOT / relative}",
                "    owner: root:root",
                "    permissions: '0444'",
                "    encoding: b64",
                f"    content: {encoded}",
            ]
        )
    manifest_bytes = canonical_bytes(source_manifest)
    lines.extend(
        [
            f"  - path: {SOURCE_MANIFEST_PATH}",
            "    owner: root:root",
            "    permissions: '0444'",
            "    encoding: b64",
            f"    content: {base64.b64encode(manifest_bytes).decode('ascii')}",
            "runcmd:",
            "  - "
            + json.dumps(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(SOURCE_ROOT / FIRSTBOOT_PATH),
                    "--repository-root",
                    str(SOURCE_ROOT),
                    "--source-manifest",
                    str(SOURCE_MANIFEST_PATH),
                    "--source-revision",
                    source_revision,
                ],
                separators=(",", ":"),
            ),
        ]
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def build_distribution_manifest(
    repository_root: Path,
    *,
    source_revision: str,
    source_manifest: Mapping[str, Any],
    cloud_config: bytes,
) -> Mapping[str, Any]:
    root = repository_root.resolve(strict=True)
    profile = _mapping(_safe_source(root, PROFILE_PATH))
    capabilities = _mapping(
        _safe_source(root, str(profile["capability_set_source"]))
    )
    external = _mapping(
        _safe_source(root, str(capabilities["external_registry_source"]))
    )
    declared = external.get("capabilities")
    if not isinstance(declared, list):
        raise BootstrapBuildError("external capabilities invalid")
    github = next(
        (
            item
            for item in declared
            if isinstance(item, Mapping) and item.get("capability_id") == "github-cli"
        ),
        None,
    )
    if not isinstance(github, Mapping):
        raise BootstrapBuildError("github-cli capability absent")
    source = github.get("source")
    install = github.get("install")
    if not isinstance(source, Mapping) or not isinstance(install, Mapping):
        raise BootstrapBuildError("github-cli capability contract invalid")
    release = build_release_manifest(
        root,
        release_id=str(profile["release_id"]),
    )
    return {
        "schema_version": 6,
        "task_id": "AEF#61",
        "artifact": PUBLIC_YAML_NAME,
        "artifact_bytes": len(cloud_config),
        "artifact_sha256": sha256_bytes(cloud_config),
        "source_revision": source_revision,
        "source_file_count": len(source_manifest["files"]),
        "source_inventory_sha256": source_manifest["inventory_sha256"],
        "source_manifest_sha256": sha256_bytes(canonical_bytes(source_manifest)),
        "worker_profile_id": profile["profile_id"],
        "worker_release_id": profile["release_id"],
        "worker_release_content_sha256": release["content_sha256"],
        "path_contract_revision": profile["path_contract_revision"],
        "capability_set_revision": profile["capability_set_revision"],
        "github_cli": {
            "version": github["version"],
            "source_url": source["url"],
            "source_sha256": source["sha256"],
            "source_bytes": source["bytes"],
            "member_sha256": source["member_sha256"],
            "entrypoint": install["entrypoint"],
        },
        "prepared_job": PREPARED_JOB,
        "post_bootstrap_owner_command": (
            "sudo aefctl --format json credentials github login --then-run "
            + PREPARED_JOB
        ),
        "bootstrap_evidence_path": str(Path("/var/lib/aef/state/bootstrap-v6.json")),
        "runtime_package_installation": "forbidden",
        "credential_values_present": False,
        "remote_dispatch": False,
        "scheduler_cutover": False,
        "active_mode": False,
        "protected_actions_performed": False,
        "distribution_state": "PUBLICATION_REQUIRED",
    }


def build(
    repository_root: Path,
    *,
    source_revision: str,
) -> tuple[bytes, Mapping[str, Any], Mapping[str, Any]]:
    source_manifest = build_source_manifest(
        repository_root,
        source_revision=source_revision,
    )
    cloud_config = render_cloud_config(
        repository_root,
        source_revision=source_revision,
        source_manifest=source_manifest,
    )
    distribution = build_distribution_manifest(
        repository_root,
        source_revision=source_revision,
        source_manifest=source_manifest,
        cloud_config=cloud_config,
    )
    return cloud_config, distribution, source_manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aef-inline-user-data-v6")
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    parser.add_argument("--source-manifest-output", type=Path, default=None)
    args = parser.parse_args(list(argv) if argv is not None else None)
    cloud_config, manifest, source_manifest = build(
        args.repository_root,
        source_revision=args.source_revision,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(cloud_config)
    args.manifest_output.write_bytes(canonical_bytes(manifest))
    if args.source_manifest_output is not None:
        args.source_manifest_output.write_bytes(canonical_bytes(source_manifest))
    print(json.dumps(manifest, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
