# AEF Bootstrap Public

Public distribution repository for generated, secret-free Agent Execution Fabric bootstrap artifacts and exact pre-auth activation helpers.

Source of truth remains private:
https://github.com/sevranty/agent-execution-fabric

Activation task:
https://github.com/sevranty/agent-execution-fabric/issues/61

Current publication task:
https://github.com/sevranty/aef-bootstrap-public/issues/13

## Current canonical worker-v6 bootstrap for AEF#61

Source task:
https://github.com/sevranty/agent-execution-fabric/issues/61

Publication task:
https://github.com/sevranty/aef-bootstrap-public/issues/13

Source AEF merge:
`e3c9e0bb460639cf77ec69fb43769ade74a498a1`

Published candidate files:
- `aef-worker-v6.yaml` - 382387 bytes, SHA-256 `2d77df7875c7509b81a05d45b6c00357f199a05e5e9f47e78398a1af5a07c649`
- `aef-worker-v6-manifest.json` - 1580 bytes, SHA-256 `43a020f8f34888b701c44380dcfd17dcb87572fb9cd3be83b162a98660063cb3`

Pinned identities:
- source inventory SHA-256 `2c85e3e59f394e87b19f385325f539b67e015f1d5914bc5ddbb0f0cf17ad3e4a`
- source manifest SHA-256 `ecc91ce6ed6bd0eeabdcece769053d5e44c892cc2a2c2426757da275e0ac094d`
- worker release content SHA-256 `1d9945489c033270e6346e3ac73af130ee1407ab6a6499b44d87efffc5ce4471`
- path contract `path-contract-v2`
- capability set `capability-set-v1`
- GitHub CLI `2.97.0`, exact archive and binary checksums recorded in the manifest

The v6 distribution is intentionally pre-authorization and pre-ACTIVE. It contains no credential values and performs no DigitalOcean provider mutation, remote dispatch, scheduler cutover or ACTIVE transition. Workload package installation is forbidden. GitHub CLI is installed declaratively before job admission.

After a clean host completes bootstrap and all local readiness checks pass, the only prepared owner command is:

`sudo aefctl --format json credentials github login --then-run report.rep191-lifeops-refresh.shadow`

That command is not authorization to run it. AEF#61 requires a separate owner decision before creation of a new DigitalOcean Droplet. After creation, the browser-auth command may execute exactly one prepared REP#191 SHADOW and must stop before ACTIVE or scheduler cutover.

Only an immutable raw URL containing the factual public merge SHA may be used for DigitalOcean bootstrap. A mutable `main` or task-branch URL is forbidden.

## Current AEF#207 diagnostic-safe SHADOW v2 actuator

Source task:
https://github.com/sevranty/agent-execution-fabric/issues/207

Source AEF merge:
64ace61fa87b9b6ade958e3a0da63bea826085af

Source full validation run:
32048390857

Published files:
- `aef207-rep191-shadow-live-v2.py` - byte-identical to private source Git blob `56419c35dbbddd216f47ef650ef9013b693abc67`, 34182 bytes, SHA-256 `b64e04f9180adb87285981a76758e91978d14a4cbeb51b7f8773551206324a3a`;
- `aef207-rep191-shadow-live-v2-manifest.json` - secret-free source/distribution identity with `protected_retry_authorized=false`.

The v2 actuator is prepared for decision `AEF61-REP191-PROTECTED-SHADOW-V2`, but publication does not authorize or perform a protected retry. It preserves the immutable v1 evidence, validates the already-materialized local release/state read-only, keeps a bounded sanitized child failure cause, executes the child at most once only after a separate explicit authorization, and has no ACTIVE mode, remote dispatch, scheduler cutover, provider mutation, source mutation or credential-value output path.

Only an immutable raw URL containing the factual public merge SHA may be used for any later owner-authorized invocation. A mutable `main` or task-branch URL is forbidden.

## Historical AEF#207 one-shot SHADOW v1 actuator

Source task:
https://github.com/sevranty/agent-execution-fabric/issues/207

Source AEF merge:
b93716bce237de73b46168c3c29d6e797a468dd7

Source full validation run:
32014300126

Published files:
- `aef207-rep191-shadow-live.py` - byte-identical to private source Git blob `4a05e0be9632c7f726b6ad3080f4e1bb16606e88`, SHA-256 `489d44e8d1861b123b21e87baf2377e26d62ca2909fb4fed33722661295a6845`;
- `aef207-rep191-shadow-live-manifest.json` - secret-free source/distribution identity.

The v1 actuator exists only for the explicitly authorized historical AEF#61 decision `AEF61-REP191-PROTECTED-SHADOW-V1`:
- target worker is exactly `digitalocean:592813728`;
- owner interaction is one checksum-pinned invocation plus one GitHub browser-auth flow if auth is absent;
- source staging uses GitHub contents API `GET` only;
- the exact REP#214 SHADOW bundle is verified before atomic publication;
- one bounded worker enrollment record is materialized;
- exactly one REP#191 `live-shadow` is executed;
- terminal evidence must explicitly report `mutation_performed=false` and `github_mutation_performed=false`;
- remote dispatch, hourly scheduling, owner-local scheduler cutover, higher generation/fence, DigitalOcean changes and REPORT/source mutation are unavailable;
- the process stops after terminal SHADOW evidence.

The v1 publication is retained as immutable historical evidence and is not authorization to retry it.

## Current bootstrap v5

Source task:
https://github.com/sevranty/agent-execution-fabric/issues/167

Source AEF merge:
017c93e8d0317a8637ea0c41fdc0e7b8cf6636e3

Source full validation run:
31947983555

Source clean-bootstrap v5 validation run:
31947983513

Source artifact:
9263834307

Source artifact digest:
sha256:d5c0702baba5637bb84c9dd4bfaac167f74350c99497ab317101e128115ac716

Published files:
- aef-worker-v5.yaml: 125666 bytes, SHA-256 7ab08496444bca789a681519700e8ffe477282e99c69b1c1df172521f2ca6095
- aef-worker-v5-manifest.json: 1429 bytes, SHA-256 8a91db7a84d9417821dc906b8a00e8c3411c6953d1234618203011729e455a40

Bootstrap v5 preserves the accepted AEF worker release and adds a separately verified immutable GitHub CLI capability required by REP#191 admission:
- AEF release remains `a1eee6efa50b367d7ef2ffade4833fbf2b670c9b6476a7173d0679de663a33ce`;
- GitHub CLI is pinned to `2.97.0` for Linux amd64;
- source asset is exactly 14770812 bytes with SHA-256 `a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112`;
- the archive is verified before extracting only the exact `bin/gh` member;
- no package-manager install, mutable `latest` URL or credential value is used;
- the capability is published atomically under `/opt/aef/capabilities/github-cli/2.97.0`;
- bootstrap verifies `gh --version` without performing authentication;
- root-mode Ubuntu 24.04 production-sequence acceptance remains mandatory;
- v3/v4 historical regressions remain mandatory;
- provider attempts remain forbidden until repository and public distribution gates pass.

## Historical bootstrap v4

Publication task:
https://github.com/sevranty/aef-bootstrap-public/issues/5

Source task:
https://github.com/sevranty/agent-execution-fabric/issues/150

Source AEF merge:
3f1cd7f9e954cfd286c12b7afab9e34cacb9bd20

Source full validation run:
31916970022

Source clean-bootstrap v4 root-mode validation run:
31916970105

Source artifact:
9255179132

Published files retained as historical evidence:
- aef-worker-v4.yaml: 100695 bytes, SHA-256 b8be3e80dfcd840a0aaf50d1b6d377dec857a77d0ce942718fcb2d9ba20a487c
- aef-worker-v4-manifest.json: 1031 bytes, SHA-256 b99ac0759f538897a2cabeb757b7b8dafe472f2e14d48113069e9a42cb0026da

Bootstrap v4 established root-mode clean-host acceptance, bytecode-free runtime smoke, deterministic status evidence and the rule that failed clean hosts are not repaired into acceptance.

## Historical bootstrap v3

Publication task:
https://github.com/sevranty/aef-bootstrap-public/issues/3

Source AEF merge:
b36dfe677d446d77d093ec9975aaca75515c613d

Source full validation run:
31914973768

Source one-shot validation run:
31914973820

Source artifact:
9254661301

Published files retained as historical evidence:
- aef-worker-v3.yaml: 81936 bytes, SHA-256 ac1ee32fb5fa1b50a2a4fc5858bb149410580ddd73a6b1a6ff5252a251d6e2a8
- aef-worker-v3-manifest.json: 784 bytes, SHA-256 c27753fa5fdadafa43ddac749c23bea95fd00ee496c4fe3ed13888b87ecc6157

Bootstrap v3 incorporated canonical Ubuntu 24.04 provider parity and exact no-terminal-newline DigitalOcean `#include` payloads.

## Security boundary

- generated/bootstrap/activation distribution only
- no credentials, tokens, private keys, secrets, or private issue attachments
- no private AEF source-tree mirror beyond explicitly approved exact secret-free distribution artifacts
- immutable commit URLs are required for DigitalOcean bootstrap and protected pre-auth activation helpers
- mutable branch URLs must not be used for worker creation or live owner invocation
- public validation pins bootstrap v3, v4, v5, worker v6 and AEF#207 SHADOW actuator v1 + v2 identities
- public validation pins v2 byte count, SHA-256, Git blob, manifest contract and `protected_retry_authorized=false`
- public validation checks forbidden credential markers across both AEF#207 actuator generations
- public validation also pins the v5 GitHub CLI asset identity and capability contract
- public validation pins worker-v6 byte count, SHA-256, manifest, source revision, source inventory, release checksum and negative safety flags
- public validation checks forbidden credential markers in published bootstrap and actuator artifacts

DigitalOcean must use only the exact immutable raw URL produced after the relevant publication Pull Request is merged. Do not use a URL containing `main` or another mutable branch name.
