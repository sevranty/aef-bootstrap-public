# AEF Bootstrap Public

Public distribution repository for generated, secret-free Agent Execution Fabric bootstrap artifacts.

Source of truth remains private:
https://github.com/sevranty/agent-execution-fabric

Activation task:
https://github.com/sevranty/agent-execution-fabric/issues/61

Current publication task:
https://github.com/sevranty/aef-bootstrap-public/issues/5

## Current bootstrap v4

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

Published files:
- aef-worker-v4.yaml: 100695 bytes, SHA-256 b8be3e80dfcd840a0aaf50d1b6d377dec857a77d0ce942718fcb2d9ba20a487c
- aef-worker-v4-manifest.json: 1031 bytes, SHA-256 b99ac0759f538897a2cabeb757b7b8dafe472f2e14d48113069e9a42cb0026da

Bootstrap v4 adds the clean-host acceptance controls required after the third live acceptance failure:
- root-mode Ubuntu 24.04 / Python 3.12 parity is a required repository gate;
- runtime import smoke is bytecode-free and proves that the immutable release tree is not changed;
- all three historical live clean-deploy failures are regression-covered;
- worker-local read-only status is available in both human-readable and deterministic JSON forms;
- bootstrap records stable phases, passed checks, failure code/detail, safe next action and a secret-free event log;
- a new live provider attempt is forbidden until repository and public immutable-distribution gates both pass;
- failed clean hosts are evidence and are not repaired into acceptance.

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

Bootstrap v3 incorporated AEF#126 provider parity:
- canonical Ubuntu 24.04 `/etc/os-release -> ../usr/lib/os-release` is accepted only when it resolves to the exact canonical target;
- arbitrary symlink targets fail closed;
- DigitalOcean provider `#include` payloads are generated without a terminal newline so owner input and provider metadata have the same byte identity.

## Security boundary

- generated bootstrap distribution only
- no credentials, tokens, private keys, secrets, or private issue attachments
- no private AEF source-tree mirror
- immutable commit URLs are required for DigitalOcean bootstrap
- mutable branch URLs must not be used for worker creation
- public validation pins both historical v3 and current v4 byte count and SHA-256

DigitalOcean must use only the exact immutable raw URL produced after the publication Pull Request is merged. Do not use a URL containing `main` or another mutable branch name.
