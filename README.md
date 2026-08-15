# AEF Bootstrap Public

Public distribution repository for generated, secret-free Agent Execution Fabric bootstrap artifacts.

Source of truth remains private:
https://github.com/sevranty/agent-execution-fabric

Parent task:
https://github.com/sevranty/agent-execution-fabric/issues/126

Activation task:
https://github.com/sevranty/agent-execution-fabric/issues/61

Publication task:
https://github.com/sevranty/aef-bootstrap-public/issues/3

## Bootstrap v3

Source AEF merge:
b36dfe677d446d77d093ec9975aaca75515c613d

Source full validation run:
31914973768

Source one-shot validation run:
31914973820

Source artifact:
9254661301

Published files:
- aef-worker-v3.yaml: 81936 bytes, SHA-256 ac1ee32fb5fa1b50a2a4fc5858bb149410580ddd73a6b1a6ff5252a251d6e2a8
- aef-worker-v3-manifest.json: 784 bytes, SHA-256 c27753fa5fdadafa43ddac749c23bea95fd00ee496c4fe3ed13888b87ecc6157

This publication incorporates AEF#126 provider parity:
- canonical Ubuntu 24.04 `/etc/os-release -> ../usr/lib/os-release` is accepted only when it resolves to the exact canonical target;
- arbitrary symlink targets fail closed;
- DigitalOcean provider `#include` payloads are generated without a terminal newline so owner input and provider metadata have the same byte identity.

Security boundary:
- generated bootstrap distribution only
- no credentials, tokens, private keys, secrets, or private issue attachments
- no private AEF source-tree mirror
- immutable commit URLs are required for DigitalOcean bootstrap
- mutable branch URLs must not be used for worker creation

DigitalOcean must use only the exact immutable raw URL produced after the publication Pull Request is merged. Do not use a URL containing main or another mutable branch name.
