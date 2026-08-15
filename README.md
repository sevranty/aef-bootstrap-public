# AEF Bootstrap Public

Public distribution repository for generated, secret-free Agent Execution Fabric bootstrap artifacts.

Source of truth remains private:
https://github.com/sevranty/agent-execution-fabric

Parent task:
https://github.com/sevranty/agent-execution-fabric/issues/103

Publication task:
https://github.com/sevranty/aef-bootstrap-public/issues/1

## Bootstrap v3

Source AEF merge:
e283004d3e1d39f4487fdb84d1c6147ba79bf611

Source validation run:
31913055312

Source artifact:
9254192183

Published files:
- aef-worker-v3.yaml: 80900 bytes, SHA-256 6c052d8122fad68fa234147078d7fc640bff307cc261282fb7e39c182d00bb53
- aef-worker-v3-manifest.json: 784 bytes, SHA-256 8ff5722d35f89c58f0c57d68ab52a25b1d376c9ab3967d5781f1c682a8baeb49

Security boundary:
- generated bootstrap distribution only
- no credentials, tokens, private keys, secrets, or private issue attachments
- no private AEF source-tree mirror
- immutable commit URLs are required for DigitalOcean bootstrap
- mutable branch URLs must not be used for worker creation

DigitalOcean must use only the exact immutable raw URL produced after the publication Pull Request is merged. Do not use a URL containing main or another mutable branch name.
