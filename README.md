# Meridian Storage S3

`meridian-storage-s3` is the S3-compatible Object Adapter for Meridian V1. It implements
the released `meridian-storage-object-common>=1.0.3,<2` contract behind the `s3` adapter id.
Consumers continue to use mapping-first `object` Catalog Expressions; bucket names, keys,
endpoints, credentials, SDK objects, retention controls, and migration state remain private to
deployment composition and this adapter.

## Contract and guarantees

The adapter implements all eight V1 Object operation contracts:

- `publish_schema` and `create_resource` for adapter-owned Object registry metadata;
- streaming `put` and `get` with SHA-256 verification and bounded memory;
- inclusive `read_range` with per-chunk integrity verification;
- `stat`, maintenance-only bounded-prefix `list`, and exact-version `delete`;
- S3 multipart upload above a validated threshold;
- portable user metadata and immutability/retention intent;
- optional S3 Object Lock enforcement when the IaC-owned bucket enables it;
- deterministic capabilities, authenticated health probes, physical verification, and
  externally orchestrated migration hooks.

The adapter never provisions a bucket, changes bucket policy, enables versioning/Object Lock,
creates identities, manages ACLs, configures lifecycle/replication/recovery, or returns a
pre-signed URL. Those authorities remain with Platform or Vangu IaC.

## Installation

```bash
python -m pip install meridian-storage-s3==1.0.4
```

Python 3.12 or newer is required. Public API bounds admit Core `>=1.1,<2` and Object Common `>=1.0.3,<2`.
The exact tested closure is Core 1.1.0, Semantics 2.0.1, and Object Common 1.0.3. It is discovered through the
`meridian_storage.adapters` entry-point group.

## Deployment configuration

`S3AdapterFactory` consumes a closed Meridian `BindingConfig`. The physical namespace is
`bucket` or `bucket/prefix`; the binding endpoint, opaque identity/credential secret values,
TLS policy, and validated settings are translated privately to the S3 SDK. Supported settings
are listed below; unknown settings fail closed.

- `identity` resolves to the UTF-8 S3 access-key id.
- `credential` resolves either to the UTF-8 secret access key or to
  `{"secretAccessKey":"...","sessionToken":"..."}` for temporary credentials.
- `endpoint` must already be resolved by IaC. HTTP is accepted only with disabled TLS and
  `allowInsecureHttp: true`; authenticated server TLS requires HTTPS plus resolved CA material.
  Mutual TLS is rejected because the boto3 transport cannot safely consume the Core client
  identity contract.
- `selectedServerVersion` optionally records the deployment-selected storage software release.
  It is bounded provenance, not a compatibility allowlist or a probe observation.
- `region` defaults to `us-east-1`; `addressingStyle` is `auto`, `path`, or `virtual`.
- `multipartThresholdBytes`, `multipartPartBytes`, `spoolMemoryBytes`,
  `integrityChunkBytes`, `maxObjectBytes`, `maxRangeBytes`, and `maxAttempts` are bounded before
  an SDK client or transfer is created.
- `verifyAfterWrite` defaults to true. `checksumHeaders` enables provider SHA-256 headers in
  addition to Meridian's mandatory end-to-end digest verification.
- `serverSideEncryption` is `AES256` or `aws:kms`; `kmsKeyId` is required only for `aws:kms`.
- `requireVersioning` fails authenticated startup unless versioning is verified.
- `objectLockMode` is `GOVERNANCE` or `COMPLIANCE` and requires an IaC-created Object-Lock bucket.

Development-only HTTP endpoints require `allowInsecureHttp: true`. Production bindings should
use authenticated TLS. Enforced retention is advertised only when `objectLockMode` is configured
and the authenticated probe verifies Object Lock on the bucket. This is enforcement evidence,
not a WORM compliance or certification claim.

`S3MigrationHooks` exposes a deterministic forward-only metadata plan and idempotent apply hook.
It validates access and records the adapter metadata revision; the external IaC migration job
still owns scheduling, rollback/recovery decisions, bucket changes, and lifecycle policy.

## Failure and data handling

Payloads are spooled with bounded memory, hashed before publication, uploaded with conditional
metadata records, and read back for verification by default. Multipart sessions are aborted on
every incomplete path. Range reads fetch and verify every complete integrity chunk covering the
requested inclusive range. Logical ids, bucket names, endpoints, credentials, physical keys, and
provider response text are absent from consumer references and normalized failures.

The adapter maps authenticated provider failures to the released Object error taxonomy, including
conditional conflicts, not-found, range, throttling, quota, corruption, authorization, retention,
and unavailable outcomes. Maintenance listing scans a bounded number of pages and uses an opaque
logical cursor.

## Verification

```bash
python -m pytest
python -m mypy src
python -m ruff check .
python -m build
```

The integration suite targets a disposable real MinIO server and runs the released Object Common
conformance runner plus provider-specific multipart, range, metadata, retention, and normalized
failure checks. The engine image is pinned by immutable multi-platform digest. CI regenerates and
byte-compares [the committed conformance report](evidence/conformance-report.json); the locked
design/contract inputs and released Object Common wheel hash are recorded in
[the design baseline](evidence/design-baseline.json).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Payload composition (1.0.1)

Installed S3 discovery uses Object Common’s `default_payload_registry()`. An Object
consumer using that same default can upload and read through Meridian without
registering a second S3 factory. Core intentionally rejects injecting `s3` again
when its installed entry point is present. Explicit SPI compositions may still pass
`S3AdapterFactory(payloads=registry)`; an empty registry is preserved by identity.

## API contract and release provenance (1.0.3)

For both `aws-s3` and `s3-compatible`, legacy `engineVersion` continues to mean
S3 API `2006-03-01`. A storage software release belongs in the optional Binding
setting `selectedServerVersion` (`S3Config.selected_server_version`), never in
that protocol field. Unknown profiles and unsupported API contracts still fail.
AWS-managed S3 need not provide a selectable storage-server software release.
This package does not provision any provider or add a managed mode.

`AdapterProbe.observed_engine_version` is `None`: standard authenticated S3
operations do not identify server software releases. Configuration, API dates,
and generic Server headers are not authenticated release observations. The
manifest records installed Core/Object Common and adapter distribution releases,
the API contract and the optional selected server release separately. Runtime
result provenance labels the protocol and unavailable observation explicitly.

The manifest keeps Core's v1 serialization with additive extension fields. Its
canonical fingerprint therefore changes on upgrade or a selected release change;
deployments must regenerate their expected manifest from their exact installed
release closure. Physical schema fingerprints and the legacy protocol semantics
are preserved. Old fingerprints are never accepted by ignoring mismatches.
Deployment owns exact package/image locks and must verify their hashes; this
adapter does not infer behavioral compatibility from equal release numbers.

See [gate inventory](evidence/release-gates.md), [tested dependency coordinates](evidence/release-validation.txt)
and [public artifact hashes](evidence/release-artifacts.json). Bounds express the
consumed stable v1 Core SPI and Object APIs, not arbitrary future conformance.
Unlisted release tests establish metadata behavior only. Real MinIO evidence
covers exactly the committed image/closure; managed AWS S3, other S3 servers,
virtual-hosted cloud endpoints and additional releases remain unverified.
Existing Object/ConfigArtifact-facing payload, digest, immutability and metadata
fixtures are unchanged; consuming ConfigArtifact release-closure integration is
verified by the downstream owning-package task.

Release 1.0.4 corrects the 1.0.3 SBOM package identity: the generator reads owning
project metadata and packaging tests verify its version and artifact hashes.
The 1.0.3 package bytes remain immutable; consume 1.0.4 for the corrected SBOM.
