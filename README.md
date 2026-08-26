# Meridian Storage S3

`meridian-storage-s3` is the S3-compatible Object Adapter for Meridian V1. It implements
the released `meridian-storage-object-common==1.0.0` contract behind the `s3` adapter id.
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
python -m pip install meridian-storage-s3==1.0.0
```

Python 3.12 or newer is required. The package pins the released Object Common contract and
is discovered through the `meridian_storage.adapters` entry-point group.

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
