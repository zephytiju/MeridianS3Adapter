# S3 release/contract gate inventory

| Surface and variants | Classification | Required behavior |
| --- | --- | --- |
| `aws-s3`, `s3-compatible`; SDK auto/path/virtual addressing | Provider/profile constraint | Closed profile identities, validated endpoint/region/addressing; no invented provisioning mode. |
| Legacy config/manifest `engineVersion`; descriptor `supportedEngineVersions` | Protocol contract/historical metadata | `2006-03-01` identifies S3 API; explicit config contract validation remains after Core removes release membership gates. |
| Optional `selectedServerVersion` | Release provenance | Any bounded safe selection; never gates server features or becomes an observation. |
| Authenticated probe `observed_engine_version` | Observation | Unavailable (`None`); neither input settings nor generic Server headers are evidence. |
| Installed adapter/Core/Object Common versions | Release provenance | Report installed metadata; package bounds require consumed Core v1 SPI and Object v1 APIs. |
| Build/install and `release-validation.txt` | Deployment/release integrity | Exact tested closure and public hashes; package pins are not compiled runtime allowlists. |
| Capability manifest and physical verification | Deployment integrity | Canonical expected-content hashes still detect drift; additive manifest extensions require regenerated expectations. Physical schema format unchanged. |
| Object operations, digest/ranges/conditional create/multipart | Real contract/features | Existing Object runner, protocol request behavior, operation versions and required limits remain. |
| Versioning/Object Lock/retention/KMS | Real features/provider constraints | Authenticated bucket evidence and existing configuration checks; no WORM certification claim. |
| Factory/session TLS/auth/identity/namespace | Security and placement | Existing CA, HTTPS, credential and physical verification; mutual TLS unsupported. |
| Migration, payload registry, ConfigArtifact-facing Object fixtures | Public contract/lifecycle | Existing forward-only migration, payload sharing, immutable metadata and digest behavior retained; no sibling source changes. |

Validation: unit/contract tests vary selected releases independently for both profiles,
round-trip serialized Bindings and manifests, and preserve negative checks. Real tests
use the exact MinIO digest and public closure in `conformance-report.json`, including
invalid identity and TLS handshake failure. Environment release labels are explicitly
selected image provenance; S3-probed software version remains unavailable.

Managed AWS S3 and other server/addressing combinations are unverified here. A passing
metadata test does not claim future release or provider behavior. Downstream
ConfigArtifact/all-family release integration consumes this published adapter.
