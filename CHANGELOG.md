# Changelog

## 1.0.4

- Derive SPDX package identity from project metadata and test release artifact hashes.
- Correct the stale SBOM identity shipped with 1.0.3 without replacing published bytes.

## 1.0.3

- Preserve the S3 API date separately from deployment-selected server releases and unavailable observations.
- Consume released Core 1.1 SPI and Object Common 1.0.3 through compatible API bounds.
- Record actual installed package provenance and regenerate deployment manifest expectations.
- Preserve Object behavior and add real authentication/TLS negatives plus deterministic release provenance fixtures.

## 1.0.2

- Consume released Object Common 1.0.2 with Core 1.0.1 and Semantics 2.0.0.
- Align adapter compatibility metadata, release inputs, and real S3 conformance evidence.
- Preserve Object operations, shared payload discovery, and provider behavior.

## 1.0.1

- Use the shared Object Common default payload registry for installed entry-point discovery.
- Preserve empty explicitly supplied registries in both factory and adapter constructors.
- Report the actual adapter package version in execution provenance.


All notable changes are documented in this file.

## 1.0.0 - 2026-08-25

- Implement the Meridian V1 S3 Object Adapter against Object Common 1.0.0.
- Add streaming, multipart, range, metadata, immutability, retention, health, migration, and
  normalized failure behavior.
- Add unit, contract, packaging, and real S3-compatible conformance coverage.
