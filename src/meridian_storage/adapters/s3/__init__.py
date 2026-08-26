# SPDX-License-Identifier: Apache-2.0
"""S3 implementation of the released Meridian V1 Object contract."""

from ._version import __version__
from .adapter import S3ObjectAdapter
from .config import S3Config, S3Credentials
from .descriptor import (
    S3_ADAPTER_CONTRACT_VERSION,
    S3_ADAPTER_ID,
    s3_capability_manifest,
    s3_descriptor,
)
from .factory import S3AdapterFactory, S3AdapterRuntime, S3AdapterSession
from .migration import (
    S3_METADATA_REVISION,
    S3MigrationHooks,
    S3MigrationPlan,
    S3MigrationResult,
)
from .probe import S3HealthProbe, S3ProbeEvidence
from .retention import RetentionRecord
from .transport import S3Transport, create_s3_client

__all__ = [
    "S3_ADAPTER_CONTRACT_VERSION",
    "S3_ADAPTER_ID",
    "S3_METADATA_REVISION",
    "RetentionRecord",
    "S3AdapterFactory",
    "S3AdapterRuntime",
    "S3AdapterSession",
    "S3Config",
    "S3Credentials",
    "S3HealthProbe",
    "S3MigrationHooks",
    "S3MigrationPlan",
    "S3MigrationResult",
    "S3ObjectAdapter",
    "S3ProbeEvidence",
    "S3Transport",
    "__version__",
    "create_s3_client",
    "s3_capability_manifest",
    "s3_descriptor",
]
