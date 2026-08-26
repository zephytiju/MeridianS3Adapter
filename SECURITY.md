# Security policy

Please use GitHub private vulnerability reporting for suspected vulnerabilities. Do not include
credentials, bucket names, endpoints, physical keys, or customer data in reports, logs, fixtures,
or public issues.

The adapter supports the actively maintained 1.x release line. Credentials are accepted only
through Meridian secret values or explicit adapter-composition objects and are redacted from
representations. Consumer Expressions and normalized failures never expose provider configuration.
