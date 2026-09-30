# vuln-demo-app-v4

Demo Java project to validate all five fields added by the Jira integration enrichment PR:

| Field | Source | Expected value |
|---|---|---|
| **Package** | `scaData.packageName/Version` | e.g. `log4j-core@2.14.1` |
| **Fix version** | `scaData.fixedIn[0]` | e.g. `2.17.1` |
| **Reachability** | `scaData.reachability` | `function` or `package` |
| **SCM path** | `project.target_file` | `services/payment/pom.xml` |
| **NVD link** | added per CVE | `nvd.nist.gov/vuln/detail/CVE-…` |

## Vulnerabilities included

| CVE | Package | Severity | Reachability | Fix |
|---|---|---|---|---|
| CVE-2021-44228 | log4j-core@2.14.1 | CRITICAL | function | 2.17.1 |
| CVE-2022-42889 | commons-text@1.9 | CRITICAL | function | 1.10.0 |
| CVE-2015-6420 | commons-collections@3.2.1 | HIGH | package | 3.2.2 |

## Requirements

- Snyk org with **reachability analysis** enabled (Enterprise plan)
- Java 11+, Maven 3.x

## Setup

```bash
# 1. Monitor the project
snyk monitor \
  --file=services/payment/pom.xml \
  --reachability \
  --project-name="payment-service" \
  --org=<YOUR_ORG_ID>

# 2. Connect the org to Jira via the integration settings
# 3. Trigger a re-sync or wait for the next Kafka event
```

## Expected Jira ticket (log4j-core)

```
**Package:** log4j-core@2.14.1

**Fix version:** 2.17.1

**Reachability:** function

**SCM path:** services/payment/pom.xml
```

## Why Java?

Snyk's call-graph reachability analysis for Java is available without additional
flags. For JavaScript, reachability requires `--reachability` plus an org-level
feature flag that is not enabled on all environments.
