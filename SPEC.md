# SPEC - log_analysis_system

> What this repo is for, what it deliberately does not do, and what must stay
> true for a change to be correct.

## 1. Purpose

Turn unstructured server logs into answers: parse them with regex, detect
response-time anomalies statistically, identify security threats, alert by
email, and archive what has been processed.

The measurable claim: **97% parsing accuracy** on real Apache logs. The
remaining 3% matters more than the 97% - see invariant 2.

## 2. Scope

**In scope** - a configurable Apache parser driven by YAML pattern definitions;
performance and security analysers; statistical anomaly detection on response
times; SMTP alerting; SQLite storage; automatic archival; a dashboard.

**Explicitly out of scope**

- **Being a SIEM.** No correlation across hosts, no retention policy engine, no
  compliance reporting.
- **Log shipping.** It reads files that are already on the machine.
- **Non-Apache formats out of the box.** The parser is pattern-driven, so a new
  format is a YAML entry - but only Apache patterns ship.
- **Real-time streaming.** Batch over a file.

## 3. Architecture

```
config/patterns.yaml --> src/parsers/apache_parser
config/config.yaml         |
                           +--> src/analyzers/  performance | security
                           +--> src/alerting/   detector -> notifier (SMTP)
                           +--> src/storage/    database (SQLite)
                           +--> archival
config/suspicious_ips.txt feeds the security analyser
```

## 4. Invariants

1. **Patterns live in YAML, not in code.** A new log format is configuration.
2. **Unparseable lines are counted and retained, never silently dropped.** A
   parser reporting 97% accuracy while discarding the other 3% is reporting on
   the lines it happened to understand - and the malformed lines are
   disproportionately the interesting ones.
3. **Anomaly detection is statistical, not a fixed threshold.** A hard-coded
   "slow means over 500ms" is wrong for every service that is not the one it was
   written for.
4. **Alerting is separated into detection and notification.** What counts as
   worth waking someone for is a policy decision; SMTP is plumbing.
5. **Archival happens only after successful storage.** A log archived before its
   rows are committed is a log that is gone.

## 5. Verification

`test_analysis.py` and a `tests/` suite with several runners.
`config/suspicious_ips.txt` provides a deterministic fixture for the security
analyser.

## 6. Known limitations

- **Apache patterns only** in the shipped configuration.
- **SQLite**, so concurrent writers are not supported.
- **SMTP alerting has no rate limiting or deduplication** - a sustained incident
  produces a sustained volume of mail.
- **Single host.** No aggregation across servers, which is the first thing a
  real deployment would need.

## 7. Related

Shares its layering with `data-warehouse-etl` and the other ETL projects.
