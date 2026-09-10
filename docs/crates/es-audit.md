# es-audit

**Role:** persist and query safe decision metadata.

It owns SQLite schema migrations, parameterized writes, retention helpers, and
aggregate queries. Its public model deliberately cannot carry raw telemetry
fields. It does not decide a policy outcome, parse protocols, or forward data.

It depends on `es-core` and SQLite support.
