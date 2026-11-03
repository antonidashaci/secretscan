# secretscan

Catch committed API keys, tokens and database passwords before they reach a
remote. One file, no dependencies, built to run as a pre-commit hook.

```bash
python secretscan.py .
```

```
src/config.py:14: AWS access key: AKIA...LE (20 chars)
.env.backup:3: Database URL with password: post...@ (48 chars)

2 potential secret(s). Add '# secretscan: ignore' to a line that is a false positive.
```

Exits `1` on a hit, `0` when clean, `2` on a bad path.

## Install

```bash
curl -O https://raw.githubusercontent.com/antonidashaci/secretscan/main/secretscan.py
```

Python 3.9+. No dependencies.

## As a pre-commit hook

```bash
echo 'python secretscan.py . || exit 1' >> .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## What it looks for

AWS access and secret keys, GitHub tokens, Slack tokens, Stripe keys, Google
API keys, OpenAI/Anthropic keys, SendGrid keys, Twilio SIDs, JWTs, private key
blocks, database URLs with an inline password, and high-entropy
`password = "..."` assignments.

```bash
python secretscan.py --list-rules
```

## False positives

A scanner the team mutes is worse than no scanner, so generic matches are
filtered three ways before they are reported:

- known placeholder shapes (`<YOUR_KEY>`, `${ENV_VAR}`, `xxxxxx`, `%(key)s`)
- placeholder words (`changeme`, `your-api-key`, `example`, `dummy`, `insert-...`)
- Shannon entropy below 2.6 bits/char, and values with three or fewer distinct
  characters

Minified bundles, binaries, `node_modules`, `.git` and build output are skipped.
Anything left:

```python
API_KEY = "Gk8vQ2pLzR7nXw4T"  # secretscan: ignore
```

```bash
python secretscan.py . --ignore tests/fixtures/ --ignore docs/
```

**Findings are redacted.** Only the first four and last two characters are
printed. A scanner that echoes the full key into a CI log has just leaked it
again.

## As a library

```python
from secretscan import scan

for finding in scan(Path(".")):
    print(finding.rule, finding.path, finding.line_no)
```

## Tests

```bash
pytest
```

## License

MIT
