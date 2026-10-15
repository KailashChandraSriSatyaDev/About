# Sensitive Data Pattern Scanner

A small Python portfolio lab for demonstrating basic sensitive-data detection rules against authorized text files. It uses only Python's standard library and includes unit tests.

## What it checks

- Email-address patterns.
- AWS access-key ID format (AKIA followed by 16 uppercase alphanumeric characters).
- Common credential assignments such as API_KEY=..., ACCESS_TOKEN=..., CLIENT_SECRET=..., SECRET_KEY=..., and PASSWORD=....
- Private-key PEM header markers.

The scanner reports the file, line number, rule ID, severity, and a short description. It intentionally does **not** print the matched secret value.

## Run it

From this directory, scan a folder of text files:

    python scanner.py ./fixtures

Produce JSON output:

    python scanner.py ./fixtures --json

Run tests:

    python -m unittest discover -s tests -v

The fixture uses synthetic strings only. A scan that detects the fixture patterns returns exit code 1, which is useful for demonstrating how a detection tool can signal findings.

## Safety and Limitations

- Only scan files and systems you own or are authorized to assess.
- Run this lab on synthetic test data first. Do not commit real credentials, customer data, tokens, or private keys to a public repository.
- This is a simple regex-based educational tool. It can produce false positives and false negatives, and it does not replace a dedicated secrets scanner, DLP product, or security review.
- No network requests are made and no file contents are uploaded.
- The scanner skips common dependency/cache folders and ignores files above 2 MiB.

## What this lab demonstrates

Rule design, basic file processing, privacy-conscious findings output, JSON reporting, and unit testing. Before presenting it in an interview, run the tests, inspect the code, and be ready to explain the rule choices and limitations.
