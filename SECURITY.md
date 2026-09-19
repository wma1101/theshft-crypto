# Security policy

## Reporting a vulnerability

Email support@theshft.app with a description of the issue and, if you have
one, a proof of concept. Please do not open a public GitHub issue for a
vulnerability report.

We will make a best effort to acknowledge your report; there is no fixed
acknowledgement window today, and this section will say so plainly once the
owner commits to one. We do not run a paid bug bounty program.

## Scope

This repository is a mirror of the app's encryption module. Reports about
the cryptography, the vendored native ML-KEM-768 module, or the tests in
this repository are welcome here. Reports about the app itself (which is
closed source) should also go to support@theshft.app; we will coordinate a
fix even though the app code is not in this repository.

## Known limitations

See the "Known limits" section of `README.md`. Those are already known and
tracked; you do not need to report them again, though a report that shows a
concrete exploit for one of them is still useful and welcome.

## Disclosure

We ask for a reasonable window to fix an issue before public disclosure.
There is no fixed embargo period; we will communicate a timeline once we
understand the report.
