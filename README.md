# PhishGuard 🎣🛡️

A tiny, dependency-free phishing link detector. Give it a URL, get a risk score and the reasons behind it.

> Learning project. It uses simple heuristics, so expect false positives and misses. Don't rely on it as your only protection.

## Features
- Risk score (0-100) with a verdict: `LOOKS OK`, `SUSPICIOUS`, `DANGEROUS`
- Checks for: no HTTPS, raw IP hosts, `@` tricks, punycode, long URLs, excess subdomains, suspicious TLDs, URL shorteners, phishing keywords, brand impersonation / typosquatting
- Never visits the link; it only analyzes the text of the URL
- Batch mode and JSON output

## Web version
Open `index.html` in a browser, or host it free with GitHub Pages (Settings → Pages → deploy from `main`). Animated risk gauge, sample links, scan history, and dark mode. Runs fully client-side.

## CLI usage
```bash
python phishguard.py https://paypal-secure-login.xyz/verify
python phishguard.py -f urls.txt --json
```
Requires Python 3.8+. No installs needed.

## Tests
```bash
python -m unittest discover tests
```

## Roadmap
- Check domain age via WHOIS
- Integrate a public blocklist (e.g. PhishTank)
- Browser extension
- ML classifier trained on a labeled URL dataset

## Contributing
PRs welcome: add heuristics, brands, or tests.

## License
MIT
