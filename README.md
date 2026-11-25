# SecondLook

A link checker. Paste a web address and it is checked against malware and phishing lists, exact malicious addresses, VirusTotal, and suspicious address patterns.

## Run it

1. Install Node 20.6 or newer.
2. Copy `.env.example` to `.env` and paste your VirusTotal API key after `VIRUSTOTAL_API_KEY=`. Without a key the site still runs, using only the lists and pattern checks.
3. Run `npm install`, then `npm start`.
4. Open http://localhost:3000.

## Change the lists

Edit `FILTER_LISTS` at the top of `server.js`. Mark a list `kind: "threat"` if a hit means the link is malicious, or `kind: "other"` for ad, tracker and privacy lists. Add personal rules to `my-filters.txt`, one per line.

## Before putting it online

The free VirusTotal API key is for non-commercial use only. Host it behind HTTPS, and check each list's license.
