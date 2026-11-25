# SecondLook

Check a link before you click it.

SecondLook is a small web app. You paste a web address, and it tells you whether the link is known to be dangerous, looks suspicious, or has no known threats. It combines three checks into one verdict and shows each check on its own row, so you can see why it decided what it did.

It never opens the link itself. It only reads the address, so pasting a malicious link into it is safe.

## What it checks

1. **Filter lists.** The server downloads malware and phishing lists, keeps them in memory, and matches the link's domain, its parent domains, and exact malicious addresses. Lists are refreshed every 6 hours.
2. **VirusTotal.** If an API key is set and no threat list has already flagged the link, it asks VirusTotal. It first looks for an existing report and only submits the link for scanning if there isn't one.
3. **Address patterns.** It flags raw IP addresses, lookalike (punycode) domains, a username or password before the domain, long chains of subdomains, endings often used in scams (such as `.zip`, `.top`, `.xyz`), plain `http`, and very long addresses.

The page never says a link is "safe". The best result is "No known threats", because a link missing from every list can still be dangerous.

## How the verdict is decided

| Verdict | When |
| --- | --- |
| Dangerous | The link matches a threat list, or 3 or more VirusTotal engines say malicious |
| Suspicious | 1 or 2 engines flag it, any engine says suspicious, or 2 or more address-pattern signals are found |
| No known threats | None of the above |

Lists marked as `other` (ads, trackers, your own rules) add a note to the page but never change the verdict.

## Quick start

You need [Node.js](https://nodejs.org) 20.6 or newer.

```powershell
copy .env.example .env
notepad .env
npm install
npm start
```

Put your VirusTotal API key after `VIRUSTOTAL_API_KEY=` in `.env`, then open http://localhost:3000.

On macOS or Linux, use `cp .env.example .env` instead of `copy`.

Without a key, the app still runs and uses only the filter lists and address patterns.

## Configuration

| Setting | Where | What it does |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | `.env` | Turns on the VirusTotal check |
| `PORT` | `.env` | Port to listen on (default 3000) |
| `FILTER_LISTS` | top of `server.js` | Which lists to download |
| `LIST_REFRESH_HOURS` | top of `server.js` | How often the lists are downloaded again (default 6) |
| `CACHE_HOURS` | top of `server.js` | How long a finished result is remembered (default 24) |

### Choosing lists

Each entry in `FILTER_LISTS` has a name, a `url` or a local `file`, and a `kind`:

- `kind: "threat"` for malware and phishing lists. A match means the link is dangerous.
- `kind: "other"` for ad, tracker and privacy lists. A match only adds a note.

Lists in hosts-file format, plain domain lists, and Adblock-style lists are all read. Domain rules (`||example.com^`), exact-address rules (`||example.com/path/file.exe^`) and wildcard rules for whole endings (`||*.example^`) are used. Cosmetic rules, exception rules and rules with other wildcards are skipped.

### Your own rules

Add rules to `my-filters.txt`, one per line, in the same format. They are marked as `other`, so they appear as a note and never change the verdict.

## Trying it out

While `test-threat.txt` is listed in `FILTER_LISTS`, these made-up addresses always match as dangerous:

- `http://malicious-test.invalid/`
- `http://exact-test.invalid/bad/file.exe`

`http://exact-test.invalid/other` does not match, which shows that exact-address rules only match the exact path.

To test the address-pattern checks, try `http://google.com@login-check.xyz/verify`.

## API

`POST /api/check` with a JSON body `{ "url": "https://example.com" }` returns the verdict, the list matches, the VirusTotal result and the address-pattern signals.

`GET /api/status` returns how many domains and exact addresses are loaded, and whether a VirusTotal key is set.

Each visitor is limited to 10 checks per minute.

## Project layout

```
server.js          the server: lists, VirusTotal, patterns, API
public/index.html  the page
my-filters.txt     your own rules
test-threat.txt    fake threat entries for testing
.env.example       template for your settings
```

## Deploying

SecondLook is a normal Node server that keeps its lists in memory, so it needs a host that keeps it running, such as Render, Railway, Fly.io or your own server. It is not a good fit for serverless hosts like Vercel.

On Render, create a Web Service from this repository with the build command `npm install` and the start command `node server.js`. Add `VIRUSTOTAL_API_KEY` under Environment instead of using a `.env` file. Free instances go to sleep when idle, which empties the cache and re-downloads the lists on the next visit.

Before putting it online:

- Remove the "Test threat list" line from `FILTER_LISTS` in `server.js`.
- Never commit `.env`. The included `.gitignore` already excludes it.
- The free VirusTotal key allows 4 requests a minute and is for non-commercial use only.
- Check the license of each list you use.

## Limits

- Lists match whole domains and exact addresses. A malicious page on an otherwise clean site is only caught if a list contains that exact address or VirusTotal knows about it.
- Shortened links such as bit.ly are checked as written, not expanded.
- Results are only as fresh as the last list download.
- Addresses sent to VirusTotal can become visible to its community, so do not check links that contain private tokens, such as password reset links.
- The cache and rate limits live in memory and reset when the server restarts.
