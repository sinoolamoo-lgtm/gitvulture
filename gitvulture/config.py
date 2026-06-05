"""Constants and configuration defaults for GitVulture."""

# Files always present in a real .git directory - probed for exposure detection
KNOWN_FILES = [
    "HEAD",
    "config",
    "description",
    "info/exclude",
    "info/refs",
    "info/packs",
    "objects/info/packs",
    "objects/info/alternates",
    "packed-refs",
    "FETCH_HEAD",
    "ORIG_HEAD",
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "index",
    "logs/HEAD",
    "COMMIT_EDITMSG",
]

# Common branches / refs to brute-force when directory listing is disabled.
COMMON_BRANCHES = [
    "main", "master", "develop", "development", "dev", "stage", "staging",
    "production", "prod", "test", "testing", "qa", "release", "hotfix",
    "feature/admin", "feature/login", "feature/auth", "feature/permission-model",
    "feature/permissions", "feature/api", "feature/payment", "feature/users",
    "bugfix/login", "bugfix/auth", "release/1.0", "release/2.0",
    "gh-pages", "trunk",
]

# Files probed inside refs/ when directory listing is disabled
REF_PATHS = [
    "refs/heads/{branch}",
    "refs/remotes/origin/{branch}",
    "refs/tags/{branch}",
    "logs/refs/heads/{branch}",
    "logs/refs/remotes/origin/{branch}",
]

# 403 / 404 bypass path variants (kept short - the most field-tested)
BYPASS_PATH_VARIANTS = [
    "{path}",
    "/{path}",
    "//{path}",
    "/./{path}",
    "/{path}/",
    "/{path}/.",
    "/{path}/..;/",
    "/{path}%20",
    "/{path}%09",
    "/%2e/{path}",
    "/{path}%00",
    "/{path}.json",
]

# Headers that occasionally bypass naive 403 ACLs
BYPASS_HEADERS = [
    {"X-Original-URL": "/{path}"},
    {"X-Rewrite-URL": "/{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Referer": "https://www.google.com/"},
    {"X-Originating-IP": "127.0.0.1"},
]

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "curl/8.4.0",
    "git/2.40.0",
    "Wget/1.21.4",
    "GitVulture/1.0",
]

# WAF signatures (response headers / body fingerprints)
WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare"],
    "aws-waf": ["x-amzn-waf"],
    "akamai": ["akamai", "x-akamai"],
    "imperva": ["x-iinfo"],
    "f5-bigip": ["x-waf-status", "bigipserver"],
    "sucuri": ["x-sucuri"],
    "wordfence": ["wordfence"],
}

# Defaults
DEFAULT_TIMEOUT = 15
DEFAULT_CONCURRENCY = 20
DEFAULT_RATE_LIMIT = 30  # requests / second
DEFAULT_RETRIES = 3

# A valid commit hash is 40 hex chars
SHA1_RE = r"\b[0-9a-f]{40}\b"
