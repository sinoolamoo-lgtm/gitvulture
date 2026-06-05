"""Global settings and constants."""
from __future__ import annotations

# Common files inside .git/ that we always try to fetch first.
KNOWN_GIT_FILES = [
    "HEAD",
    "ORIG_HEAD",
    "FETCH_HEAD",
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "BISECT_HEAD",
    "config",
    "description",
    "info/exclude",
    "info/refs",
    "info/packs",
    "objects/info/alternates",
    "objects/info/http-alternates",
    "objects/info/packs",
    "packed-refs",
    "index",
    "logs/HEAD",
    "COMMIT_EDITMSG",
    "hooks/applypatch-msg.sample",
    "hooks/pre-commit.sample",
]

# Refs paths we walk recursively (when directory listing is disabled).
REF_SCAN_PATHS = [
    "refs/heads/",
    "refs/remotes/",
    "refs/tags/",
    "refs/stash",
    "refs/pull/",
    "refs/merge-requests/",
]

# Common branch / remote names to brute force when listings are disabled.
COMMON_BRANCHES = [
    "master",
    "main",
    "develop",
    "development",
    "dev",
    "staging",
    "stage",
    "preprod",
    "release",
    "test",
    "testing",
    "qa",
    "uat",
    "prod",
    "production",
    "feature",
    "fix",
    "hotfix",
    "trunk",
]

COMMON_REMOTES = ["origin", "upstream", "github", "gitlab", "bitbucket"]
COMMON_TAGS = ["v1.0", "v1.0.0", "v0.1", "v0.1.0", "release", "latest", "stable"]

# Extra dotfiles worth probing alongside .git/.
SENSITIVE_EXTRAS = [
    ".gitignore",
    ".gitattributes",
    ".gitconfig",
    ".gitmodules",
    ".gitkeep",
    ".svn/entries",
    ".svn/wc.db",
    ".hg/store",
    ".bzr/branch-format",
    ".DS_Store",
    ".env",
    ".env.local",
    ".env.production",
    ".env.dev",
    ".env.example",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "config.php.bak",
    "config.php~",
    "wp-config.php.bak",
    "backup.zip",
    "backup.tar.gz",
    "database.sql",
    "dump.sql",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "Dockerfile",
    "docker-compose.yml",
]

# User-agent rotation – plain HTTP libraries are blocked by some WAFs.
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "git/2.42.0",
    "curl/8.4.0",
]

DEFAULT_HEADERS = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

# A sha1 hex string (40 chars) – used to detect refs, objects, etc.
SHA1_RE = r"\b[0-9a-f]{40}\b"

# Heuristic: bytes that indicate a soft-404 page from common WAFs/CDNs.
SOFT_404_MARKERS = [
    b"<title>404",
    b"Not Found",
    b"NoSuchKey",
    b"AccessDenied",
    b"<title>Access Denied",
    b"Cloudflare",
    b"cf-error-details",
]

OBJECT_DIR_PREFIXES = [f"{i:02x}" for i in range(256)]

# Files that should *never* be downloaded even if linked – e.g., wormable hooks.
SKIP_PATHS = {"hooks/post-commit", "hooks/post-receive"}
