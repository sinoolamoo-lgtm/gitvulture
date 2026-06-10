"""Tests for L3 endpoint discovery + D2 origin finder."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from gitvulture.core.endpoint_discovery import (
    discover_endpoints,
    _normalize_route,
)
from gitvulture.core.origin_finder import (
    _simhash,
    _simhash_similarity,
    generate_permutations,
)


# ---------------------------------------------------------------------------
# L3
# ---------------------------------------------------------------------------
class TestEndpointDiscovery:
    def _make_repo(self, files: dict[str, str]) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="gv_l3_"))
        for rel, content in files.items():
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return tmp

    def test_php_laravel(self):
        repo = self._make_repo({
            "routes/web.php": '''<?php
Route::get('/users', 'UserController@index');
Route::post('/users/{id}/avatar', 'UserController@upload');
'''
        })
        eps, by_file = discover_endpoints(repo)
        paths = {(e.method, e.path) for e in eps}
        assert ("GET", "/users") in paths
        assert ("POST", "/users/:id/avatar") in paths

    def test_python_flask(self):
        repo = self._make_repo({
            "app.py": '''
@app.route("/api/login", methods=["POST"])
def login(): pass
@app.route("/health")
def health(): pass
'''
        })
        eps, _ = discover_endpoints(repo)
        paths = {(e.method, e.path) for e in eps}
        assert ("POST", "/api/login") in paths
        assert ("GET", "/health") in paths

    def test_python_fastapi(self):
        repo = self._make_repo({
            "main.py": '''
@app.get("/items/{item_id}")
def read_item(): pass
@router.post("/items")
def create_item(): pass
'''
        })
        eps, _ = discover_endpoints(repo)
        paths = {(e.method, e.path) for e in eps}
        assert ("GET", "/items/:item_id") in paths
        assert ("POST", "/items") in paths

    def test_express(self):
        repo = self._make_repo({
            "server.js": '''
app.get('/api/v1/users', handler);
app.post("/api/v1/users", handler);
router.delete(`/api/v1/users/:id`, handler);
'''
        })
        eps, _ = discover_endpoints(repo)
        paths = {(e.method, e.path) for e in eps}
        assert ("GET", "/api/v1/users") in paths
        assert ("POST", "/api/v1/users") in paths
        assert ("DELETE", "/api/v1/users/:id") in paths

    def test_spring(self):
        repo = self._make_repo({
            "UserController.java": '''
@GetMapping("/users/{id}")
public User get(...) {}
@PostMapping(value = "/users")
public User create(...) {}
'''
        })
        eps, _ = discover_endpoints(repo)
        paths = {(e.method, e.path) for e in eps}
        assert ("GET", "/users/:id") in paths
        assert ("POST", "/users") in paths

    def test_endpoints_by_file_populated(self):
        repo = self._make_repo({
            "src/api.py": "@app.route('/x')\ndef x(): pass",
        })
        eps, by_file = discover_endpoints(repo)
        assert "src/api.py" in by_file
        assert by_file["src/api.py"][0]["path"] == "/x"
        assert "id" in by_file["src/api.py"][0]

    def test_skip_node_modules(self):
        repo = self._make_repo({
            "src/app.py": "@app.route('/real')\ndef real(): pass",
            "node_modules/lib/foo.py": "@app.route('/fake')\ndef fake(): pass",
        })
        eps, _ = discover_endpoints(repo)
        paths = {e.path for e in eps}
        assert "/real" in paths
        assert "/fake" not in paths

    def test_normalize_route(self):
        assert _normalize_route("/users/{id}") == "/users/:id"
        assert _normalize_route("/users/<int:id>") == "/users/:id"
        assert _normalize_route("users//x///y") == "/users/x/y"
        assert _normalize_route("/api/v1/") == "/api/v1"


# ---------------------------------------------------------------------------
# D2 — only the pure-function bits (no network)
# ---------------------------------------------------------------------------
class TestOriginFinderPure:
    def test_simhash_identical(self):
        a = _simhash("the quick brown fox jumps over the lazy dog")
        b = _simhash("the quick brown fox jumps over the lazy dog")
        assert a == b
        assert _simhash_similarity(a, b) == 1.0

    def test_simhash_different(self):
        a = _simhash("totally different content here entirely")
        b = _simhash("nothing alike whatsoever you see")
        assert _simhash_similarity(a, b) < 0.85

    def test_simhash_empty(self):
        assert _simhash("") == 0
        assert _simhash("   ") == 0

    def test_permutations(self):
        out = generate_permutations("api.target.tld")
        assert "origin.target.tld" in out
        assert "dev.api.target.tld" in out
        assert "stage.target.tld" in out
        # original NOT in output
        # (caller drops it explicitly; here it's allowed to appear via prefix)

    def test_permutations_short_host(self):
        out = generate_permutations("x")
        assert out == set()  # too short to permute


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
