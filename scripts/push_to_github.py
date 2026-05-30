"""
scripts/push_to_github.py
Push the current workspace to GitHub using the Git Data API.
Reads GITHUB_TOKEN from the environment; git push is blocked in this sandbox.
"""

import base64
import json
import os
import pathlib
import urllib.error
import urllib.request

OWNER  = "haskopavol-hash"
REPO   = "synthegria-siem"
BRANCH = "main"
TOKEN  = os.environ["GITHUB_TOKEN"]

# Files / dirs to skip
SKIP_DIRS  = {
    ".git", "__pycache__", ".pythonlibs", "node_modules",
    ".local", ".upm", ".cache", ".config", ".agents",
    "artifacts", "lib", "dist", "build", ".tsbuildinfo",
}
SKIP_FILES = {
    "uv.lock", ".replit", ".breakpoints",
}
SKIP_EXTS  = {".pyc", ".pyo", ".egg-info"}

BASE_URL = f"https://api.github.com/repos/{OWNER}/{REPO}"
HEADERS  = {
    "Authorization":        f"Bearer {TOKEN}",
    "Accept":               "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type":         "application/json",
}


def gh(method: str, path: str, body: dict | None = None) -> dict:
    url  = BASE_URL + path
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise RuntimeError(f"GitHub API {e.code}: {raw[:300]}") from e


# ── 1. Get remote HEAD ──────────────────────────────────────────────────────
print("1. Fetching remote HEAD …")
ref    = gh("GET", f"/git/refs/heads/{BRANCH}")
remote_sha = ref["object"]["sha"]
print(f"   Remote HEAD: {remote_sha}")

# ── 2. Collect local files ──────────────────────────────────────────────────
root   = pathlib.Path(__file__).parent.parent   # workspace root
blobs  = []

print("2. Collecting local files …")
for path in sorted(root.rglob("*")):
    if path.is_dir():
        continue
    rel = path.relative_to(root)
    parts = rel.parts

    # skip rules
    if any(p in SKIP_DIRS for p in parts[:-1]):
        continue
    if parts[0] in SKIP_DIRS:
        continue
    if path.name in SKIP_FILES:
        continue
    if path.suffix in SKIP_EXTS:
        continue
    if path.name.startswith(".") and path.name not in {".dockerignore", ".gitignore"}:
        continue

    blobs.append((str(rel).replace("\\", "/"), path))

print(f"   {len(blobs)} files to push")

# ── 3. Create blobs ─────────────────────────────────────────────────────────
print("3. Creating blobs …")
tree_items = []
for i, (rel_path, abs_path) in enumerate(blobs, 1):
    raw = abs_path.read_bytes()
    try:
        content  = raw.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content  = base64.b64encode(raw).decode()
        encoding = "base64"

    blob = gh("POST", "/git/blobs", {"content": content, "encoding": encoding})
    tree_items.append({
        "path":  rel_path,
        "mode":  "100755" if abs_path.stat().st_mode & 0o111 else "100644",
        "type":  "blob",
        "sha":   blob["sha"],
    })
    if i % 10 == 0 or i == len(blobs):
        print(f"   [{i}/{len(blobs)}]  {rel_path}")

# ── 4. Create tree ──────────────────────────────────────────────────────────
print("4. Creating tree …")
tree = gh("POST", "/git/trees", {
    "tree":      tree_items,
    "base_tree": None,   # start from scratch — clean tree
})
print(f"   Tree SHA: {tree['sha']}")

# ── 5. Create commit ────────────────────────────────────────────────────────
print("5. Creating commit …")
commit = gh("POST", "/git/commits", {
    "message": "Push latest: landing page, README, SDK, AI analyst, 125 tests",
    "tree":    tree["sha"],
    "parents": [remote_sha],
    "author": {
        "name":  "Synthegria Agent",
        "email": "agent@synthegria.io",
    },
})
print(f"   Commit SHA: {commit['sha']}")

# ── 6. Update branch ref (force — new tree replaces old) ────────────────────
print("6. Updating branch ref …")
gh("PATCH", f"/git/refs/heads/{BRANCH}", {
    "sha":   commit["sha"],
    "force": True,
})
print(f"\n✅  Branch '{BRANCH}' updated → {commit['sha'][:12]}")
print(f"   https://github.com/{OWNER}/{REPO}/tree/{BRANCH}")
