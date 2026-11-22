"""Check the four-platform asset set before exposing it to desktop updaters."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True).strip()


def publish(directory, version, sha):
    tag = f"v{version}"
    prefix = "Moonlight-VPlus-"
    names = {f"{prefix}{version}-arm64.dmg", f"{prefix}SteamLink-{version}.zip"}
    for arch in ("x86_64", "aarch64"):
        image = f"{prefix}{version}-{arch}.AppImage"
        names.update([image, image + ".zsync"])
    for brand in (prefix, "Moonlight"):
        names.add(f"{brand}Setup-{version}.exe")
        for arch in ("arm64", "x64"):
            names.add(f"{brand}Portable-{arch}-{version}.zip")

    assets = {path.name: path for path in directory.iterdir() if path.is_file() and path.stat().st_size}
    if set(assets) != names:
        raise ValueError(f"Incorrect release assets: missing={names-assets.keys()}, extra={assets.keys()-names}")
    options = ("--json", "isDraft,targetCommitish,assets")
    repo = os.environ["GITHUB_REPOSITORY"]
    existing = json.loads(gh("release", "list", "--limit", "100", "--json", "tagName,isDraft"))
    for item in existing:
        if not item["isDraft"] and item["tagName"].startswith("v6.6."):
            if int(item["tagName"].removeprefix("v6.6.")) > int(version.split(".")[-1]):
                print("A newer build is already published.")
                return
    if not any(item["tagName"] == tag for item in existing):
        gh("release", "create", tag, "--draft", "--target", sha, "--title", f"Moonlight V+ {version}",
           "--notes", f"Desktop build from [{sha[:12]}](https://github.com/{repo}/commit/{sha}).")
    release = json.loads(gh("release", "view", tag, *options))
    if release["targetCommitish"] != sha:
        raise ValueError("Release target does not match the build")
    if release["isDraft"]:
        gh("release", "upload", tag, "--clobber", *map(str, assets.values()))
        release = json.loads(gh("release", "view", tag, *options))
    digests = {asset["name"]: asset["digest"] for asset in release["assets"]}
    for name, path in assets.items():
        with path.open("rb") as stream:
            expected = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        if digests.get(name) != expected:
            raise ValueError(f"Release asset verification failed: {name}")
    if release["isDraft"]:
        gh("release", "edit", tag, "--draft=false", "--latest")


if __name__ == "__main__":
    publish(Path(sys.argv[1]), os.environ["CI_VERSION"], os.environ["GITHUB_SHA"])
