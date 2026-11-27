#!/usr/bin/env python3
"""Check instruction integrity; optionally build a disposable initialized consumer."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def _check_skill_paths(root, files, pattern):
    for relative, expected in files.items():
        path = root / relative
        if not re.fullmatch(pattern, relative):
            raise ValueError("unsafe skill path: " + relative)
        cur = root / ".agents/skills"
        for part in Path(relative).relative_to(".agents/skills").parts:
            cur = cur / part
            if cur.is_symlink():
                raise ValueError("unsafe symlink in skill path: " + relative)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("skill differs from its pinned source: " + relative)
        if path.name == "SKILL.md":
            text = data.decode("utf-8")
            if not text.startswith("---\nname: " + path.parent.name + "\n") or "\ndescription: " not in text.split("---", 2)[1]:
                raise ValueError("invalid skill metadata: " + relative)


def check(root):
    manifest = json.loads((root / ".agents/skills-source.json").read_text(encoding="utf-8"))
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["revision"]):
        raise ValueError("skills source must identify an immutable commit")
    primary_files = manifest["files"]
    _check_skill_paths(root, primary_files, r"\.agents/skills/[a-z0-9-]+/SKILL\.md")

    sup_path = root / ".agents/skills-service-template.json"
    sup_files = {}
    if sup_path.is_file():
        sup_manifest = json.loads(sup_path.read_text(encoding="utf-8"))
        if not re.fullmatch(r"[0-9a-f]{40}", sup_manifest["revision"]):
            raise ValueError("supplemental skills source must identify an immutable commit")
        sup_files = sup_manifest["files"]
        if set(primary_files) & set(sup_files):
            raise ValueError("supplemental skills overlap with primary pinned skills")
        _check_skill_paths(root, sup_files, r"\.agents/skills/[a-z0-9-]+/(SKILL\.md|references/[a-z0-9-]+\.md)")

    all_manifest_skills = {p for p in (set(primary_files) | set(sup_files)) if p.endswith("/SKILL.md")}
    actual_skills = {p.relative_to(root).as_posix() for p in (root / ".agents/skills").glob("*/SKILL.md")}
    if actual_skills != all_manifest_skills or not actual_skills:
        raise ValueError("vendored skill inventory differs from its manifest")
    actual_all_md = {p.relative_to(root).as_posix() for p in (root / ".agents/skills").rglob("*.md")}
    if actual_all_md != (set(primary_files) | set(sup_files)):
        raise ValueError("vendored skill reference inventory differs from its manifest")

    # Repository-local Markdown links should not depend on an author's machine.
    docs = [root / name for name in ["README.md", "AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md"]]
    docs += list((root / "docs").rglob("*.md")) + list((root / "specs").rglob("*.md"))
    docs += [root / rel for rel in sorted(sup_files)]
    for path in docs:
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if "://" in target or target.startswith(("#", "mailto:")):
                continue
            local = target.split("#", 1)[0]
            if local.startswith("/") or not (path.parent / local).exists():
                raise ValueError("broken or nonportable link in " + str(path.relative_to(root)) + ": " + target)
    print("Validated " + str(len(actual_skills)) + " pinned/adapted skills and repository documentation links.")


def consumer(root):
    with tempfile.TemporaryDirectory(prefix="rust-cli-consumer-") as temporary:
        target = Path(temporary) / "consumer"
        shutil.copytree(root, target, ignore=shutil.ignore_patterns(".git", "target", ".codegraph", "__pycache__", "dist", "benchmark-results"))
        spec = importlib.util.spec_from_file_location("template_init", target / "scripts/init.py")
        initializer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(initializer)
        identity = json.loads((target / ".template/identity.json").read_text())
        if identity["initialized"]:
            print("Consumer already initialized; validating a disposable copy of its current identity.")
            name = identity["name"]
        else:
            name = "example-file-tool"
            initializer.initialize(target, name, "https://github.com/example/example-file-tool", "A renamed consumer used to verify template adoption.")
        check(target)
        for command in [
            ["cargo", "test", "--locked", "--all-targets"],
            ["cargo", "test", "--locked", "--doc"],
            ["cargo", "package", "--locked", "--allow-dirty", "--no-verify"],
        ]:
            subprocess.run(command, cwd=target, check=True)
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=target))
        executable = Path(metadata["target_directory"]) / "debug" / (name + (".exe" if sys.platform == "win32" else ""))
        if not identity["initialized"]:
            result = subprocess.run([str(executable), "--format", "json", "stats"], input=b"alpha\nbeta", capture_output=True, check=True, timeout=15)
            if result.stdout != b'{"bytes":10,"lines":1}\n' or result.stderr:
                raise ValueError("initialized command violated its stdin/stdout contract")
        print("Disposable consumer compiled, tested, and packaged successfully.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).absolute().parent.parent
    try:
        check(root)
        if args.consumer:
            consumer(root)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Template check failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
