import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"


@unittest.skipIf(sys.platform == "win32", "POSIX sh installer tests require Unix")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release_dir = self.root / "release"
        self.release_dir.mkdir()
        self.install_dir = self.root / "bin"

    def build_mock_release(self, version, target, *, corrupt_checksum=False):
        bare = version.lstrip("v")
        archive_root = f"targetwarden-{bare}-{target}"
        archive_name = f"{archive_root}.tar.gz"
        archive_path = self.release_dir / archive_name

        fake_bin = f"#!/bin/sh\nif [ \"${{1:-}}\" = \"--version\" ]; then\n  printf 'targetwarden {bare}\\n'\nfi\n".encode("utf-8")
        with tarfile.open(archive_path, "w:gz") as archive:
            for rel, payload, mode in [
                (f"{archive_root}/targetwarden", fake_bin, 0o755),
                (f"{archive_root}/README.md", b"# targetwarden\n", 0o644),
                (f"{archive_root}/LICENSE", b"MIT\n", 0o644),
            ]:
                member = tarfile.TarInfo(rel)
                member.size = len(payload)
                member.mode = mode
                archive.addfile(member, io.BytesIO(payload))

        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        if corrupt_checksum:
            digest = "0" * 64
        (self.release_dir / "SHA256SUMS").write_text(
            f"{digest}  {archive_name}\n", encoding="utf-8"
        )

    def run_installer(self, env_overrides):
        env = os.environ.copy()
        env.update(
            {
                "TARGETWARDEN_INSTALL_DIR": str(self.install_dir),
                "TARGETWARDEN_DOWNLOAD_BASE": self.release_dir.as_uri(),
            }
        )
        env.update(env_overrides)
        return subprocess.run(
            ["sh", str(INSTALLER)],
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_installs_verified_macos_arm64_and_x86_64_archives(self):
        for arch, target in [("arm64", "aarch64-apple-darwin"), ("x86_64", "x86_64-apple-darwin")]:
            with self.subTest(arch=arch):
                self.build_mock_release("v0.1.0", target)
                result = self.run_installer(
                    {
                        "TARGETWARDEN_VERSION": "v0.1.0",
                        "TARGETWARDEN_OS": "Darwin",
                        "TARGETWARDEN_ARCH": arch,
                    }
                )
                self.assertEqual(result.returncode, 0, msg=result.stderr)
                installed = self.install_dir / "targetwarden"
                self.assertTrue(installed.is_file())
                self.assertTrue(os.access(installed, os.X_OK))
                self.assertIn("Installed targetwarden 0.1.0", result.stdout)

    def test_rejects_checksum_mismatch_without_clobbering_existing_binary(self):
        self.install_dir.mkdir(parents=True, exist_ok=True)
        existing = self.install_dir / "targetwarden"
        existing.write_bytes(b"existing-binary")
        self.build_mock_release("v0.1.0", "aarch64-apple-darwin", corrupt_checksum=True)

        result = self.run_installer(
            {
                "TARGETWARDEN_VERSION": "v0.1.0",
                "TARGETWARDEN_OS": "Darwin",
                "TARGETWARDEN_ARCH": "arm64",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(existing.read_bytes(), b"existing-binary")

    def test_rejects_non_macos_and_invalid_version(self):
        linux = self.run_installer(
            {
                "TARGETWARDEN_VERSION": "v0.1.0",
                "TARGETWARDEN_OS": "Linux",
                "TARGETWARDEN_ARCH": "x86_64",
            }
        )
        self.assertNotEqual(linux.returncode, 0)
        self.assertIn("macOS only", linux.stderr)

        bad_ver = self.run_installer(
            {
                "TARGETWARDEN_VERSION": "v0.1.0/../evil",
                "TARGETWARDEN_OS": "Darwin",
                "TARGETWARDEN_ARCH": "arm64",
            }
        )
        self.assertNotEqual(bad_ver.returncode, 0)
        self.assertIn("invalid", bad_ver.stderr)


if __name__ == "__main__":
    unittest.main()
