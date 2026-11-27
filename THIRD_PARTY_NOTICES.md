# Third-party notices

The vendored Rust CLI skills in `.agents/skills/` originate from
[Dankosik/rust-cli-skills](https://github.com/Dankosik/rust-cli-skills),
copyright (c) 2026 Dankosik, under the MIT license reproduced in
[LICENSE](LICENSE). [skills-source.json](.agents/skills-source.json) is the
single source for their current immutable upstream revision and content hashes.
Identical per-skill MIT notices are retained by that root license; a notice with
different content must be preserved explicitly before adopting it.

Eight additional Rust coding, structural-quality, review, security,
dependency, configuration, reliability, and verification skills (along with
seven pure-Rust reference files under `.agents/skills/rust-coder/references/`
and `.agents/skills/rust-structural-quality/references/`) are adapted from
[Dankosik/rust-service-template-rest](https://github.com/Dankosik/rust-service-template-rest),
commit `52835313ee80fef11793edd942b9e66c3b391f4c`, copyright (c) 2026 Dankosik,
under the MIT license reproduced in [LICENSE](LICENSE). Their current hashes
are tracked in [skills-service-template.json](.agents/skills-service-template.json).

The template adapts the runnable starting point, initialization, contract,
validation, and agent-workflow ideas of
[Dankosik/go-service-template-rest](https://github.com/Dankosik/go-service-template-rest),
commit `ef6a3bc9983431de065a421e6a3fced36ef886ba`, also licensed under MIT.
The Rust runtime and maintenance tools are newly written for CLI behavior.

Cargo dependencies retain their own licenses. `Cargo.lock` identifies the
resolved packages; `deny.toml` defines the project's dependency license and
advisory policy. This notice does not replace the licenses of dependencies.
