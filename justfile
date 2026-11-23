# List the recipes.
default:
    @just --list

# Build pwk and link it into ~/.local (bin, man pages, completions).
install:
    nix run .#install

# Remove the links and the GC root; configuration and sessions are kept.
uninstall:
    nix run .#uninstall

# Build pwk with man pages and completions (into ./result).
build:
    nix build

# Build the static release packages for installing without Nix (into ./result).
release:
    nix build .#release

# Format Rust, Nix and Markdown.
fmt:
    cargo fmt --all
    nix fmt -- flake.nix nix/*.nix
    prettier --write '**/*.md'

# Lint Rust and Markdown.
lint:
    cargo clippy --workspace --all-targets -- --deny warnings
    prettier --check '**/*.md'
    markdownlint-cli2

# Everything CI runs: build, tests, clippy (Linux + macOS), rustfmt, Markdown, changelog, local links, audit, release package.
check:
    nix flake check -L

# Unit and integration tests.
test:
    cargo nextest run --workspace

# Check the links in every Markdown file with lychee (pass --offline for local links only).
links *args:
    nix run .#links -- {{args}}
