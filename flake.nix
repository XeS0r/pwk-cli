{
  description = "pwk: command line client for Passwork 7";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # RustSec advisories for `checks.audit`. Pinned by flake.lock, so the check is
    # reproducible; `nix flake update advisory-db` picks up new advisories.
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
      rust-overlay,
      advisory-db,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        inherit (pkgs) lib;
        isLinux = pkgs.stdenv.hostPlatform.isLinux;

        # Turns a target triple into the suffix of cargo's per-target variables.
        envTarget = target: lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] target);
        ccTarget = target: builtins.replaceStrings [ "-" ] [ "_" ] target;

        toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
          # The musl targets are for the release packages; the macOS target is only
          # type-checked (`checks.macos`), never linked.
          targets = [
            "x86_64-unknown-linux-musl"
            "aarch64-unknown-linux-musl"
            "aarch64-apple-darwin"
          ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

        # The workspace manifests and everything below crates/, not only what
        # cleanCargoSource keeps (.rs and .toml): tests may read JSON fixtures or test
        # vectors next to the code.
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./crates
          ];
        };
        version = (lib.importTOML ./Cargo.toml).workspace.package.version;
        commonArgs = {
          inherit src version;
          strictDeps = true;
          pname = "pwk";
          buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # pwk with man pages and completions, which the binary generates itself.
        pwk = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            cargoExtraArgs = "--locked -p pwk";
            doCheck = false; # tests run in checks.tests
            nativeBuildInputs = [ pkgs.installShellFiles ];
            postInstall = ''
              $out/bin/pwk generate-man man
              installManPage man/*
              installShellCompletion --cmd pwk \
                --bash <($out/bin/pwk completions bash) \
                --zsh <($out/bin/pwk completions zsh) \
                --fish <($out/bin/pwk completions fish)
            '';
            meta = {
              description = "Command line client for Passwork 7";
              mainProgram = "pwk";
              license = lib.licenses.mit;
            };
          }
        );

        # Release packages for installing without Nix: pwk statically linked (musl),
        # man pages, completions and install.sh. Built on Linux for Linux machines.
        # The TLS stack (rustls with the ring provider) has C and assembly, so these
        # need the musl cross compilers from nixpkgs; a pure-Rust binary could link
        # with rust-lld alone.
        releaseTargets = lib.optionalAttrs isLinux {
          "x86_64-linux" = {
            target = "x86_64-unknown-linux-musl";
            cc = pkgs.pkgsCross.musl64.stdenv.cc;
          };
          "aarch64-linux" = {
            target = "aarch64-unknown-linux-musl";
            cc = pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc;
          };
        };
        mkStatic =
          platform:
          { target, cc }:
          let
            prefix = cc.targetPrefix;
          in
          craneLib.buildPackage (
            commonArgs
            // {
              pname = "pwk-static-${platform}";
              cargoExtraArgs = "--locked -p pwk";
              CARGO_BUILD_TARGET = target;
              # The cc crate (ring's build script) and the linker take the cross
              # compiler; build scripts themselves still run on the build machine.
              "CC_${ccTarget target}" = "${cc}/bin/${prefix}cc";
              "AR_${ccTarget target}" = "${cc.bintools}/bin/${prefix}ar";
              "CARGO_TARGET_${envTarget target}_LINKER" = "${cc}/bin/${prefix}cc";
              "CARGO_TARGET_${envTarget target}_RUSTFLAGS" = "-C target-feature=+crt-static";
              doCheck = false;
            }
          );
        statics = lib.mapAttrs mkStatic releaseTargets;
        mkRelease =
          platform: static:
          let
            name = "pwk-${version}-${platform}";
          in
          pkgs.runCommand name { } ''
            mkdir -p ${name}/bin ${name}/share
            cp ${static}/bin/pwk ${name}/bin/
            # Man pages and completions are text; the native build generated them.
            cp -r ${pwk}/share/man ${pwk}/share/bash-completion ${pwk}/share/fish \
              ${pwk}/share/zsh ${name}/share/
            install -m 755 ${./packaging/install.sh} ${name}/install.sh
            cp ${./LICENSE} ${name}/LICENSE
            cp ${./THIRD-PARTY-NOTICES.md} ${name}/THIRD-PARTY-NOTICES.md
            cp ${./README.md} ${name}/README.md
            chmod -R u+w,go-w ${name}
            mkdir -p $out
            tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1 -czf $out/${name}.tar.gz ${name}
          '';
        releases = lib.mapAttrs mkRelease statics;
        release = pkgs.runCommand "pwk-${version}-release" { } ''
          mkdir -p $out
          ${lib.concatMapStrings (r: "cp ${r}/*.tar.gz $out/\n") (builtins.attrValues releases)}
          cd $out && sha256sum *.tar.gz > SHA256SUMS
        '';

        # `nix run .#install` / `.#uninstall`: links pwk into ~/.local via a GC root.
        mkInstaller =
          action:
          pkgs.writeShellApplication {
            name = "pwk-${action}";
            text = ''
              action=${action}
              package=${pwk}
            ''
            + builtins.readFile ./nix/install.sh;
          };

        # Link check of the Markdown files with lychee.toml, from the repository root:
        #   nix run .#links                 everything, with network
        #   nix run .#links -- --offline    only local files and anchors (checks.links)
        # Further arguments go to lychee. Links to this repository's main branch are
        # checked against the working tree, so they may point to what a change adds.
        links = pkgs.writeShellApplication {
          name = "pwk-links";
          runtimeInputs = [ pkgs.lychee ];
          text = ''
            if [ ! -f lychee.toml ]; then
              echo "run this from the repository root (no lychee.toml here)" >&2
              exit 2
            fi
            exec lychee --config lychee.toml \
              --remap "^https://github\.com/XeS0r/pwk-cli/blob/main/(.*)\$ file://$PWD/\$1" \
              "$@" '**/*.md'
          '';
        };
      in
      {
        packages = {
          default = pwk;
          inherit pwk;
        }
        // lib.optionalAttrs isLinux { inherit release; }
        // lib.mapAttrs' (platform: drv: lib.nameValuePair "static-${platform}" drv) statics;

        apps = {
          default = flake-utils.lib.mkApp { drv = pwk; };
          install = flake-utils.lib.mkApp { drv = mkInstaller "install"; };
          uninstall = flake-utils.lib.mkApp { drv = mkInstaller "uninstall"; };
          links = flake-utils.lib.mkApp { drv = links; };
        };

        checks = {
          build = pwk;
          clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--workspace --all-targets -- --deny warnings";
            }
          );
          fmt = craneLib.cargoFmt commonArgs;
          tests = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoNextestExtraArgs = "--workspace";
              # The API tests build the HTTP client, which loads the system CAs (the
              # servers they talk to are local mocks).
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            }
          );
          # Known vulnerabilities in Cargo.lock. RUSTSEC-2023-0071 (Marvin attack on
          # `rsa`) is accepted: it needs a server that decrypts attacker-chosen
          # ciphertexts, pwk only decrypts its own data (SECURITY.md).
          audit = craneLib.cargoAudit {
            inherit src advisory-db version;
            pname = "pwk";
            # --no-yanked: that check needs the crates.io index, and the build has no
            # network.
            cargoAuditExtraArgs = "--no-yanked --ignore RUSTSEC-2023-0071";
          };
        }
        # macOS code paths are cfg'd out on Linux; type-check and lint them for
        # aarch64-apple-darwin without a Mac. pwk-api and pwk need ring (TLS), whose C
        # and assembly cannot be compiled for macOS without Apple's SDK, so only the
        # pure-Rust pwk-crypto is checked.
        // lib.optionalAttrs isLinux {
          macos = craneLib.mkCargoDerivation (
            commonArgs
            // {
              pname = "pwk-macos-check";
              cargoArtifacts = null;
              doInstallCargoArtifacts = false;
              buildPhaseCargoCommand = ''
                cargo clippy --locked --target aarch64-apple-darwin --all-targets \
                  -p pwk-crypto -- --deny warnings
              '';
              installPhaseCommand = "touch $out";
            }
          );
        }
        // lib.optionalAttrs isLinux {
          markdown =
            pkgs.runCommand "pwk-markdown"
              {
                src = lib.fileset.toSource {
                  root = ./.;
                  fileset = lib.fileset.unions [
                    (lib.fileset.fileFilter (file: file.hasExt "md") ./.)
                    ./.prettierrc.yaml
                    ./.markdownlint-cli2.yaml
                  ];
                };
                nativeBuildInputs = [
                  pkgs.prettier
                  pkgs.markdownlint-cli2
                ];
              }
              ''
                cd $src
                prettier --check '**/*.md'
                markdownlint-cli2
                touch $out
              '';
          # The release workflow takes its notes from CHANGELOG.md; a version
          # bump without a changelog section fails here, not at release time.
          # release-notes-test.sh also tests the script on a fixture and rejects
          # relative links in the notes (dead on the release page).
          changelog =
            pkgs.runCommand "pwk-changelog"
              {
                src = lib.fileset.toSource {
                  root = ./.;
                  fileset = lib.fileset.unions [
                    ./CHANGELOG.md
                    ./packaging/release-notes.sh
                    ./packaging/release-notes-test.sh
                  ];
                };
              }
              ''
                cd $src
                sh packaging/release-notes.sh ${version} CHANGELOG.md > /dev/null
                sh packaging/release-notes-test.sh ${version} CHANGELOG.md
                touch $out
              '';
          # Local links and anchors only: `--offline` blocks every network request,
          # so this is deterministic (the links workflow checks the rest).
          links =
            pkgs.runCommand "pwk-links"
              {
                src = lib.fileset.toSource {
                  root = ./.;
                  fileset = lib.fileset.unions [
                    (lib.fileset.fileFilter (file: file.hasExt "md") ./.)
                    ./lychee.toml
                    # Every other file the Markdown links to.
                    ./LICENSE
                    ./crates/api/tests/fixtures/LICENSE.passwork-python
                    ./crates/crypto/tests/fixtures/LICENSE.passwork-python
                  ];
                };
              }
              ''
                cd $src
                # lychee builds its HTTP client even offline, and that wants CAs.
                HOME=$TMPDIR SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt \
                  ${lib.getExe links} --offline
                touch $out
              '';
          release = import ./nix/release-test.nix {
            inherit pkgs version;
            tarball = releases.${system};
          };
        };

        formatter = pkgs.nixfmt;

        devShells.default = craneLib.devShell {
          # Not `tests` (its check inputs) and not `release` (cross compilers): the dev
          # shell needs neither.
          checks = removeAttrs self.checks.${system} [
            "tests"
            "release"
          ];
          packages = [
            pkgs.cargo-audit
            pkgs.cargo-nextest
            pkgs.just
            pkgs.lychee
            pkgs.markdownlint-cli2
            pkgs.nixfmt
            pkgs.prettier
          ];
        };
      }
    );
}
