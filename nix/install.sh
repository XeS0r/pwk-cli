# Installs or removes pwk for the current user, without a Nix profile.
#
# Not run directly: flake.nix prepends `action=install|uninstall` and `package=<pwk>`
# and wraps it as the apps `install` / `uninstall` (`nix run .#install`, `just install`).
#
# The package is the store path of pwk. It is kept alive by a GC root at
# $XDG_DATA_HOME/pwk/package; everything else links through that root, so an update
# only swaps the root and existing links stay valid.
#
#   $PREFIX/bin/pwk
#   $PREFIX/share/man/man1/*.1.gz
#   $XDG_DATA_HOME/bash-completion/completions/pwk
#   $XDG_DATA_HOME/fish/vendor_completions.d/pwk.fish
#
# zsh has no per-user directory it reads by default; the completion is in the package
# at share/zsh/site-functions/_pwk for an fpath entry of your own.
#
# PREFIX defaults to ~/.local.

action=${action:?}
package=${package:?}

prefix=${PREFIX:-$HOME/.local}
data_home=${XDG_DATA_HOME:-$HOME/.local/share}
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
state_home=${XDG_STATE_HOME:-$HOME/.local/state}
root=$data_home/pwk/package

bin_dir=$prefix/bin
man_dir=$prefix/share/man/man1
bash_completion=$data_home/bash-completion/completions/pwk
fish_completion=$data_home/fish/vendor_completions.d/pwk.fish

# Links $2 -> $1, but never replaces a file that is not a symlink.
link() {
  if [ -e "$2" ] && [ ! -L "$2" ]; then
    echo "warning: $2 exists and is not a symlink; left untouched" >&2
    return
  fi
  mkdir -p "$(dirname "$2")"
  ln -sfn "$1" "$2"
}

# Removes $1 if it is a symlink into our GC root.
unlink_ours() {
  if [ -L "$1" ]; then
    case "$(readlink "$1")" in
      "$root"/*) rm -f "$1" ;;
    esac
  fi
}

do_install() {
  mkdir -p "$(dirname "$root")"
  # Registers $root as an indirect GC root pointing at the package.
  nix-store --realise "$package" --add-root "$root" >/dev/null

  link "$root/bin/pwk" "$bin_dir/pwk"
  for page in "$root"/share/man/man1/*; do
    link "$root/share/man/man1/$(basename "$page")" "$man_dir/$(basename "$page")"
  done
  link "$root/share/bash-completion/completions/pwk.bash" "$bash_completion"
  link "$root/share/fish/vendor_completions.d/pwk.fish" "$fish_completion"

  echo "installed $(basename "$package") into $prefix"
  echo "next: pwk login, then eval \"\$(pwk unlock)\" (see README.md)"

  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) echo "note: $bin_dir is not in your PATH" >&2 ;;
  esac
}

do_uninstall() {
  unlink_ours "$bin_dir/pwk"
  if [ -d "$man_dir" ]; then
    for page in "$man_dir"/*; do
      unlink_ours "$page"
    done
  fi
  unlink_ours "$bash_completion"
  unlink_ours "$fish_completion"
  rm -f "$root"
  rmdir "$(dirname "$root")" 2>/dev/null || true
  # The session files hold the API tokens; they are the user's to delete (`pwk logout`
  # before uninstalling, or by hand).
  echo "uninstalled from $prefix (kept: configuration in $config_home/pwk,"
  echo "sessions with their tokens in $state_home/pwk)"
}

case "$action" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
