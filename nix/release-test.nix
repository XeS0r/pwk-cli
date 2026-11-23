# Uses a release package the way someone without Nix would: unpack, check that pwk is
# static and runs with an empty environment, install.sh, update, uninstall. Nothing
# here talks to a server. Run with `nix build .#checks.<system>.release`.
{
  pkgs,
  tarball,
  version,
}:
pkgs.runCommand "pwk-release-test"
  {
    nativeBuildInputs = [ pkgs.binutils ];
  }
  ''
    set -euo pipefail
    export HOME=$TMPDIR/home NO_COLOR=1
    mkdir -p $HOME
    expect() { case "$2" in *"$1"*) ;; *) echo "expected '$1' in: $2" >&2; exit 1 ;; esac; }

    tar xzf ${tarball}/*.tar.gz -C $TMPDIR
    pkg=$(echo $TMPDIR/pwk-*/)
    for f in $pkg/install.sh $pkg/LICENSE $pkg/THIRD-PARTY-NOTICES.md $pkg/README.md \
      $pkg/share/bash-completion/completions/pwk.bash \
      $pkg/share/zsh/site-functions/_pwk \
      $pkg/share/fish/vendor_completions.d/pwk.fish; do
      test -f "$f"
    done
    ls $pkg/share/man/man1/pwk.1.gz

    echo "== static pwk"
    if readelf -l $pkg/bin/pwk | grep -q "program interpreter"; then
      echo "bin/pwk is dynamic" >&2
      exit 1
    fi
    expect "pwk ${version}" "$(env -i $pkg/bin/pwk --version)"
    # Exercises the crypto (random generator) without a server or a session.
    password=$(env -i HOME=$HOME $pkg/bin/pwk generate --length 12)
    echo "generated: ''${#password} characters"
    test -n "$password"

    echo "== install.sh"
    res=$(PATH=/usr/bin:/bin:$PATH sh $pkg/install.sh --prefix $TMPDIR/p)
    echo "$res"
    expect "✓ installed pwk" "$res"
    expect "Next (see README.md):" "$res"
    test -x $TMPDIR/p/bin/pwk
    test -f $TMPDIR/p/share/man/man1/pwk.1.gz

    echo "== update removes what the new version no longer ships"
    old=share/man/man1/pwk-retired.1.gz
    touch $TMPDIR/p/$old
    echo $old >> $TMPDIR/p/share/pwk/installed-files
    res=$(sh $pkg/install.sh --prefix $TMPDIR/p)
    expect "✓ updated pwk" "$res"
    test ! -e $TMPDIR/p/$old
    if grep -q retired $TMPDIR/p/share/pwk/installed-files; then echo "manifest still lists it" >&2; exit 1; fi

    echo "== uninstall"
    res=$(sh $pkg/install.sh --prefix $TMPDIR/p --uninstall)
    expect "✓ removed pwk" "$res"
    test ! -e $TMPDIR/p/bin/pwk
    test ! -e $TMPDIR/p/share/pwk
    test -z "$(find $TMPDIR/p -type f)"

    touch $out
  ''
