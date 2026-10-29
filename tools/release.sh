#!/bin/sh

# Cut a Kismet release; called by 'make release-NAME' and 'make subrelease-NAME'.
#
#   release NAME       refresh the generated databases on master, test build, then branch
#                      kismet-YYYY-MM, version, tag kismet-NAME and write ../kismet-NAME.tar.xz
#   subrelease NAME    the same on the existing kismet-YYYY-MM branch, without the databases
#
# NAME is YYYY-MM-Rn, optionally with a letter (2022-01-R3a).  Nothing is pushed; the push
# commands are printed at the end.  RELEASE_CONFIGURE holds configure options for the test
# build, and RELEASE_SKIP_BUILD=1 skips it.

set -e

MAKE=${MAKE:-make}

die() {
    echo "release: $*" >&2
    exit 1
}

usage() {
    die "usage: $0 release|subrelease YYYY-MM-Rn"
}

has_ref() {
    git rev-parse -q --verify "$1" >/dev/null
}

test $# -eq 2 || usage
mode=$1
name=$2

case "$mode" in
    release|subrelease) ;;
    *) usage ;;
esac

case "$name" in
    *[!0-9A-Za-z-]*) die "'$name' is not a release name like 2026-10-R1" ;;
esac

echo "$name" | grep -Eq '^[0-9]{4}-(0[1-9]|1[0-2])-R[0-9]+[a-z]?$' ||
    die "'$name' is not a release name like 2026-10-R1"

branch=kismet-$(echo "$name" | cut -d- -f1,2)
tag=kismet-$name
tarball=../kismet-$name.tar.xz

test -z "$(git status --porcelain --untracked-files=no)" ||
    die "the tree has uncommitted changes; commit or remove them first"

if has_ref "refs/tags/$tag"; then
    die "tag $tag already exists"
fi

if test -e "$tarball" || test -e "../kismet-$name.tar"; then
    die "$tarball already exists"
fi

git fetch origin

# Commit a regenerated database only when its contents changed; gzip stores a timestamp,
# so compare the uncompressed data
commit_db() {
    file=$1
    what=$2

    if ! git diff --quiet -- "$file"; then
        old=$(mktemp "${TMPDIR:-/tmp}/kismet-db.XXXXXX")
        new=$(mktemp "${TMPDIR:-/tmp}/kismet-db.XXXXXX")
        git show "HEAD:$file" | gunzip -c > "$old"
        gunzip -c "$file" > "$new"
        if cmp -s "$old" "$new"; then
            git checkout -- "$file"
        fi
        rm -f "$old" "$new"
    fi

    if git diff --quiet -- "$file"; then
        echo "$file is unchanged"
    else
        git commit "$file" -m "$what update for $name" -m "Update $what for release $name"
    fi
}

# Build what will be shipped: this commit plus its version file
test_build() {
    if test "$RELEASE_SKIP_BUILD" = "1"; then
        echo "skipping the test build"
        return 0
    fi

    dir=$(mktemp -d "${TMPDIR:-/tmp}/kismet-release.XXXXXX")
    echo "test building $name in $dir"
    git archive --format tar --prefix "kismet-$name/" -o "$dir/src.tar" HEAD
    (cd "$dir" && tar xf src.tar)

    jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
    if ! (cd "$dir/kismet-$name" &&
            ./tools/mkversion.sh "$BUILD_DATE" "$name" "$rev" &&
            ./configure $RELEASE_CONFIGURE > ../configure.log 2>&1 &&
            $MAKE -j"$jobs" > ../build.log 2>&1); then
        die "the test build failed, see $dir/configure.log and $dir/build.log; nothing was branched or tagged"
    fi

    rm -rf "$dir"
}

if test "$mode" = "release"; then
    test "$(git symbolic-ref -q --short HEAD)" = "master" ||
        die "releases are cut from master"

    git merge-base --is-ancestor origin/master HEAD ||
        die "master is behind origin/master; pull first"

    if has_ref "refs/heads/$branch" || has_ref "refs/remotes/origin/$branch"; then
        die "branch $branch already exists; use 'make subrelease-$name' to release from it"
    fi

    $MAKE manuf
    commit_db conf/kismet_manuf.txt.gz "Manuf"

    $MAKE icao
    commit_db conf/kismet_adsb_icao.txt.gz "ICAO"

    $MAKE btdb
    commit_db conf/kismet_bluetooth_manuf.txt.gz "Bluetooth manuf"
    commit_db conf/kismet_bluetooth_ids.txt.gz "Bluetooth IDs"

    push="git push origin master $branch $tag"
else
    if has_ref "refs/heads/$branch"; then
        git checkout "$branch"
        if has_ref "refs/remotes/origin/$branch"; then
            git merge --ff-only "origin/$branch" ||
                die "$branch has diverged from origin/$branch; reconcile it first"
        fi
    elif has_ref "refs/remotes/origin/$branch"; then
        git checkout -b "$branch" "origin/$branch"
    else
        die "branch $branch does not exist; use 'make release-$name' to start it"
    fi

    push="git push origin $branch $tag"
fi

# The version records the commit the release is built from: the version commit can't
# hold its own hash, and differs from it only by the version file
rev=$(git rev-parse --short HEAD)

test_build

if test "$mode" = "release"; then
    git checkout -b "$branch"
fi

./tools/mkversion.sh "$BUILD_DATE" "$name" "$rev"
git add -f version.c
git commit version.c -m "Bump versioning for release $name"
git tag "$tag"

git archive --format tar --prefix "kismet-$name/" -o "../kismet-$name.tar" "$tag"
xz "../kismet-$name.tar"

echo
echo "Released $tag in $tarball.  To publish it:"
echo "    $push"
echo "    git checkout master"
