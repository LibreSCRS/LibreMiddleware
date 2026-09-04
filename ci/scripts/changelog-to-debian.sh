#!/usr/bin/env bash
# Generate debian/changelog from CHANGELOG.md and VERSION.
#
# Usage: changelog-to-debian.sh <source-package-name> [output-path]
#
# Why this exists rather than a hand-written file: the RFC-2822 date in a
# Debian changelog carries a day-of-week, and lintian checks it against the
# date. A hand-written entry failed with debian-changelog-has-wrong-day-of-week.
# `date -R` computes the day, so it cannot disagree with itself.
#
# The same generator is copied into every packaged repository. The recipes live
# in separate public repositories and cannot share a submodule, which is the
# same reason the release lockstep script is duplicated.
set -euo pipefail

src="${1:?usage: changelog-to-debian.sh <source-package> [output]}"
out="${2:-debian/changelog}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="$(tr -d '[:space:]' < "$here/VERSION")"
[ -n "$version" ] || { echo "VERSION is empty" >&2; exit 1; }

# One binary revision per upstream version. Bumping it is a packaging-only
# rebuild and has never happened, so it is not derived from anything.
revision="${DEB_REVISION:-1}"

# SOURCE_DATE_EPOCH makes the stamp reproducible when the caller sets it;
# otherwise the entry is stamped now.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  stamp="$(date -R -u -d "@$SOURCE_DATE_EPOCH")"
else
  stamp="$(date -R)"
fi

maintainer="${DEBFULLNAME:-LibreSCRS} <${DEBEMAIL:-packages@librescrs.org}>"

# Body: the bullet lines of the topmost CHANGELOG.md section, flattened to one
# level. Debian's parser wants "  * " entries and rejects an empty body.
body="$(awk '
  /^## / { if (seen) exit; seen=1; next }
  seen && /^[-*] / { sub(/^[-*] +/, ""); gsub(/\*\*/, ""); print }
' "$here/CHANGELOG.md" | cut -c1-72 | head -n 20)"

mkdir -p "$(dirname "$out")"
{
  printf '%s (%s-%s) unstable; urgency=medium\n\n' "$src" "$version" "$revision"
  if [ -n "$body" ]; then
    printf '%s\n' "$body" | sed 's/^/  * /'
  else
    printf '  * Release %s.\n' "$version"
  fi
  printf '\n -- %s  %s\n' "$maintainer" "$stamp"
} > "$out"

echo "changelog-to-debian: wrote $out for $src $version-$revision"
