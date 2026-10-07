#!/usr/bin/env bash
# Flags the mechanical voice-guide violations in each Markdown file given.
# For pages in docs/user/ and docs/design/, not for the voice guide that lists the words.
# Usage: check-prose.sh <file.md>...
# Prints each hit as file:line: kind: text, and exits 1 when it finds one.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <file.md>..." >&2
  exit 2
fi

exec perl -CSD -Mutf8 -e '
  my @checks = (
    ["em-dash",     qr/\x{2014}/],
    ["emoji",       qr/[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]/],
    ["word",        qr/\b(?:robust|powerful|seamless(?:ly)?|effortless(?:ly)?|elegant|comprehensive|flexible|simply|easily|gracefully|leverages?|utilizes?|delve|crucial|vital|pivotal|boasts|notably|importantly|remarkably|basically|additionally|moreover|furthermore)\b/i],
    ["phrase",      qr/it.?s worth noting|it is worth noting|it.?s important to|it is important to|it should be noted|in order to|as mentioned|plays a key role|serves as|not just .+, but|cutting-edge|state-of-the-art/i],
  );
  my $status = 0;
  for my $file (@ARGV) {
    open(my $fh, "<", $file) or die "$file: $!\n";
    my $fence = "";
    while (my $line = <$fh>) {
      chomp $line;
      if ($fence eq "" && $line =~ /^\s*(`{3,}|~{3,})/) { $fence = $1; next; }
      if ($fence ne "") {
        my ($char, $length) = (substr($fence, 0, 1), length $fence);
        $fence = "" if $line =~ /^\s*(\Q$char\E{$length,})\s*$/;
        next;
      }
      (my $prose = $line) =~ s/(`+)(?!`).*?(?<!`)\1(?!`)//g;
      for my $check (@checks) {
        my ($kind, $pattern) = @$check;
        if ($prose =~ $pattern) {
          print "$file:$.: $kind: $line\n";
          $status = 1;
        }
      }
    }
  }
  exit $status;
' -- "$@"
