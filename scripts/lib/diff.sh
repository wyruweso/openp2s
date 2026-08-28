#!/usr/bin/env bash
#
# Unified-diff parsing, in one place.
#
# Headers are matched by their real syntax, not by `^+[^+]`: that also skips an
# added source line beginning with `+`, so `++counter;` appears as
# `+++counter;` and vanishes from the check.

# Source lines a patch adds, without the leading '+'.
diff_added_lines() {
    awk '
        /^\+\+\+ /  { next }   # file header, not content
        /^\+/       { print substr($0, 2) }
    ' "$1"
}

# Source lines a patch removes, without the leading '-'.
diff_removed_lines() {
    awk '
        /^--- /     { next }   # file header, not content
        /^-/        { print substr($0, 2) }
    ' "$1"
}

# Files a patch touches, as unique paths.
diff_touched_files() {
    awk '/^--- a\// { sub(/^--- a\//, ""); sub(/[[:space:]].*$/, ""); print }' "$1" | sort -u
}

# Added lines with C comments removed.
#
# Tracks /* */ spans across lines rather than testing line prefixes: a line
# like `* explanation */ some_code();` starts with '*' and contains real code.
diff_added_code() {
    diff_added_lines "$1" | awk '
        {
            line = ""
            rest = $0
            while (length(rest) > 0) {
                if (in_comment) {
                    end = index(rest, "*/")
                    if (end == 0) { rest = ""; break }
                    in_comment = 0
                    rest = substr(rest, end + 2)
                } else {
                    start = index(rest, "/*")
                    if (start == 0) { line = line rest; break }
                    line = line substr(rest, 1, start - 1)
                    in_comment = 1
                    rest = substr(rest, start + 2)
                }
            }
            # Trim, and drop lines that were entirely comment or whitespace.
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (length(line) > 0) print line
        }
    '
}
