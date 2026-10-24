#!/usr/bin/env python3
"""Read or write at a UBSan index-out-of-bounds site (PR-17, sinks).

stdin: the reported source line; argv[1]: the reported column (1-based). The subscript
expression whose `[` is at or nearest after the column is taken; it is a WRITE when the
expression is assigned to (`=`, compound assignment), incremented or decremented, and a READ for
any other use. Prints READ, WRITE or UNDECIDED.
"""
import re
import sys

line = sys.stdin.read().split("\n")[0]
col = int(sys.argv[1]) - 1
starts = [m.start() for m in re.finditer(r"\[", line)]
after = [s for s in starts if s >= col] or [s for s in starts if s < col][-1:]
if not after:
    print("UNDECIDED")
    raise SystemExit
i, depth = after[0], 0
for j in range(i, len(line)):
    depth += {"[": 1, "]": -1}.get(line[j], 0)
    if depth == 0:
        break
else:
    print("UNDECIDED")
    raise SystemExit
rest = line[j + 1 :]
# Further subscripts or member access belong to the same lvalue (a[i][j], a[i].x).
rest = re.sub(r"^(\s*(\[[^\]]*\]|\.\w+|->\w+))*", "", rest)
before = line[: i]
head = re.search(r"(\+\+|--)\s*[\w.>\-]*$", before)
if re.match(r"\s*(=(?!=)|[-+*/%&|^]=|<<=|>>=|\+\+|--)", rest) or head:
    print("WRITE")
else:
    print("READ")
