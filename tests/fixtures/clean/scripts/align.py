"""Align the pipes of Markdown tables in a file and print the result."""
import sys


def align(lines):
    rows = [[c.strip() for c in line.strip().strip("|").split("|")] for line in lines]
    widths = [max(len(r[i]) for r in rows if i < len(r)) for i in range(max(map(len, rows)))]
    return ["| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(r)) + " |" for r in rows]


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        table = [line for line in fh if line.strip().startswith("|")]
    print("\n".join(align(table)))
