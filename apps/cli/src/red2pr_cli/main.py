"""Cross-platform Red2PR CLI entry point."""

from __future__ import annotations

import argparse
import sys

from red2pr_cli.commands import COMMANDS, execute_command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="red2pr")
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("args", nargs="*")
    parsed = parser.parse_args(argv)
    result = execute_command(parsed.command, args=parsed.args)
    if result.output:
        sys.stdout.write(result.output + "\n")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
