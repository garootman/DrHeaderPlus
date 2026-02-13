#!/usr/bin/env python3
"""Bulk scan helper — accepts URLs as arguments, outputs JSON report."""

import json
import sys

from drheader import Drheader


def main() -> None:
    urls = sys.argv[1:]
    if not urls:
        print("Usage: scan_bulk.py <url1> <url2> ...", file=sys.stderr)
        sys.exit(1)

    results = []
    for url in urls:
        try:
            scanner = Drheader(url=url)
            findings = scanner.analyze()
            results.append(
                {
                    "url": url,
                    "issues": len(findings),
                    "findings": [f.to_dict() for f in findings],
                }
            )
        except Exception as e:
            results.append({"url": url, "error": str(e), "findings": []})

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
