#!/usr/bin/env python3
"""Fail unless every upstream job reported 'success'. Reads the GitHub `needs` context from $NEEDS (passed via env, never interpolated into a shell)."""
import json
import os
import sys

needs = json.loads(os.environ["NEEDS"])
results = {job: info["result"] for job, info in needs.items()}
print("upstream jobs:", results)
bad = {job: r for job, r in results.items() if r != "success"}
if bad:
    print(f"FAIL: upstream jobs did not succeed: {bad}")
    sys.exit(1)
