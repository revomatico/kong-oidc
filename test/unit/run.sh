#!/bin/bash
set -e

rm -f luacov.stats.out

# Run all test_*.lua files in test/unit
for f in test/unit/test_*.lua; do
  (set -x
    lua -lluacov ${f} -o TAP --failure -v
    # lua -lluacov ${f} -o TAP --failure -v
  )
done
luacov
cat luacov.report.out
