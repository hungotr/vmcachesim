#!/usr/bin/env bash
set -e

# Build
make

# Example parameters from the PDF
CACHE_SIZE=512        # KB
BLOCK_SIZE=16         # bytes
ASSOC=4               # 4-way
REPLACEMENT=rr        # rr = Round-Robin
PHYS_MEM=1024         # MB
INSTR_SLICE=100       # instructions per slice
PERCENT_OS=75         # % phys mem used by OS

# Trace files
TRACE_FILES=("A-10_new_1.5_a.pdf.trc" "A-9_new_1.5.pdf.trc" "A-9_new_trunk2.trc")

# Run simulator
./VMCacheSim3 \
  -s $CACHE_SIZE \
  -b $BLOCK_SIZE \
  -a $ASSOC \
  -r $REPLACEMENT \
  -p $PHYS_MEM \
  -n $INSTR_SLICE \
  -u $PERCENT_OS \
  ${TRACE_FILES[@]/#/ -f }