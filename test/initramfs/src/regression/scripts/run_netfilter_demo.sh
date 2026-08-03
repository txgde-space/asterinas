#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

echo "Running focused Netfilter demo trace"
cd /test/network
./netfilter_rules
echo "Netfilter demo trace passed."
