#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

echo "Running interactive Netfilter demo"
cd /test/network
./netfilter_demo_step
