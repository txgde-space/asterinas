#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

exec /benchmark/bin/python3 /benchmark/flask_socket_demo/app.py --host 0.0.0.0 --port 8080
