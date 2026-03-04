#!/bin/bash
set -e

# Ensure tmp directory exists for ephemeral SQLite database
mkdir -p /tmp

echo "Starting EireScope OSINT Dashboard..."
exec python run.py --host 0.0.0.0 --port 5000
