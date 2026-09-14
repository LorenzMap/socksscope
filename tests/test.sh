#!/bin/sh
# Run from .venv that has the required dependencies
if [ "$1" = cov ]; then
    python3 -m coverage erase
    python3 -m pytest --coverage -p no:xdist
    python3 -m coverage combine
    python3 -m coverage report -m
    python3 -m coverage erase
else
    python3 -m pytest "$@"
fi
