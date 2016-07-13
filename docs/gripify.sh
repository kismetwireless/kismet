#!/bin/bash

for x in *.md; do
    grip $x --export $1/`basename "$x" .md`.html --no-inline
done
