#!/bin/bash

set -e

# Download current gh-pages content to a temp location
mkdir -p build/previous-versions/current
git fetch origin gh-pages
git archive origin/gh-pages | tar -x -C build/previous-versions/current

# Move older versions from dokka's 'older' output dir to previous-versions root
if [ -d "build/previous-versions/current/older" ]; then
    for version_dir in build/previous-versions/current/older/*/; do
        if [ -d "$version_dir" ]; then
            version_name=$(basename "$version_dir")
            mv "$version_dir" "build/previous-versions/$version_name"
        fi
    done
    rm -rf build/previous-versions/current/older
fi

# Move the current gh-pages version into its own versioned directory
if [ -f "build/previous-versions/current/version.json" ]; then
    CURRENT_VERSION=$(grep -o '"version":"[^"]*"' build/previous-versions/current/version.json | cut -d'"' -f4)
    if [ -n "$CURRENT_VERSION" ]; then
        rm -rf "build/previous-versions/$CURRENT_VERSION"
        mv build/previous-versions/current "build/previous-versions/$CURRENT_VERSION"
    else
        echo "Warning: could not parse version from version.json, skipping current version"
        rm -rf build/previous-versions/current
    fi
else
    echo "Warning: version.json not found in gh-pages, skipping current version"
    rm -rf build/previous-versions/current
fi