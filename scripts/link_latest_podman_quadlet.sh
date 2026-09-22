#!/bin/bash
# Links the podman QUADLET GENERATOR BINARY (the podman-system-generator /
# podman-user-generator and podman's systemd units) from the latest Nix-store
# podman into the standard /usr/lib/systemd generator paths. This is the podman
# quadlet system-generator toolchain -- NOT the static quadlet/ unit tree; it
# touches no *.container/*.volume/*.network files under quadlet/ or
# /etc/containers/systemd.
#TODO: may need to add a nix-store --gc, to clean up extra files that exist
# Find the latest podman version in the Nix store
latest_podman=$(find /nix/store -maxdepth 1 -name '*-podman-*' | 
                sed -n 's/.*-podman-\([0-9.]*\)$/\1/p' | 
                sort -V | 
                tail -n1)

if [ -n "$latest_podman" ]; then
    # Find the full path of the latest version
    podman_path=$(find /nix/store -maxdepth 1 -name "*-podman-${latest_podman}" | tail -n1)
    
    # Assign the result to a variable
    LATEST_PODMAN_PATH="$podman_path"
    
    echo "Latest Podman version found: $latest_podman"
    echo "Path: $LATEST_PODMAN_PATH"
else
    echo "No Podman installation found in the Nix store."
fi


sudo ln -sf "$LATEST_PODMAN_PATH/lib/systemd/system-generators/podman-system-generator" /usr/lib/systemd/system-generators/podman-system-generator
sudo ln -sf "$LATEST_PODMAN_PATH/lib/systemd/user-generators/podman-user-generator" /usr/lib/systemd/user-generators/
sudo ln -sf -t /usr/lib/systemd/system/ "$LATEST_PODMAN_PATH"/lib/systemd/system/*
sudo ln -sf -t /usr/lib/systemd/user/ "$LATEST_PODMAN_PATH"/lib/systemd/user/*

echo "Linked the files in systemd"

