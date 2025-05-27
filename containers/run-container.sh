#!/bin/bash
#
# Script to build and run a container using configuration files from the current directory
# Rather than using hardcoded paths, this script uses the script's directory for all configs
#

# Get script directory using BASH_SOURCE
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="/tmp/podman-containers-data"
IMAGE_NAME="localhost/bootcdev-image"
CONTAINERFILE_PATH="$SCRIPT_DIR"  # Use the containers folder where bootcdev.containerfile is located

# Create data directory if it doesn't exist
if [ ! -d "$DATA_DIR" ]; then
    mkdir -p "$DATA_DIR"
    echo "Created data directory at $DATA_DIR"
fi

# Check for required files
REQUIRED_FILES=("auth.json" "containers.conf" "policy.json" "registries.conf" "storage.conf" "bootcdev.containerfile")
MISSING_FILES=()

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$file" ]; then
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo "ERROR: Missing required files in $SCRIPT_DIR: ${MISSING_FILES[*]}"
    echo "Please ensure all configuration files are present before running this script."
    exit 1
fi

# Check if image exists
if ! podman image exists "$IMAGE_NAME"; then
    CONTAINERFILE="$SCRIPT_DIR/bootcdev.containerfile"
    echo "Image '$IMAGE_NAME' not found. Building from $CONTAINERFILE..."
    podman build -t "$IMAGE_NAME" -f "$CONTAINERFILE" "$CONTAINERFILE_PATH"
fi

# Run the container
echo "Starting bootc container from $IMAGE_NAME..."
podman run -d --name bootcdev \
    --privileged \
    --systemd always \
    -v "$SCRIPT_DIR/auth.json:/usr/lib/container-auth.json:ro" \
    -v "$SCRIPT_DIR/containers.conf:/etc/containers/containers.conf:ro" \
    -v "$SCRIPT_DIR/policy.json:/etc/containers/policy.json:ro" \
    -v "$SCRIPT_DIR/registries.conf:/etc/containers/registries.conf:ro" \
    -v "$SCRIPT_DIR/storage.conf:/etc/containers/storage.conf:ro" \
    -v "$DATA_DIR:/data" \
    -p 2222:22 \
    -p 8080:80 \
    -p 8443:443 \
    "$IMAGE_NAME"

CONTAINER_ID=$(podman ps -qf name=bootcdev)
if [ -n "$CONTAINER_ID" ]; then
    echo "Container started with ID: $CONTAINER_ID"
    echo "Access SSH on port 2222, HTTP on 8080, and HTTPS on 8443"
    echo "To stop: podman stop bootcdev"
    echo "To remove: podman rm bootcdev"
else
    echo "ERROR: Failed to start the container. Check if all required configuration files exist in the script directory."
    echo "Required files: auth.json, containers.conf, policy.json, registries.conf, storage.conf, bootcdev.containerfile"
    exit 1
fi
podman run -it --rm \
  --privileged \
  --systemd always \
  -v "$SCRIPT_DIR/auth.json:/usr/lib/container-auth.json:ro" \
  -v "$SCRIPT_DIR/containers.conf:/etc/containers/containers.conf:ro" \
  -v "$SCRIPT_DIR/policy.json:/etc/containers/policy.json:ro" \
  -v "$SCRIPT_DIR/registries.conf:/etc/containers/registries.conf:ro" \
  -v "$SCRIPT_DIR/storage.conf:/etc/containers/storage.conf:ro" \
  -v "$DATA_DIR:/var/lib/myapp" \
  "$IMAGE_NAME"
