#!/bin/sh

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS="linux" ;;
    *)      echo "Unsupported OS: $OS — Linux namespaces are only available on Linux."; exit 1 ;;
esac

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

BINARY_NAME="nsm"
ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH}"

REPO_OWNER="last1chosen"
REPO_NAME="namespace-manager-tui"

DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/${ASSET_NAME}"

echo "Downloading $ASSET_NAME..."

if ! curl -fSL "$DOWNLOAD_URL" -o "/tmp/$BINARY_NAME"; then
    echo "Download failed! Please check if the release exists on GitHub."
    exit 1
fi

chmod +x "/tmp/$BINARY_NAME"

echo "Installing to /usr/local/bin (requires sudo)..."
if sudo mv "/tmp/$BINARY_NAME" "/usr/local/bin/$BINARY_NAME"; then
    echo "Success! You can now run '$BINARY_NAME' in your terminal."
else
    echo "Installation failed."
    exit 1
fi
