#!/bin/bash
# Script: full_dev_environment_setup.sh

echo 'Setting up global tools and local dev dependencies...'

# Check npm
if ! command -v npm &> /dev/null; then
  echo 'npm not found. Please install Node.js and npm.'
  exit 1
fi

# Install global CLI tools and language support
npm install -g yo generator-code podman-mcp-server @podman-desktop/podman-extension-api @podman-desktop/webview-api vscode-languageclient vscode-jsonrpc vscode-languageserver-types vscode-languageserver-protocol vscode-json-languageservice vscode-languageserver-textdocument vscode-textmate vscode-css-languageservice @vscode/l10n vscode-html-languageservice @vscode/vscode-languagedetection @vscode/test-electron @vscode/emmet-helper @vscode/dev-container-cli @vscode/test-cli vscode-markdown-languageservice vscode-markdown-languageserver
npm install -g podman-mcp-server

# Install local dev dependencies
npm install --save-dev vscode-uri node-addon-api http-proxy-agent @vscode/sudo-prompt @vscode/sqlite3 @vscode/debugprotocol @vscode/debugadapter @vscode/web-custom-data @vscode/wasm-wasi @vscode/jupyter-ipywidgets8 @vscode/ca-certs @vscode/openssl-prebuilt @vscode/prompt-tsx @vscode/chat-extension-utils

echo 'All tools installed successfully.'