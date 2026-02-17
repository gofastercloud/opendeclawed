#!/usr/bin/env bash
# setup-ollama.sh — Install Ollama and pull default models for OpenDeclawed
set -euo pipefail

CHAT_MODEL="qwen3:8b"
EMBED_MODEL="nomic-embed-text"

# ── Install Ollama ──────────────────────────────────────────────────────
if command -v ollama &>/dev/null; then
  echo "✓ Ollama already installed: $(ollama --version)"
else
  echo "Installing Ollama via Homebrew..."
  if ! command -v brew &>/dev/null; then
    echo "Error: Homebrew not found. Install from https://brew.sh or install Ollama manually." >&2
    exit 1
  fi
  brew install ollama
  echo "✓ Ollama installed"
fi

# ── Bind Ollama to all interfaces ──────────────────────────────────────
# Required so LiteLLM inside Docker can reach Ollama via host.docker.internal.
# By default Ollama only listens on 127.0.0.1, which is unreachable from containers.
# WARNING: Binding to 0.0.0.0 exposes Ollama to ALL network interfaces.
# On macOS behind NAT this is typically safe, but on a VPS or cloud host
# ensure a firewall blocks external access to port 11434.
export OLLAMA_HOST=0.0.0.0

# Persist for macOS launchd (survives terminal close / reboot)
if command -v launchctl &>/dev/null; then
  launchctl setenv OLLAMA_HOST 0.0.0.0 2>/dev/null || true
fi
echo "✓ OLLAMA_HOST=0.0.0.0 (listening on all interfaces)"

# ── Ensure Ollama is running ────────────────────────────────────────────
if curl -sf http://localhost:11434/api/tags &>/dev/null; then
  echo "✓ Ollama is already running"
  echo "  NOTE: If Ollama was started before OLLAMA_HOST was set, restart it:"
  echo "        brew services restart ollama   # or: pkill ollama && ollama serve &"
else
  echo "Starting Ollama in the background..."
  ollama serve &>/dev/null &
  OLLAMA_PID=$!
  # Wait for Ollama to accept connections (up to 15s)
  for i in $(seq 1 30); do
    if curl -sf http://localhost:11434/api/tags &>/dev/null; then
      break
    fi
    if ! kill -0 "$OLLAMA_PID" 2>/dev/null; then
      echo "Error: Ollama process exited unexpectedly." >&2
      exit 1
    fi
    sleep 0.5
  done
  if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
    echo "Error: Ollama did not start within 15 seconds." >&2
    exit 1
  fi
  echo "✓ Ollama started (pid $OLLAMA_PID)"
fi

# ── Pull models ─────────────────────────────────────────────────────────
echo "Pulling $EMBED_MODEL (embedding model)..."
ollama pull "$EMBED_MODEL"

echo "Pulling $CHAT_MODEL (chat model)..."
ollama pull "$CHAT_MODEL"

# ── Verify ──────────────────────────────────────────────────────────────
echo ""
echo "Installed models:"
ollama list

echo ""
echo "✓ Ollama setup complete. Both models are ready for LiteLLM."
