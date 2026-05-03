#!/usr/bin/env sh
set -eu

has_command() {
  command -v "$1" >/dev/null 2>&1
}

run_if_available() {
  command_name="$1"
  shift

  if has_command "$command_name"; then
    "$@"
  else
    echo "Skipping $command_name: command not found"
  fi
}

search_regex() {
  pattern="$1"
  shift

  if has_command rg; then
    rg -n "$pattern" "$@"
  else
    grep -RInE "$pattern" "$@"
  fi
}

echo "==> Checking for sensitive debug output"
if search_regex "IO\.inspect|dbg\(|Logger\.(debug|info|warning|warn|error).*(password|secret|private_key|access_token|refresh_token|authorization|bearer|token)" lib config priv guides README.md test; then
  echo "Sensitive debug output patterns found. Review the matches above."
  exit 1
fi

secret_paths="lib config priv guides README.md"

echo "==> Checking for committed secret-looking material"
if search_regex "BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|AKIA[0-9A-Z]{16}|[\"']?(client_secret|api[_-]?key|access_token|refresh_token)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9_./+=:-]{24,}[\"']" $secret_paths; then
  echo "Secret-looking material found. Review the matches above."
  exit 1
fi

echo "==> Running dependency audit when available"
if mix help deps.audit >/dev/null 2>&1; then
  mix deps.audit
else
  echo "Skipping mix deps.audit: task not available"
fi

echo "==> Running Hex audit when available"
if mix help hex.audit >/dev/null 2>&1; then
  mix hex.audit
else
  echo "Skipping mix hex.audit: task not available"
fi

echo "==> Running gitleaks when available"
run_if_available gitleaks gitleaks detect --source . --no-git=false --redact

echo "Security audit completed"
