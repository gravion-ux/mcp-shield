"""Security checks for MCP server configs and tool definitions.

Every check returns a list of Finding objects with a severity and concrete
remediation text. The checks are purely static: nothing is executed.
"""

import re
import unicodedata

from .models import Finding

# --------------------------------------------------------------------------
# Server-config checks
# --------------------------------------------------------------------------

SHELL_BINARIES = {
    "sh", "bash", "zsh", "fish", "dash", "ksh", "csh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
}

BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "/*", "\\", "C:", "C:/", "C:\\"}
_DRIVE_ROOT_RE = re.compile(r"^[A-Za-z]:[\\/]?$")
_PIPE_TO_SHELL_RE = re.compile(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b")

SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|access[_-]?token|auth[_-]?token|session[_-]?token|token|"
    r"secret|password|passwd|private[_-]?key|credential|aws_|gcp_|azure_|"
    r"client[_-]?secret)",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r"^(\s*|\$\{[^}]*\}|<[^>]*>|your[-_ ].*|change[-_ ]?me|todo.*|example.*|"
    r"sample.*|dummy.*|x{3,}|\*{3,}|redacted|placeholder.*|insert[-_ ].*|"
    r"none|null)$",
    re.IGNORECASE,
)
# Well-known token formats: (regex, human label). A match is treated as a
# real credential regardless of the variable name it sits under.
SECRET_VALUE_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "OpenAI-style API key (sk-...)"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GitHub personal access token (ghp_...)"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "GitHub fine-grained token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID (AKIA...)"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token (xox...)"),
    (re.compile(r"AIza[0-9A-Za-z_-]{20,}"), "Google API key (AIza...)"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), "Stripe live secret key (sk_live_...)"),
    (re.compile(r"rk_live_[A-Za-z0-9]{16,}"), "Stripe restricted key (rk_live_...)"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "GitLab personal access token (glpat-...)"),
    (re.compile(r"npm_[A-Za-z0-9]{36}"), "npm token (npm_...)"),
    (re.compile(r"pypi-[A-Za-z0-9_-]{20,}"), "PyPI token (pypi-...)"),
]


def _basename(command):
    return command.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def _args_of(server):
    args = server.get("args")
    if isinstance(args, list):
        return [a for a in args if isinstance(a, str)]
    return []


def _env_of(server):
    env = server.get("env")
    if isinstance(env, dict):
        return {str(k): v for k, v in env.items()}
    return {}


def check_shell_command(name, server):
    findings = []
    command = server.get("command")
    loc = "server '%s'" % name
    if isinstance(command, str) and _basename(command) in SHELL_BINARIES:
        findings.append(Finding(
            check_id="shell-command",
            severity="critical",
            title="Server is launched through a shell",
            location=loc,
            detail=(
                "The server command is '%s', a shell interpreter. Anything the "
                "MCP host passes (or a poisoned tool description tricks it into "
                "passing) becomes arbitrary command execution." % command
            ),
            remediation=(
                "Invoke the server binary directly (e.g. 'node', 'python', the "
                "absolute path to the executable) instead of via a shell, and "
                "never use 'sh -c' style wrappers."
            ),
        ))
    for arg in _args_of(server):
        if _PIPE_TO_SHELL_RE.search(arg):
            findings.append(Finding(
                check_id="pipe-to-shell",
                severity="critical",
                title="Argument pipes a remote download into a shell",
                location=loc,
                detail="Argument %r downloads remote content and pipes it into a shell." % arg,
                remediation=(
                    "Remove download-and-execute arguments. Install the server "
                    "from a pinned package through a package manager instead."
                ),
            ))
            break
    return findings


def check_broad_paths(name, server):
    findings = []
    loc = "server '%s'" % name
    for arg in _args_of(server):
        if arg in BROAD_PATHS or _DRIVE_ROOT_RE.match(arg):
            findings.append(Finding(
                check_id="broad-filesystem-access",
                severity="high",
                title="Server is granted an overly broad filesystem path",
                location=loc,
                detail=(
                    "Argument %r grants access to a root/home-level path. A "
                    "compromised or poisoned server can read or modify "
                    "everything under it (SSH keys, cloud credentials, documents)."
                    % arg
                ),
                remediation=(
                    "Scope the server to the narrowest project directory it "
                    "actually needs instead of '/', '~' or a drive root."
                ),
            ))
    return findings


def check_secrets_in_env(name, server):
    findings = []
    loc = "server '%s'" % name
    for key, value in _env_of(server).items():
        if not isinstance(value, str):
            continue
        label = None
        for pattern, pat_label in SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                label = pat_label
                break
        if label is not None:
            findings.append(Finding(
                check_id="secret-in-env",
                severity="critical",
                title="Live credential committed in env block",
                location="%s env '%s'" % (loc, key),
                detail=(
                    "The value of %s matches the format of a %s. Anyone with "
                    "read access to this config file owns the credential."
                    % (key, label)
                ),
                remediation=(
                    "Rotate this credential now (treat it as leaked), remove it "
                    "from the config, and inject it at runtime via an "
                    "environment reference such as ${VAR} or a secret manager."
                ),
            ))
        elif SECRET_KEY_RE.search(key) and not _PLACEHOLDER_RE.match(value.strip()) \
                and len(value.strip()) >= 8:
            findings.append(Finding(
                check_id="secret-in-env",
                severity="high",
                title="Secret-looking value stored in env block",
                location="%s env '%s'" % (loc, key),
                detail=(
                    "Variable %s has a secret-sounding name and a non-placeholder "
                    "value stored in plaintext in the config file." % key
                ),
                remediation=(
                    "Move the secret out of the config file: reference the host "
                    "environment (e.g. \"${%s}\") or use a secret manager, and "
                    "rotate the value if the file was ever shared or committed."
                    % key
                ),
            ))
    return findings


def _spec_is_pinned(spec):
    """True if an npm-style package spec carries a concrete version pin."""
    s = spec.strip()
    if not s or s.endswith("@latest"):
        return False
    if s.startswith("@"):
        # Scoped package: @scope/name[@version]
        slash = s.find("/")
        if slash == -1:
            return False
        rest = s[slash + 1:]
        if "@" in rest:
            return rest.split("@", 1)[1] not in ("", "latest")
        return False
    if "@" in s:
        return s.split("@", 1)[1] not in ("", "latest")
    return False


def _first_positional(args, value_flags=()):
    """First non-flag argument, skipping values of flags that take a value."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in value_flags:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return arg
    return None


def _docker_image_is_pinned(image):
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return last.rsplit(":", 1)[1] not in ("", "latest")
    return False


def check_unpinned_packages(name, server):
    findings = []
    command = server.get("command")
    if not isinstance(command, str):
        return findings
    base = _basename(command)
    args = _args_of(server)
    loc = "server '%s'" % name
    specs = []

    if base in ("npx", "bunx"):
        for i, arg in enumerate(args):
            if arg in ("-p", "--package") and i + 1 < len(args):
                specs.append(args[i + 1])
        positional = _first_positional(args, value_flags=("-p", "--package"))
        if positional:
            specs.append(positional)
        runner = base
    elif base == "uvx":
        for i, arg in enumerate(args):
            if arg == "--from" and i + 1 < len(args):
                specs.append(args[i + 1])
        positional = _first_positional(
            args, value_flags=("--from", "--with", "-w", "--python", "-p")
        )
        if positional:
            specs.append(positional)
        runner = base
    elif base == "docker" and args and args[0] == "run":
        image = _first_positional(
            args[1:],
            value_flags=("-e", "--env", "--env-file", "-v", "--volume",
                         "-p", "--publish", "--name", "--network",
                         "--user", "-u", "--pull", "-w", "--workdir"),
        )
        if image and not _docker_image_is_pinned(image):
            findings.append(Finding(
                check_id="unpinned-package",
                severity="medium",
                title="Docker image is not pinned to a version",
                location=loc,
                detail=(
                    "Image '%s' has no tag or uses 'latest', so every launch "
                    "can silently pull different code." % image
                ),
                remediation="Pin the image to an exact tag or digest, e.g. 'image:1.2.3' or 'image@sha256:...'.",
            ))
        return findings
    else:
        return findings

    for spec in specs:
        if not _spec_is_pinned(spec):
            findings.append(Finding(
                check_id="unpinned-package",
                severity="medium",
                title="Package executed without a version pin (%s)" % runner,
                location=loc,
                detail=(
                    "'%s %s' resolves the newest published version at launch "
                    "time. If the package is hijacked or re-published with "
                    "malicious code (a rug pull), it runs automatically with "
                    "the MCP host's privileges." % (runner, spec)
                ),
                remediation=(
                    "Pin an exact version, e.g. '%s@1.2.3', review the package, "
                    "and only bump versions deliberately."
                    % (spec[:-len("@latest")] if spec.endswith("@latest") else spec)
                ),
            ))
    return findings


def audit_server(name, server):
    findings = []
    findings += check_shell_command(name, server)
    findings += check_broad_paths(name, server)
    findings += check_secrets_in_env(name, server)
    findings += check_unpinned_packages(name, server)
    return findings


def audit_config(servers):
    findings = []
    for name in sorted(servers):
        findings += audit_server(name, servers[name])
    return findings


# --------------------------------------------------------------------------
# Tool-definition checks
# --------------------------------------------------------------------------

# Phrases that indicate a description is trying to steer the model rather
# than describe the tool. (pattern, severity, label)
_POISON_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+instructions", re.I),
     "critical", "tells the model to ignore other instructions"),
    (re.compile(r"disregard\s+(all\s+)?(the\s+)?(previous|prior|above|other)\b", re.I),
     "critical", "tells the model to disregard other instructions"),
    (re.compile(r"do\s+not\s+(tell|inform|notify|alert|mention\s+to)\s+the\s+user", re.I),
     "critical", "tells the model to hide behaviour from the user"),
    (re.compile(r"never\s+(tell|inform|notify|reveal\s+to)\s+the\s+user", re.I),
     "critical", "tells the model to hide behaviour from the user"),
    (re.compile(r"send\s+(the\s+)?(contents|data|files?|results?|output|conversation)\b[^.]{0,60}\bto\s+\S+@", re.I),
     "critical", "instructs exfiltration of data to an email address"),
    (re.compile(r"before\s+(using|calling|invoking)\s+any\s+other\s+tool", re.I),
     "high", "tries to force invocation order over other tools"),
    (re.compile(r"you\s+must\s+(always|never)\b", re.I),
     "high", "issues standing orders to the model"),
    (re.compile(r"<\s*/?\s*system\s*>|system\s+prompt\s*:", re.I),
     "high", "imitates a system prompt"),
    (re.compile(r"important\s*:\s*(you\s+must|always|never|before)", re.I),
     "high", "uses urgency framing to steer the model"),
    (re.compile(r"whenever\s+you\s+(use|call|invoke)\s+this\s+tool,?\s+(also|first|silently)", re.I),
     "high", "attaches hidden side-effects to tool use"),
]

# Zero-width, bidi-control and other format characters that can hide text
# from a human reviewer while remaining visible to the model.
_HIDDEN_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}


def _hidden_chars_in(text):
    found = []
    for ch in text:
        if ch in _HIDDEN_CHARS or unicodedata.category(ch) == "Cf":
            if ch not in found:
                found.append(ch)
    return found


def check_description_poisoning(tool):
    findings = []
    name = str(tool.get("name", "<unnamed>"))
    loc = "tool '%s'" % name
    description = tool.get("description")
    if not isinstance(description, str):
        description = ""

    for pattern, severity, label in _POISON_PATTERNS:
        match = pattern.search(description)
        if match:
            findings.append(Finding(
                check_id="tool-description-poisoning",
                severity=severity,
                title="Tool description contains instruction-like content",
                location=loc,
                detail=(
                    "Description %s: matched %r. Tool descriptions are loaded "
                    "into the model's context; instructions inside them are a "
                    "prompt-injection / tool-poisoning vector."
                    % (label, match.group(0)[:80])
                ),
                remediation=(
                    "Rewrite the description to only state what the tool does, "
                    "its inputs and its outputs. Remove any text addressed to "
                    "the model (orders, secrecy, invocation rules)."
                ),
            ))

    hidden = _hidden_chars_in(name) + _hidden_chars_in(description)
    if hidden:
        codepoints = ", ".join("U+%04X" % ord(c) for c in hidden)
        findings.append(Finding(
            check_id="tool-hidden-unicode",
            severity="high",
            title="Hidden Unicode characters in tool name/description",
            location=loc,
            detail=(
                "Found invisible/control characters (%s). These can hide "
                "instructions from human reviewers while the model still "
                "reads them." % codepoints
            ),
            remediation=(
                "Strip all zero-width and bidirectional control characters "
                "from tool names and descriptions; re-type the text plainly."
            ),
        ))

    if len(description) > 1000:
        findings.append(Finding(
            check_id="tool-description-length",
            severity="low",
            title="Tool description is excessively long",
            location=loc,
            detail=(
                "Description is %d characters. Very long descriptions are a "
                "common place to bury injected instructions and inflate the "
                "tool's influence over the model." % len(description)
            ),
            remediation="Trim the description to a concise summary of behaviour, inputs and outputs.",
        ))
    return findings


WELL_KNOWN_TOOL_NAMES = {
    "read_file", "write_file", "edit_file", "create_file", "append_file",
    "delete_file", "remove_file", "move_file", "copy_file",
    "read_text_file", "read_media_file", "read_multiple_files",
    "list_directory", "directory_tree", "list_allowed_directories",
    "search_files", "get_file_info", "get_file_contents",
    "execute_command", "run_command", "run_shell_command", "bash", "shell",
    "fetch", "web_fetch", "web_search", "search", "download_file",
    "upload_file", "send_email", "execute_sql", "query", "list_tables",
    "create_issue", "list_issues", "get_issue", "add_comment",
    "think", "sequentialthinking", "create_memory", "search_nodes",
    "open_nodes", "get_current_time", "convert_time",
}


def _normalize_name(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _levenshtein(a, b):
    if abs(len(a) - len(b)) > 1:
        return 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_name_shadowing(tools):
    findings = []
    names = [str(t.get("name", "")) for t in tools]

    for tool in tools:
        name = str(tool.get("name", ""))
        if name in WELL_KNOWN_TOOL_NAMES:
            findings.append(Finding(
                check_id="tool-name-shadowing",
                severity="medium",
                title="Tool name squats a well-known tool name",
                location="tool '%s'" % name,
                detail=(
                    "'%s' is the name of a tool shipped by a popular MCP "
                    "server. When two servers offer the same name, the model "
                    "(and the user) cannot tell which implementation actually "
                    "runs, so a malicious server can shadow a trusted one." % name
                ),
                remediation=(
                    "Namespace third-party tool names (e.g. 'acme_read_file') "
                    "and remove servers that re-define names you already trust."
                ),
            ))

    by_normalized = {}
    for name in names:
        if name:
            by_normalized.setdefault(_normalize_name(name), set()).add(name)
    for normalized, variants in sorted(by_normalized.items()):
        if len(variants) > 1:
            findings.append(Finding(
                check_id="tool-name-collision",
                severity="high",
                title="Tool names collide after normalisation",
                location="tools %s" % ", ".join(sorted(variants)),
                detail=(
                    "Names %s differ only by case or separators ('_', '-'), "
                    "which many hosts and models treat as the same tool."
                    % ", ".join(sorted(variants))
                ),
                remediation="Rename one of the tools so every tool name is unambiguous.",
            ))

    unique_names = sorted(set(n for n in names if n))
    for i, a in enumerate(unique_names):
        for b in unique_names[i + 1:]:
            na, nb = _normalize_name(a), _normalize_name(b)
            if na != nb and len(na) >= 4 and _levenshtein(na, nb) == 1:
                findings.append(Finding(
                    check_id="tool-name-confusable",
                    severity="medium",
                    title="Tool names are one edit apart",
                    location="tools '%s' / '%s'" % (a, b),
                    detail=(
                        "'%s' and '%s' differ by a single character, making it "
                        "easy for a model or user to invoke the wrong one." % (a, b)
                    ),
                    remediation="Rename one tool so the names are clearly distinct.",
                ))
    return findings


def check_input_schema(tool):
    name = str(tool.get("name", "<unnamed>"))
    loc = "tool '%s'" % name
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict) or not schema:
        return [Finding(
            check_id="tool-schema-missing",
            severity="medium",
            title="Tool has no inputSchema",
            location=loc,
            detail=(
                "Without an inputSchema the host cannot validate arguments "
                "before they reach the server, and the model must guess the "
                "parameter shape."
            ),
            remediation="Add a JSON Schema inputSchema describing every parameter, its type and constraints.",
        )]

    issues = []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for prop_name, prop in properties.items():
            if isinstance(prop, dict) and prop.get("type") == "string" \
                    and "maxLength" not in prop and "enum" not in prop \
                    and "format" not in prop:
                issues.append(
                    "string parameter '%s' has no maxLength/enum/format constraint"
                    % prop_name
                )
    if schema.get("additionalProperties") is not False:
        issues.append("additionalProperties is not false, so undeclared parameters are accepted")
    if issues:
        return [Finding(
            check_id="tool-schema-unconstrained",
            severity="low",
            title="Tool inputSchema lacks constraints",
            location=loc,
            detail="; ".join(issues) + ".",
            remediation=(
                "Constrain string parameters (maxLength, enum or format), and "
                "set additionalProperties to false so only declared parameters "
                "are accepted."
            ),
        )]
    return []


def audit_tools(tools):
    findings = []
    for tool in tools:
        findings += check_description_poisoning(tool)
        findings += check_input_schema(tool)
    findings += check_name_shadowing(tools)
    return findings
