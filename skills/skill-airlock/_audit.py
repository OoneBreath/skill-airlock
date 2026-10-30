"""Static audit for agent skills (SKILL.md plus bundled files).

Evidence, not verdicts: every finding carries file:line and a sanitised excerpt.
A clean report means "nothing known was found", never "safe".
Python 3 stdlib only.
"""
import hashlib
import os
import re
import unicodedata

HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITIES = (HIGH, MEDIUM, LOW)
VERDICTS = {HIGH: "BLOCK", MEDIUM: "REVIEW", LOW: "OK", None: "CLEAN"}

MAX_BYTES = 2_000_000
MAX_LINE = 20_000
MAX_PER_RULE_PER_FILE = 5
SKIP_DIRS = {".git", "node_modules", "__pycache__"}
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
              ".php", ".ps1", ".psm1", ".bat", ".cmd", ".lua", ".go", ".rs", ".swift"}
ASSET_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".woff", ".woff2", ".ttf",
             ".otf", ".mp3", ".mp4", ".wav", ".zip", ".gz", ".tgz", ".docx", ".xlsx", ".pptx"}
# A zero-width character right before a fence is the usual way to show a literal ``` inside a fenced
# template; outside SKILL.md that exact shape is low, anywhere else zero-width stays high.
FENCE_ESCAPE = re.compile(r"^(\s*[\u200b\u200c\u200d\u2060\ufeff]+)(```|~~~)")
# SKILL.md that tells the agent to fetch content at run time: the audited copy is then not the whole story.
REMOTE_URL = re.compile(r"https?://[^\s`'\")<>]+")
FETCH_VERB = re.compile(r"\b(fetch\w*|download\w*|retriev\w*|pull(s|ed|ing)?|load(s|ed|ing)?|grab\w*|webfetch|curl|wget)\b",
                        re.IGNORECASE)
# What is fetched has to BE the instructions: "fetch the latest rules", "rules from the fetched document",
# or a URL pointing at an instruction file. A course catalogue or an SDK README is reference material.
_NOUN = r"(guidelines?|rules?|instructions?|prompts?|checklists?|polic(y|ies)|playbooks?)"
FETCHES_INSTRUCTIONS = re.compile(r"\b(fetch\w*|download\w*|retriev\w*|load\w*|pull\w*|grab\w*|webfetch)\b(\W+\w+){0,4}?\W+" + _NOUN + r"\b|"
                                  r"\b" + _NOUN + r"\W+(in|from)\W+the\W+fetched\b", re.IGNORECASE)
INSTRUCTION_FILE = re.compile(r"/(command|skill|agents?|claude|prompts?|rules|guidelines|instructions)[\w-]*\.md\b", re.IGNORECASE)
BENIGN_DOTFILES = {".gitignore", ".gitkeep", ".gitattributes", ".editorconfig", ".prettierrc"}

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
TAGS = range(0xE0000, 0xE0080)

NETWORK_RULES = {"network", "raw-ip", "exfil-endpoint", "reverse-shell"}
SECRET_RULES = {"secret-path", "dotenv", "env-dump", "credential-store", "agent-credentials"}
# Rules about instructions aimed at the agent. A quoted mention ("never write 'ignore previous
# instructions'") in docs or comments is documentation, not an attack, and drops to low.
INSTRUCTION_RULES = {"injection", "conceal-from-user", "skip-confirmation", "without-asking", "permission-bypass",
                     "role-override", "fake-system-tag", "exfil-instruction", "claims-user-approval", "airlock-override"}
# Everything else that matches a line is about code that could run. In Markdown prose (outside a
# fenced block) or in a script comment it is one level less severe: it describes, it doesn't run.
DOWNGRADE = {HIGH: MEDIUM, MEDIUM: LOW, LOW: LOW}

# (rule, severity, pattern, note). Applied to every line of every text file:
# Markdown counts too, because a skill's Markdown is instructions the agent will act on.
LINE_RULES = [
    # network
    ("network", MEDIUM, r"\b(curl|wget|ncat|netcat|socat|telnet|sftp|scp)\b", "network tool"),
    ("network", MEDIUM, r"(?<![\w.-])nc\s+-?[a-zA-Z0-9]", "netcat"),
    ("network", MEDIUM, r"\b(requests|httpx)\.(get|post|put|patch|delete|request|head|Session|Client|AsyncClient)\b", "HTTP client"),
    ("network", MEDIUM, r"\burllib(3|\.request)\b|\burlopen\s*\(|\bhttp\.client\b|\baiohttp\b", "HTTP client"),
    ("network", MEDIUM, r"\bsocket\.(socket|create_connection)\b", "raw socket"),
    ("network", MEDIUM, r"(?<![\w.])fetch\(|\baxios\b|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bsendBeacon\b", "HTTP client"),
    ("network", MEDIUM, r"\bInvoke-(WebRequest|RestMethod)\b|\bNet\.WebClient\b", "HTTP client"),
    ("raw-ip", MEDIUM, r"https?://(?!127\.0\.0\.1|0\.0\.0\.0)\d{1,3}(\.\d{1,3}){3}", "URL with a raw IP address"),
    ("reverse-shell", HIGH, r"/dev/(tcp|udp)/", "bash network device, typical of reverse shells"),
    # Bounded on both sides: "toast.promise" must not read as oast.pro, nor "notpastebin.com" as pastebin.com.
    ("exfil-endpoint", HIGH, r"(?<![\w-])(discord(app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|requestbin|pipedream\.net|"
                             r"ngrok(-free)?\.(io|app)|pastebin\.com|transfer\.sh|interact\.sh|oast\.(fun|me|pro|live|site)|"
                             r"burpcollaborator)(?![\w-])",
     "known data-collection or tunnelling endpoint"),
    # secrets
    ("secret-path", MEDIUM, r"(?<![\w-])\.(ssh|aws|gnupg|kube)\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.git-credentials|"
                            r"(?<![\w-])\.(netrc|npmrc|pypirc)\b|\.docker/config\.json|\.config/gh/hosts", "path to credentials"),
    ("dotenv", MEDIUM, r"(?<![\w./\\-])\.env(?![\w.-])|(?<![\w./\\-])\.env\.(local|production|prod)\b", ".env file"),
    ("env-dump", MEDIUM, r"\bprintenv\s*($|[|;>&)])|(^|[;&|(`]\s*|\$\(\s*)env\s*\||JSON\.stringify\(\s*process\.env\s*\)|"
                         r"json\.dumps?\(\s*(dict\()?\s*os\.environ|print\(\s*(dict\()?\s*os\.environ\s*\)?\s*\)",
     "dumps all environment variables"),
    ("credential-store", HIGH, r"\bsecurity\s+find-(generic|internet)-password\b|Login Data|Cookies\.binarycookies|"
                               r"\bkeyring\.get_password\b", "reads a password or cookie store"),
    ("agent-credentials", HIGH, r"\.claude/\.credentials|\.codex/auth\.json|\.config/gcloud|application_default_credentials",
     "reads an agent's or cloud CLI's credentials"),
    ("secret-env", LOW, r"\b[A-Z][A-Z0-9_]*_(TOKEN|SECRET|API_KEY|APIKEY|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY)\b",
     "secret-looking environment variable"),
    # execution and obfuscation
    ("pipe-to-shell", HIGH, r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?((ba|z|da|k)?sh|python3?|node|perl|ruby|php)\b|"
                            r"\b(ba|z)?sh\s+(-c\s+)?[\"']?\$\(\s*(curl|wget)|\b(ba|z)?sh\s+<\(\s*(curl|wget)",
     "downloads and runs code in one step"),
    ("decode-and-run", HIGH, r"base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(sudo\s+)?((ba|z|da)?sh|python3?|perl|node)\b|"
                             r"exec\s*\(\s*(base64\.)?b64decode|eval\s*\(\s*(atob|Buffer\.from)\s*\(|exec\s*\(\s*(zlib|marshal|codecs)\.",
     "decodes hidden code and runs it"),
    ("dynamic-exec", MEDIUM, r"(?<![\w.])(eval|exec)\s*\(|\bnew\s+Function\s*\(|__import__\s*\(|\bmarshal\.loads\b|"
                             r"\bpickle\.loads\b|(?<![\w-])eval\s+[\"'$`]", "runs code built at runtime"),
    ("decode", MEDIUM, r"base64\s+(-d|--decode|-D)\b|\bb64decode\b|\batob\s*\(|\bfromCharCode\b", "decodes encoded data"),
    ("encoded-blob", MEDIUM, r"[A-Za-z0-9+/]{200,}={0,2}|(\\x[0-9a-fA-F]{2}){16,}", "long encoded blob"),
    # persistence and system changes
    ("persistence", HIGH, r"\bcrontab\b|/etc/cron|\bsystemctl\s+(--user\s+)?enable\b|\blaunchctl\s+(load|bootstrap)\b|"
                          r"LaunchAgents|LaunchDaemons|/etc/rc\.local|\bschtasks\b|CurrentVersion\\+Run", "survives reboot or logout"),
    ("shell-rc-write", HIGH, r"((?<![-=])>>?|\btee\b(\s+-a)?)\s*['\"]?(~|\$HOME|\$\{HOME\})?/?\S*\.(bashrc|zshrc|bash_profile|zprofile|profile|zshenv)\b",
     "writes to a shell startup file"),
    ("shell-rc", MEDIUM, r"(?<![\w-])\.(bashrc|zshrc|bash_profile|zprofile|zshenv)\b", "mentions a shell startup file"),
    ("agent-config", HIGH, r"\.claude/settings(\.local)?\.json|\.claude/(hooks|commands|agents)/|\.codex/config\.toml|"
                           r"\.gemini/settings\.json|\.cursor/(mcp|rules)|\.mcp\.json|claude_desktop_config\.json",
     "touches the agent's own settings, hooks or MCP config"),
    ("ssh-authorized-keys", HIGH, r"authorized_keys", "can grant remote SSH access"),
    ("privilege", MEDIUM, r"(?<![\w-])sudo\s", "asks for root"),
    ("destructive", HIGH, r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*['\"]?(/|~|\$HOME|\$\{HOME\})['\"]?(\s|$|/\*)|"
                          r"(^|[;&|(]\s*|\$\(\s*|`)(sudo\s+)?(mkfs(\.\w+)?\s+(-\S+\s+)*/dev/|dd\s+if=\S+\s+of=/dev/)|:\(\)\s*\{\s*:\|:&\s*\};:", "can destroy data"),
    ("runtime-install", LOW, r"\b(pip3?|npm|pnpm|yarn|gem|cargo)\s+(install|add|i)\b|\bgo\s+(install|get)\b|\bnpx\s+(-y\s+)?[@\w]",
     "installs packages at runtime"),
    # instructions aimed at the agent
    ("injection", HIGH, r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(of\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|"
                        r"preceding|system|original)\s+(instructions?|rules|prompts?|directions|guidelines|messages?)",
     "tries to override the agent's instructions"),
    ("conceal-from-user", HIGH, r"\b(do\s+not|don'?t|never)\s+(tell|inform|notify|alert)\s+the\s+user\s*([.,;:!]|$|\b(about|that\s+you|what\s+you|"
                                r"you\s+(ran|did|have)|this|it)\b)|\b(never|don'?t|do\s+not)\s+(mention|reveal|show)\s+(it|this|that)\s+to\s+the\s+user\b|\b(hide|conceal)\s+(it|this|that)?\s*from\s+the\s+user\b|"
                                r"\bwithout\s+the\s+user\s+(knowing|noticing)\b", "tells the agent to hide something from you"),
    ("skip-confirmation", HIGH, r"\b(do\s+not|don'?t|never|no\s+need\s+to)\s+ask\s+(the\s+user\s+)?(for\s+)?(permission|confirmation|approval|consent)\b",
     "tells the agent not to ask you"),
    ("claims-user-approval", HIGH, r"\b(this\s+skill|the\s+skill|it|installation|installing\s+it|everything)\s+(is|has\s+been|was)\s+"
                                   r"(already\s+)?(pre-?approved|approved|authori[sz]ed)\b|\b(pre-?approved|authori[sz]ed)\s+by\s+the\s+user\b|"
                                   r"\b(the\s+)?user\s+(has\s+)?(already\s+)?(pre-?approved|approved|authori[sz]ed|consented\s+to|"
                                   r"agreed\s+to)\s+(this|it|the\s+install|installing|running)\b|"
                                   r"\bno\s+(need\s+for|further)\s+(user\s+)?(approval|consent|confirmation)\b",
     "claims consent the user never gave"),
    ("airlock-override", HIGH, r"\b(airlock|dock|vent)\b[^\n]{0,80}--force\b|--force\b[^\n]{0,80}\b(airlock|dock)\b",
     "tells the agent to override skill-airlock's own checks"),
    ("without-asking", MEDIUM, r"\b(run|proceed|execute|install|delete|remove|send|upload|continue|apply|push|commit|overwrite|dock|use|"
                               r"enable|download|fetch|modify|write|edit|change|grant|approve|accept|allow|start|launch|"
                               r"do\s+(it|this|so))\b[^.\n]{0,60}\bwithout\s+(asking|confirmation|confirming|approval|permission)\b|"
                               r"^\W*without\s+(asking|confirmation|confirming)\b", "tells the agent to act without asking"),
    ("permission-bypass", HIGH, r"dangerously-?skip-?permissions|dangerouslyDisableSandbox|bypassPermissions|--yolo\b|auto-?approve\s+all",
     "turns off the agent's permission checks"),
    ("role-override", HIGH, r"\byou\s+are\s+now\s+(in\s+)?(an?\s+)?(unrestricted|jailbroken|developer\s+mode|dan\b|god\s+mode)|"
                            r"\b(here\s+(is|are)|this\s+is)\s+(your|the)\s+(new|updated|real)\s+system\s+(prompt|instructions)\b|"
                            r"\byour\s+(new|real|true)\s+instructions\s+are\b", "tries to change the agent's role"),
    ("fake-system-tag", MEDIUM, r"</?\s*(system|system-reminder|system_prompt|admin|developer)\s*>", "imitates a system message"),
    ("exfil-instruction", MEDIUM, r"\b(send|upload|post|transmit|exfiltrate|forward|email|paste)\b[^\n]{0,80}\b(api[\s_-]?keys?|tokens?|"
                                  r"credentials?|passwords?|secrets?|\.env\b|ssh\s+keys?|private\s+keys?|cookies|environment\s+variables)\b",
     "talks about sending secrets somewhere"),
]
COMPILED = [(r, s, re.compile(p, re.IGNORECASE if r in INSTRUCTION_RULES else 0), n) for r, s, p, n in LINE_RULES]
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Kept narrow on purpose: generic words ("sync", "keys", "server") must not excuse network or credential use.
NET_WORDS = re.compile(r"\b(api|apis|http|https|web|website|url|urls|download|upload|fetch|online|internet|cloud|remote|"
                       r"github|gitlab|slack|discord|email|e-mail|webhook|deploy|browse|browser|scrape|crawl|endpoint|"
                       r"network)s?\b", re.IGNORECASE)
CONFIG_WORDS = re.compile(r"\b(hooks?|settings|config|configure|configuration|plugins?|mcp|claude\s+code|agents?|subagents?|"
                          r"automations?|permissions?|skills?)\b", re.IGNORECASE)
SECRET_WORDS = re.compile(r"\b(credentials?|(access|api|auth|bearer|github|oauth)\s+tokens?|secrets?|auth|oauth|authentication|"
                          r"ssh|passwords?|keychain|vault|"
                          r"api[\s_-]?keys?|private\s+keys?|dotenv)\b|\.env\b", re.IGNORECASE)


def parse_frontmatter(text):
    """Tiny YAML-subset reader for SKILL.md frontmatter. Returns (dict, body_start_line_index)."""
    lines = text.splitlines()
    if not lines or lines[0].strip().lstrip("\ufeff") != "---":
        return {}, 0
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, 0
    meta, key, block, style = {}, None, None, ">"
    for raw in lines[1:end]:
        if block is not None:
            if raw.startswith((" ", "\t")) or not raw.strip():
                block.append(raw.strip())
                continue
            meta[key] = (" " if style == ">" else "\n").join(x for x in block if x or style == "|").strip()
            block = None
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", raw)
        if not m:
            if key and raw.startswith((" ", "\t")) and isinstance(meta.get(key), str):
                meta[key] = (meta[key] + " " + raw.strip()).strip()
            continue
        key, val = m.group(1), m.group(2).strip()
        if val in (">", ">-", ">+", "|", "|-", "|+"):
            block, style = [], val[0]
            continue
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        meta[key] = val
    if block is not None:
        meta[key] = (" " if style == ">" else "\n").join(x for x in block if x or style == "|").strip()
    return meta, end + 1


def tokens(text):
    """Rough token estimate (chars / 4); stdlib has no tokenizer."""
    return (len(text) + 3) // 4


def sanitize(text, limit=160):
    """Make an excerpt safe to print: invisible and control characters become <U+XXXX>."""
    out = []
    for ch in text.strip():
        cp = ord(ch)
        if ch in "\t\r\n":
            out.append(" ")
        elif cp in ZERO_WIDTH or cp in BIDI or cp in TAGS or unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cn"):
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _hidden_chars(line):
    zw = sorted({ord(c) for c in line if ord(c) in ZERO_WIDTH})
    bidi = sorted({ord(c) for c in line if ord(c) in BIDI})
    tagged = "".join(chr(ord(c) - 0xE0000) for c in line if ord(c) in TAGS)
    return zw, bidi, tagged


_SELF = None


def _self_hashes():
    """sha256 of this auditor's own code, so its rule tables don't flag themselves.
    Only byte-identical copies match, so another skill can't borrow the exemption for its own code."""
    global _SELF
    if _SELF is None:
        here = os.path.dirname(os.path.abspath(__file__))
        _SELF = set()
        for name in ("_audit.py", "airlock"):
            try:
                with open(os.path.join(here, name), "rb") as fh:
                    _SELF.add(hashlib.sha256(fh.read()).hexdigest())
            except OSError:
                pass
    return _SELF


def instruction_hits(text):
    """Instruction rules that match a piece of catalog text (name or description)."""
    return sorted({r for r, _, rx, _ in COMPILED if r in INSTRUCTION_RULES and rx.search(text)})


def _quoted(line, start):
    """True when a match sits inside backticks or right after an opening quote."""
    before = line[:start]
    return before.count("`") % 2 == 1 or before.rstrip(" (")[-1:] in ("\"", "'", "\u201c", "\u2018")


def _is_comment(line):
    t = line.lstrip()
    return t.startswith(("#", "//", "/*", "* ", "-- ", "<!--")) and not t.startswith("#!")


def _declared(rule, desc):
    """The description says the skill does this, so it is expected rather than hidden."""
    if rule in ("network", "raw-ip"):
        return bool(NET_WORDS.search(desc))
    if rule in ("secret-path", "dotenv", "env-dump", "secret-env"):
        return bool(SECRET_WORDS.search(desc))
    if rule == "agent-config":
        return bool(CONFIG_WORDS.search(desc))
    return False


def _read_meta(root):
    skill_md = os.path.join(root, "SKILL.md")
    if not os.path.isfile(skill_md) or os.path.islink(skill_md):
        return None, 0, ""
    with open(skill_md, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    meta, body_start = parse_frontmatter(text)
    return meta, body_start, text


def _remote_fetches(text):
    """(line, url, is_instructions) for each URL the SKILL.md tells the agent to fetch (verb within 3 lines)."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        for m in REMOTE_URL.finditer(line):
            verb_lines = [l for l in lines[max(0, i - 3):i + 4] if FETCH_VERB.search(l)]
            if verb_lines:
                instr = bool(INSTRUCTION_FILE.search(m.group(0))) or any(FETCHES_INSTRUCTIONS.search(l) for l in [line] + verb_lines)
                out.append((i + 1, m.group(0), instr))
    return out


def _is_script(path, text):
    ext = os.path.splitext(path)[1].lower()
    return ext in SCRIPT_EXT or text.startswith("#!")


def audit(root):
    """Audit one skill directory. Returns a report dict (see render())."""
    root = os.path.abspath(root)
    real_root = os.path.realpath(root)
    findings, files, scripts = [], [], []
    counts_per_rule = {}
    meta, body_start, skill_text = _read_meta(root)
    desc = (meta or {}).get("description", "")
    rules_by_file = {}

    def add(sev, rule, rel, line, excerpt, note):
        key = (rule, rel)
        counts_per_rule[key] = counts_per_rule.get(key, 0) + 1
        if counts_per_rule[key] > MAX_PER_RULE_PER_FILE:
            return
        findings.append({"severity": sev, "rule": rule, "file": rel, "line": line,
                         "excerpt": sanitize(excerpt), "note": note})

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                filenames.append(d)          # report symlinked dirs like symlinked files
                dirnames.remove(d)
            elif d in SKIP_DIRS:
                dirnames.remove(d)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                target = os.path.realpath(full)
                inside = target == real_root or target.startswith(real_root + os.sep)
                add(LOW if inside else HIGH, "symlink" if inside else "symlink-outside", rel, 0,
                    f"-> {os.readlink(full)}", "symlink" if inside else "symlink pointing outside the skill")
                continue
            if not os.path.isfile(full):
                add(MEDIUM, "special-file", rel, 0, name, "not a regular file (fifo, device or socket)")
                continue
            files.append(rel)
            if name.startswith(".") and name not in BENIGN_DOTFILES:
                add(LOW, "hidden-file", rel, 0, name, "hidden file")
            size = os.path.getsize(full)
            if size > MAX_BYTES:
                add(MEDIUM, "large-file", rel, 0, f"{size} bytes", "too large to scan; review by hand")
                continue
            with open(full, "rb") as fh:
                data = fh.read()
            ext = os.path.splitext(name)[1].lower()
            if hashlib.sha256(data).hexdigest() in _self_hashes():
                add(LOW, "self", rel, 0, name, "skill-airlock's own code (byte-identical); rule tables not scanned")
                continue
            if b"\x00" in data[:8192]:
                add(LOW if ext in ASSET_EXT else MEDIUM, "binary-asset" if ext in ASSET_EXT else "binary", rel, 0,
                    f"{size} bytes", "binary file; cannot be reviewed as text")
                continue
            text = data.decode("utf-8", errors="replace")
            is_script = _is_script(name, text)
            if is_script:
                scripts.append(rel)
            file_rules = {}
            is_md = ext in (".md", ".markdown")
            is_skill_md = rel == "SKILL.md"
            in_fence = False
            for no, line in enumerate(text.splitlines(), 1):
                if no == 1 and line.startswith("\ufeff"):
                    line = line[1:]
                scan = line[:MAX_LINE]
                zw, bidi, tagged = _hidden_chars(scan)
                if zw:
                    fence = FENCE_ESCAPE.match(scan)
                    hidden = sum(1 for c in scan if ord(c) in ZERO_WIDTH)
                    if fence and not is_skill_md and hidden == sum(1 for c in fence.group(1) if ord(c) in ZERO_WIDTH):
                        add(LOW, "hidden-unicode", rel, no, scan, "zero-width character escaping a code fence (template idiom)")
                    else:
                        add(HIGH, "hidden-unicode", rel, no, scan,
                            "invisible characters: " + ", ".join(f"U+{c:04X}" for c in zw))
                if bidi:
                    add(HIGH, "bidi-control", rel, no, scan, "bidirectional controls can make text read differently than it runs")
                if tagged:
                    add(HIGH, "unicode-tags", rel, no, "hidden text decoded: " + tagged, "invisible Unicode tag characters carry hidden text")
                if is_md and scan.lstrip().startswith(("```", "~~~")):
                    in_fence = not in_fence
                    continue
                # SKILL.md is the agent's instructions, prose included. Other Markdown is reference
                # material: outside fenced blocks it describes rather than instructs.
                descriptive = (is_md and not in_fence and not is_skill_md) or (not is_md and _is_comment(scan))
                line_rules = set()
                for rule, sev, rx, note in COMPILED:
                    m = rx.search(scan)
                    if not m:
                        continue
                    if rule in INSTRUCTION_RULES:
                        if _quoted(scan, m.start()) and (descriptive or is_skill_md):
                            sev = LOW if descriptive else (MEDIUM if sev == HIGH else sev)
                            note += " (quoted mention)"
                    elif descriptive:
                        sev = DOWNGRADE[sev]
                    if _declared(rule, desc):
                        sev, note = DOWNGRADE[sev], note + " (declared in the description)"
                    add(sev, rule, rel, no, scan, note)
                    if not descriptive:
                        line_rules.add(rule)
                    if is_script and not _is_comment(scan):
                        file_rules.setdefault(rule, no)
                if line_rules & NETWORK_RULES and line_rules & SECRET_RULES:
                    add(HIGH, "exfil-pattern", rel, no, scan, "reads secrets and sends them in the same command")
            if ext in (".md", ".markdown"):
                for m in re.finditer(r"<!--(.*?)-->", text, re.S):
                    body = " ".join(m.group(1).split())
                    if len(body.split()) >= 4:
                        loud = any(rx.search(body) for _, _, rx, _ in COMPILED)
                        add(MEDIUM if loud else LOW, "html-comment", rel, text.count("\n", 0, m.start()) + 1, body,
                            "HTML comment: invisible when rendered, read by the agent")
            if file_rules:
                rules_by_file[rel] = file_rules
            net = [r for r in file_rules if r in NETWORK_RULES]
            sec = [r for r in file_rules if r in SECRET_RULES]
            if net and sec:
                add(HIGH, "exfil-pattern", rel, file_rules[sec[0]],
                    f"{', '.join(sorted(sec))} + {', '.join(sorted(net))}", "reads secrets and uses the network in the same file")

    body_tokens = 0
    if meta is None:
        meta = {}
        add(MEDIUM, "no-skill-md", "SKILL.md", 0, "missing", "no SKILL.md: not a skill, or a broken one")
    else:
        text = skill_text
        body_tokens = tokens("\n".join(text.splitlines()[body_start:]))
        if not meta.get("name") or not meta.get("description"):
            add(MEDIUM, "frontmatter", "SKILL.md", 1, "name/description missing", "frontmatter lacks name or description")
        elif len(meta["description"]) < 40:
            add(LOW, "vague-description", "SKILL.md", 1, meta["description"], "description too short to judge what it does")
        for no, url, is_instructions in _remote_fetches(text):
            if is_instructions:
                add(MEDIUM, "remote-instructions", "SKILL.md", no, url,
                    "tells the agent to fetch its instructions at run time; what it follows was never audited and can change")
            else:
                add(LOW, "remote-content", "SKILL.md", no, url, "loads reference material from the network at run time")
        if meta.get("name") and not SAFE_NAME.match(meta["name"]):
            add(MEDIUM, "unsafe-name", "SKILL.md", 1, meta["name"],
                "frontmatter name is not a valid skill name (may carry text aimed at the agent); cannot be installed")
        if text.count("\n") > 500:
            add(LOW, "oversized", "SKILL.md", 0, f"{text.count(chr(10))} lines", "SKILL.md over 500 lines; costs context on every use")

    sec_files = sorted(f for f, rs in rules_by_file.items() if set(rs) & SECRET_RULES)
    net_files = sorted(f for f, rs in rules_by_file.items() if set(rs) & NETWORK_RULES)
    if sec_files and net_files and not set(sec_files) & set(net_files):
        # Split across scripts so no single file looks like exfiltration. Declared words don't excuse this.
        first = min(rules_by_file[sec_files[0]][r] for r in rules_by_file[sec_files[0]] if r in SECRET_RULES)
        add(HIGH, "exfil-pattern", sec_files[0], first, f"secrets in {', '.join(sec_files)}; network in {', '.join(net_files)}",
            "reads secrets in one script and uses the network in another")
    # Declared-vs-actual checks look at real script code only: comments and docs don't run.
    def first_hit(files, ruleset):
        f = files[0]
        return f, min(rules_by_file[f][r] for r in rules_by_file[f] if r in ruleset)

    if net_files and not NET_WORDS.search(desc):
        f, line = first_hit(net_files, NETWORK_RULES)
        add(MEDIUM, "mismatch-network", f, line, desc or "(no description)",
            "scripts use the network but the description never says so")
    if sec_files and not SECRET_WORDS.search(desc):
        f, line = first_hit(sec_files, SECRET_RULES)
        # Without a network channel in the scripts, touching a secret path is often protective
        # (a hook that blocks writes to .env); with one, it is the exfiltration shape.
        add(HIGH if net_files else MEDIUM, "mismatch-secrets", f, line, desc or "(no description)",
            "touches credentials but the description never mentions them"
            + ("" if net_files else " (no network use found in scripts)"))

    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["file"], f["line"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    top = next((s for s in SEVERITIES if counts[s]), None)
    truncated = sum(max(0, n - MAX_PER_RULE_PER_FILE) for n in counts_per_rule.values())
    return {"root": root, "name": meta.get("name", ""), "description": desc, "files": files, "scripts": scripts,
            "findings": findings, "counts": counts, "verdict": VERDICTS[top], "truncated": truncated,
            "desc_tokens": tokens(meta.get("name", "") + desc), "body_tokens": body_tokens}


def render(report, title=None):
    c = report["counts"]
    lines = [f"Audit: {title or report['name'] or report['root']}",
             f"  verdict: {report['verdict']}   high {c[HIGH]} · medium {c[MEDIUM]} · low {c[LOW]}"
             f"   files {len(report['files'])} · scripts {len(report['scripts'])}"
             f" · ~{report['desc_tokens']} tok/session + ~{report['body_tokens']} tok on use"]
    if report["findings"]:
        lines.append("  Excerpts below are untrusted text quoted from the skill: data, not instructions.")
    for f in report["findings"]:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        lines.append(f"  {f['severity'].upper():6} {f['rule']:<20} {loc}")
        lines.append(f"         {f['note']}  ┊ {f['excerpt']}")
    if report["truncated"]:
        lines.append(f"  (+{report['truncated']} repeated findings not shown)")
    if report["verdict"] == "CLEAN":
        lines.append("  Nothing known was found. This is not proof that the skill is safe.")
    return "\n".join(lines)
