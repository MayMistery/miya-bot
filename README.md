# Miya

Miya is a local CLI for running authorized security missions with Claude Agent
SDK. It coordinates specialist agents, records structured domain events, and
keeps a shared blackboard so each phase can build on previous findings.

It supports three mission types:

- `oneday`: assess known CVEs and exploit paths against a live target
- `zeroday`: inspect a codebase for unknown vulnerabilities and optional PoC validation
- `ctf`: solve single challenges or multi-challenge CTF sets

Use Miya only on systems you own or are explicitly authorized to test.

## Requirements

- Python 3.10 or newer
- `uv`
- Anthropic credentials, unless your Claude Agent SDK environment supplies auth
- Optional security tools on `PATH` for missions that need them, such as
  `semgrep`, `nmap`, `nuclei`, `sqlmap`, `ghidra`, or `gdb`

Install `uv` if needed:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Install

The installer clones the repo into `~/miya-bot`, syncs dependencies, and places
the `miya` command on your `PATH`.

```bash
curl -fsSL https://raw.githubusercontent.com/MayMistery/miya-bot/main/install.sh | bash
```

For local development:

```bash
git clone https://github.com/MayMistery/miya-bot
cd miya-bot
make install-dev
uv run miya --help
```

Update an installed checkout:

```bash
miya update
# or
make update
```

## Configure

Set credentials in the shell or in a local `.env` file:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_BASE_URL=https://api.anthropic.com
export MIYA_MODEL=opus
```

Every mission command also accepts per-run overrides:

```bash
miya oneday \
  --target https://example.com \
  --api-key sk-ant-... \
  --base-url https://proxy.example.com \
  --model sonnet
```

Supported model shortcuts are `opus`, `sonnet`, and `haiku`.

## Commands

```bash
miya --help
miya health
miya info
miya interactive
miya oneday --target <host|url|cidr>
miya zeroday --target <path|repo-url>
miya ctf --target <url|file>
```

Common options:

- `--model`, `--api-key`, `--base-url`: Claude runtime settings
- `--topology`: `ooda`, `attack_graph`, or `fanout`
- `--db`: SQLite event database path
- `--unlimited`: disable mission timeouts and iteration limits
- `--prompt`: operator instructions for the mission

## Mission Examples

Run a 1-day mission against a live service:

```bash
miya oneday --target 192.168.1.100
miya oneday --target https://app.example.com --topology attack_graph
```

Add source code for white-box context:

```bash
miya oneday --target https://app.example.com --source ./app-source
```

Analyze a codebase for 0-day issues:

```bash
miya zeroday --target ./service --language python
miya zeroday --target https://github.com/org/repo --language go
```

Analyze source and validate against a running service:

```bash
miya zeroday --target ./service --service https://staging.example.com
```

Solve CTF challenges:

```bash
miya ctf --target https://ctf.example.com/challenge/1 --category web
miya ctf --target ./vuln --category pwn
miya ctf --target ./ciphertext.txt --category crypto
miya ctf --target ./crackme --category reverse
```

## Interactive Mode

The REPL keeps mission history, runtime configuration, events, and blackboard
state available across commands.

```bash
miya interactive
```

Typical session:

```text
miya (opus) > set model sonnet
miya (sonnet) > set topology attack_graph
miya (sonnet) > oneday https://app.example.com --source ./app
miya (sonnet) > zeroday ./service --language python
miya (sonnet) > ctf ./challenge.zip --category misc
miya (sonnet) > status
miya (sonnet) > events
miya (sonnet) > blackboard
miya (sonnet) > info
miya (sonnet) > exit
```

## Topologies

| Topology | Use it when |
| --- | --- |
| `ooda` | You want a focused Observe -> Orient -> Decide -> Act loop with reflection. |
| `attack_graph` | You want path planning across assets, vulnerabilities, and access states. |
| `fanout` | You have multiple CTF challenges and want parallel per-challenge solving. |

## MCP Tools

Miya can pass MCP server configs to Claude Agent SDK when a mission needs
external tools. Tool availability is checked at runtime.

| Tool | Used by | Purpose |
| --- | --- | --- |
| `semgrep` | 0-day | Static analysis |
| `nmap` | 1-day | Host and service discovery |
| `nuclei` | 1-day, CTF | Template-based scanning |
| `shodan` | 1-day | Internet asset intelligence |
| `metasploit` | 1-day | Exploit framework integration |
| `sqlmap` | 1-day, CTF | SQL injection testing |
| `exploitdb` | 1-day | Public exploit lookup |
| `ghidra` | CTF | Reverse engineering |
| `gdb` | CTF | Debugging |
| `sage` | CTF | Math and crypto support |
| `factordb` | CTF | Integer factorization lookup |
| `cyberchef` | CTF | Encoding and transform chains |
| `binwalk` | CTF | Firmware and file analysis |
| `exiftool` | CTF | Metadata extraction |

## How It Works

Miya treats each state change as a domain event. Agents emit `[EVENT:...]`
markers, Miya parses those markers, updates the blackboard, and persists the
event stream in SQLite.

```text
CLI
  -> MissionService
  -> Topology
  -> Claude Agent SDK
  -> [EVENT:...] output
  -> Blackboard projection
  -> SQLite EventStore
  -> MissionReport
```

Main packages:

```text
miya/
  main.py                 CLI entrypoint
  mission/service.py      Mission orchestration
  topology/               OODA, attack graph, and fanout execution
  shared/events.py        Domain event model
  shared/blackboard.py    Event-sourced mission state
  infra/event_store.py    SQLite event persistence
  infra/mcp_registry.py   MCP server definitions
  oneday/                 1-day bounded contexts
  zeroday/                0-day bounded contexts
  ctf/                    CTF bounded contexts
```

## Development

```bash
make install-dev
make lint
make test-unit
make test
```

Useful direct commands:

```bash
uv run ruff check miya tests
uv run pytest tests/unit -v --tb=short
uv run miya health
```

Tests inject mock coordinators through the coordinator interface, so unit tests
do not require real Claude API calls.

## License

MIT
