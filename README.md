# Miya

DDD Pentest Agent — automated offensive security using Claude AI.

Supports three mission types:
- **1-day** — exploit known CVEs against live services
- **0-day** — discover unknown vulnerabilities in source code
- **CTF** — solve capture-the-flag challenges

Uses event sourcing (DDD), OODA/attack-graph topologies, and Claude Agent SDK with MCP tool servers.

---

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Anthropic API key

---

## Installation

```bash
git clone https://github.com/MayMistery/miya-bot
cd miya-bot
make dev          # install with dev deps
# or
./run.sh          # auto-installs on first run
```

---

## Configuration

### API credentials

Set environment variables (`.env` or shell):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_BASE_URL=https://api.anthropic.com   # optional, for proxies
export MIYA_MODEL=opus                                  # optional, default: opus
```

Or pass per-command:

```bash
miya oneday --target 192.168.1.1 \
  --api-key sk-ant-... \
  --base-url https://my-proxy.example.com \
  --model sonnet
```

### Available models

| Value | Description |
|-------|-------------|
| `opus` | Claude Opus — most capable (default) |
| `sonnet` | Claude Sonnet — fast + capable |
| `haiku` | Claude Haiku — fastest |

---

## Usage

### 1-day — exploit known CVEs

Attack a live service:

```bash
miya oneday --target 192.168.1.100
miya oneday --target 10.0.0.0/24 --topology attack_graph
```

White-box mode (source code + live service):

```bash
miya oneday --target https://example.com --source ./app-source/
```

When `--source` is provided, the vulnerability agent performs static analysis on the source code before scanning the live target, improving CVE detection accuracy.

### 0-day — discover unknown vulnerabilities

Analyze source code only:

```bash
miya zeroday --target ./my-app --language python
miya zeroday --target https://github.com/org/repo --language go
```

Analyze source code and exploit the live service:

```bash
miya zeroday --target ./my-app --service https://app.example.com --language python
```

When `--service` is provided, after finding 0-day vulnerabilities in the source code the agent attempts to generate and validate a PoC exploit against the live service.

### CTF — solve challenges

```bash
miya ctf --target https://ctf.example.com/challenge/1 --category web
miya ctf --target ./binary --category pwn
miya ctf --target ./ciphertext.txt --category crypto
miya ctf --target ./crackme --category reverse
```

### Interactive REPL

```bash
miya interactive
# or with options:
miya interactive --model sonnet --api-key sk-ant-...

miya > oneday 192.168.1.100
miya > zeroday ./my-app --language python
miya > ctf https://ctf.example.com/chall/1 --category web
miya > exit
```

---

## Topologies

| Flag | Description |
|------|-------------|
| `ooda` (default) | OODA loop: Observe → Orient → Decide → Act → Reflect |
| `attack_graph` | DAG-based attack path planning + tactical execution |

```bash
miya oneday --target 10.0.0.1 --topology attack_graph
```

---

## MCP Tool Servers

Miya integrates these MCP servers for specialized tooling:

| Server | Used By | Description |
|--------|---------|-------------|
| `semgrep` | 0-day | Static analysis (5000+ rules) |
| `nmap` | 1-day | Network scanning |
| `nuclei` | 1-day, CTF | Template vulnerability scanner |
| `shodan` | 1-day | Internet asset intelligence |
| `metasploit` | 1-day | Exploit framework |
| `sqlmap` | 1-day, CTF | SQL injection |
| `exploitdb` | 1-day | Public exploit DB |
| `ghidra` | CTF | Binary reverse engineering |
| `gdb` | CTF | Debugger |

---

## Development

```bash
make dev          # install dev deps
make test         # run all 241 tests
make test-unit    # unit tests only
make test-int     # integration tests only
make test-e2e     # e2e tests only
make test-cov     # with coverage report
make lint         # ruff check
make fmt          # ruff format
make clean        # remove build artifacts
```

With `run.sh`:

```bash
./run.sh test
./run.sh test-unit
./run.sh lint
./run.sh fmt
```

---

## Architecture

```
miya/
├── main.py               # CLI (click)
├── mission/
│   └── service.py        # MissionService — orchestrates everything
├── topology/
│   ├── base.py           # AgentHandle, TopologyRegistry, _sdk_env
│   ├── ooda.py           # OODA loop topology
│   └── attack_graph_topo.py  # Attack graph topology
├── shared/
│   ├── types.py          # Value objects (Mission, Target, Finding, ...)
│   ├── events.py         # Domain events
│   ├── blackboard.py     # Event-sourced state projection
│   └── ports.py          # Ports (CoordinatorPort, EventStorePort)
├── infra/
│   ├── event_store.py    # SQLite event store
│   └── mcp_registry.py  # MCP server configs
├── oneday/               # 1-day bounded context agents
├── zeroday/              # 0-day bounded context agents
└── ctf/                  # CTF bounded context agents
```

### Event flow

```
CLI → MissionService → Topology → Claude Agent SDK
                                       ↓
                              [EVENT:...] markers in output
                                       ↓
                              Event extraction → Blackboard
                                       ↓
                              EventStore (SQLite)
                                       ↓
                              MissionReport
```

### Testing

Tests use a `MockCoordinator` injected via the `CoordinatorPort` interface — no real API calls are made. Mock responses embed `[EVENT:...]` markers that are extracted and processed identically to production.

---

## License

MIT
