# Miya — DDD Pentest Agent 设计文档

> **版本**: v2.0 draft
> **日期**: 2026-03-17
> **状态**: 待讨论

---

## 1. 系统愿景

Miya 是一个基于 DDD 战术设计 + Claude Agent SDK 编排的渗透测试 Agent 系统。
三种任务类型（Mission）：**挖掘 0-day**、**利用 1-day**、**解 CTF 题目**。
每种 Mission 有独立的限界上下文划分逻辑，共享统一的编排拓扑引擎和事件溯源基础设施。

**设计原则**：
- **领域纯净**：核心领域模型不依赖任何基础设施（Claude SDK、MCP、SQLite）
- **拓扑可插拔**：编排策略通过策略模式+注册表切换，不修改领域代码
- **工具外挂**：所有安全工具通过开源 MCP 服务器集成，零自研 MCP
- **事件溯源**：所有状态变更以领域事件形式持久化到 SQLite，支持回放和审计

---

## 2. 编排拓扑引擎

### 2.1 设计：策略模式 + 注册表

```
┌─────────────────────────────────────────────────────┐
│                 TopologyRegistry                    │
│  register(name, factory) / get(name) → Topology     │
│                                                     │
│  内置:                                              │
│    "ooda"          → OODATopology                   │
│    "attack_graph"  → AttackGraphTopology            │
│                                                     │
│  扩展: 用户可 registry.register("custom", factory)   │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────▼────────────────┐
          │     Topology (Protocol)     │
          │                             │
          │  async execute(mission,     │
          │    blackboard, agents)      │
          │    → AsyncIterator[Event]   │
          │                             │
          │  @property                  │
          │  name: str                  │
          └────────────┬────────────────┘
                       │
          ┌────────────┼────────────────┐
          │            │                │
    ┌─────▼─────┐ ┌───▼──────┐  ┌──────▼──────┐
    │   OODA    │ │ Attack   │  │  Future...  │
    │ Topology  │ │ Graph    │  │             │
    └───────────┘ └──────────┘  └─────────────┘
```

### 2.2 OODA 拓扑

```
            ┌─────────────────────────────────┐
            │         OODA Controller         │
            └──────────┬──────────────────────┘
                       │
    ┌──────────────────┼──────────────────────┐
    │                  │                      │
    ▼                  ▼                      ▼
┌────────┐      ┌───────────┐          ┌──────────┐
│OBSERVE │      │  ORIENT   │          │  DECIDE  │
│        │─────▶│           │─────────▶│          │
│侦察收集 │      │分析研判    │          │制定计划   │
└────────┘      └───────────┘          └────┬─────┘
                                            │
                                            ▼
                                       ┌──────────┐
                                       │   ACT    │
                                       │          │
                                       │执行+反思  │
                                       └────┬─────┘
                                            │
                                    ┌───────▼───────┐
                                    │  Reflection   │
                                    │  Gate         │
                                    │               │
                                    │ 成功? → 继续   │
                                    │ 失败? → 回OBSERVE│
                                    │ 完成? → 结束   │
                                    └───────────────┘
```

**关键机制**：
- 每个阶段产生领域事件写入 Blackboard
- Reflection Gate 在 ACT 后强制反思：结果是否符合预期？是否需要调整方向？
- OODA 循环可嵌套：宏观 OODA（整体任务）包含微观 OODA（单个攻击步骤）

### 2.3 AttackGraph 拓扑

```
    ┌────────────────────────────────────────┐
    │         Strategic Planner             │
    │  输入: AttackGraph(当前状态)            │
    │  输出: AttackPath(最优路径)             │
    └──────────────┬─────────────────────────┘
                   │ path = [step1, step2, ...]
                   ▼
    ┌────────────────────────────────────────┐
    │         Tactical Executor             │
    │  按 path 顺序执行每个 step:            │
    │    1. 选择对应 Agent                   │
    │    2. 执行 Agent                       │
    │    3. 结果写入 AttackGraph              │
    │    4. 如果图拓扑变化 → 触发 Re-plan     │
    └──────────────┬─────────────────────────┘
                   │
    ┌──────────────▼─────────────────────────┐
    │          AttackGraph (DAG)             │
    │                                        │
    │  Node = AssetState(host+权限+已知信息)  │
    │  Edge = Technique(ATT&CK ID + 成本)    │
    │                                        │
    │  动态更新:                              │
    │    发现新资产 → 添加 Node               │
    │    发现新漏洞 → 添加 Edge               │
    │    利用成功   → 更新 Node 状态          │
    └────────────────────────────────────────┘
```

**关键机制**：
- Planner 在图上搜索最优路径（最低成本、最高成功率）
- 每次执行后检查图拓扑变化，变化则 re-plan
- 图的节点/边标注 MITRE ATT&CK 战术/技术 ID

### 2.4 Blackboard（两种拓扑共用）

```python
class Blackboard:
    """跨 Agent 共享知识库 — 所有拓扑的公共状态层"""

    # 资产发现
    assets: dict[str, Asset]          # host/service/endpoint
    # 漏洞发现
    vulnerabilities: dict[str, Vulnerability]
    # 凭据收集
    credentials: list[Credential]
    # 攻击图
    attack_graph: AttackGraph
    # 事件流（EventStore 的内存投影）
    events: list[DomainEvent]

    def project_from(self, event_store: EventStore) -> None: ...
```

---

## 3. 限界上下文设计

### 3.1 总览：三种 Mission，三套限界上下文

```
┌─────────────────────────────────────────────────────────────────┐
│                        Miya System                              │
│                                                                 │
│  ┌─── Shared Kernel ──────────────────────────────────────────┐ │
│  │  Target, Finding, Severity, Credential, Asset              │ │
│  │  DomainEvent, EventStore, EventBus                         │ │
│  │  Blackboard, AttackGraph                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── Mission: 0-day ────────┐  按 API 调用链分层               │
│  │  EntryPoint (入口发现)     │                                 │
│  │  DataFlow   (数据流追踪)   │                                 │
│  │  Sink       (危险函数分析)  │                                 │
│  │  PoC        (证明构造)     │                                 │
│  └────────────────────────────┘                                │
│                                                                 │
│  ┌─── Mission: 1-day ────────┐  按杀伤链阶段分层               │
│  │  Recon      (侦察)        │                                 │
│  │  Scan       (扫描)        │                                 │
│  │  Vuln       (漏洞匹配)     │                                 │
│  │  Exploit    (漏洞利用)     │                                 │
│  │  Post       (后渗透)       │                                 │
│  └────────────────────────────┘                                │
│                                                                 │
│  ┌─── Mission: CTF ──────────┐  按题目类型分层                  │
│  │  Web        (Web安全)      │                                │
│  │  Pwn        (二进制利用)    │                                │
│  │  Crypto     (密码学)       │                                │
│  │  Reverse    (逆向工程)     │                                │
│  │  Misc       (杂项/取证)    │                                │
│  └────────────────────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Mission: 0-day（API 调用链分层）

**限界上下文 & 领域模型**：

#### 3.2.1 EntryPoint Context（入口发现）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `CodeBase` | Aggregate Root | 目标代码库，管理入口点集合 |
| `EntryPoint` | Entity | 一个外部可达的入口（HTTP handler, CLI parser, 消息处理器） |
| `InputVector` | Value Object | 入口的具体输入向量（param name, header, body field） |
| `EntryPointDiscovered` | Domain Event | 发现新入口时发布 |

**领域服务**：`EntryPointDiscoveryService` — 通过 Semgrep 规则 + AST 分析发现入口

**端口（Port）**：
- `CodeAnalyzerPort` — 代码分析能力抽象（适配器：Semgrep MCP）
- `EntryPointRepository` — 入口持久化

#### 3.2.2 DataFlow Context（数据流追踪）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `TaintSession` | Aggregate Root | 一次完整的污点追踪会话 |
| `TaintSource` | Value Object | 污染源（来自 EntryPoint 的 InputVector） |
| `TaintSink` | Value Object | 危险汇聚点（SQL执行, 命令执行, 内存操作等） |
| `TaintPath` | Entity | 从 source 到 sink 的一条数据流路径 |
| `Sanitizer` | Value Object | 路径上的过滤/消毒操作 |
| `TaintPathTraced` | Domain Event | 完成一条路径追踪 |

**领域服务**：`TaintAnalysisService` — 编排污点追踪流程

**端口**：
- `TaintEnginePort` — 污点分析引擎抽象（适配器：Semgrep MCP taint mode）
- `TaintSessionRepository`

#### 3.2.3 Sink Context（危险函数分析）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `SinkAnalysis` | Aggregate Root | 对一个 sink 的安全分析 |
| `SinkPattern` | Value Object | 危险模式（CWE-ID + 匹配规则） |
| `Exploitability` | Value Object | 可利用性评估（需要认证? 网络可达? 复杂度?） |
| `SinkConfirmed` | Domain Event | 确认 sink 可利用 |

**领域服务**：`SinkEvaluationService` — 评估 sink 的真实风险

#### 3.2.4 PoC Context（证明构造）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `PoCProject` | Aggregate Root | 一个 PoC 工程 |
| `PoCPayload` | Entity | 具体的利用载荷 |
| `PoCResult` | Value Object | 执行结果（成功/失败 + 证据） |
| `VulnerabilityProven` | Domain Event | PoC 验证成功 |

**领域服务**：`PoCGeneratorService`

**端口**：
- `SandboxPort` — 安全执行环境抽象
- `PoCRepository`

### 3.3 Mission: 1-day（杀伤链分层）

#### 3.3.1 Recon Context（侦察）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `ReconMission` | Aggregate Root | 一次侦察任务 |
| `Asset` | Entity | 发现的资产（IP, 域名, 服务） |
| `Fingerprint` | Value Object | 资产指纹（软件名+版本+OS+技术栈） |
| `ServiceBanner` | Value Object | 服务 Banner 信息 |
| `AssetDiscovered` | Domain Event | 发现新资产 |
| `FingerprintCompleted` | Domain Event | 指纹识别完成 |

**端口**：
- `NetworkScannerPort` — 网络扫描抽象（适配器：Nmap MCP）
- `AssetIntelPort` — 资产情报抽象（适配器：Shodan MCP）
- `AssetRepository`

#### 3.3.2 Scan Context（扫描）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `ScanTask` | Aggregate Root | 一次扫描任务 |
| `ScanTarget` | Value Object | 扫描目标（来自 Recon 的 Asset） |
| `ScanResult` | Entity | 扫描结果（发现的开放端口、服务、潜在漏洞） |
| `ScanCompleted` | Domain Event | 扫描完成 |

**端口**：
- `VulnScannerPort` — 漏洞扫描抽象（适配器：Nuclei MCP）
- `ScanRepository`

**ACL（反腐层）**：Recon → Scan 的 `Asset` 需通过 ACL 转换为 `ScanTarget`

#### 3.3.3 Vuln Context（漏洞匹配）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `VulnAssessment` | Aggregate Root | 漏洞评估会话 |
| `CVE` | Value Object | CVE 条目（ID + CVSS + 描述 + 影响范围） |
| `VulnMatch` | Entity | 一个资产与一个 CVE 的匹配关系 |
| `ExploitAvailability` | Value Object | 公开利用工具的可用性（ExploitDB, Metasploit, GitHub PoC） |
| `VulnMatched` | Domain Event | 漏洞匹配成功 |

**端口**：
- `CVEDatabasePort` — CVE 数据库抽象
- `ExploitDBPort` — 利用库搜索抽象（适配器：ExploitDB MCP）
- `VulnRepository`

#### 3.3.4 Exploit Context（漏洞利用）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `ExploitCampaign` | Aggregate Root | 一次利用行动 |
| `ExploitAttempt` | Entity | 单次利用尝试 |
| `Payload` | Value Object | 利用载荷（类型 + 内容 + 目标环境适配） |
| `ExploitChain` | Value Object | 多步利用链（有序步骤列表） |
| `ExploitResult` | Value Object | 利用结果（成功/失败 + 获得的访问级别） |
| `ExploitSucceeded` | Domain Event | 利用成功 |
| `ExploitFailed` | Domain Event | 利用失败 |

**端口**：
- `ExploitFrameworkPort` — 利用框架抽象（适配器：Metasploit MCP）
- `PayloadGeneratorPort` — 载荷生成抽象
- `ExploitRepository`

#### 3.3.5 Post Context（后渗透）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `PostSession` | Aggregate Root | 后渗透会话 |
| `AccessLevel` | Value Object | 当前访问级别（user/root/SYSTEM） |
| `LootItem` | Entity | 收集到的战利品（凭据、配置、数据） |
| `PivotTarget` | Value Object | 横向移动候选目标 |
| `PrivilegeEscalated` | Domain Event | 提权成功 |
| `LootCollected` | Domain Event | 收集到新战利品 |

**端口**：
- `C2Port` — 命令控制通道抽象
- `PostRepository`

### 3.4 Mission: CTF（题目类型分层）

#### 3.4.1 CTF Shared（CTF 共享子域）

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `Competition` | Aggregate Root | 一场 CTF 比赛 |
| `Challenge` | Entity | 一道题目 |
| `Flag` | Value Object | flag 字符串（含格式校验） |
| `WriteUp` | Value Object | 解题过程记录 |
| `ChallengeSolved` | Domain Event | 解题成功 |

#### 3.4.2 Web Context

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `WebChallenge` | Aggregate Root | Web 题目 |
| `HttpEndpoint` | Entity | 可攻击的 HTTP 端点 |
| `InjectionPoint` | Value Object | 注入点（参数名 + 注入类型 + payload） |
| `WebVulnType` | Enum | SQLi, XSS, SSTI, SSRF, LFI, Deserialization... |

**端口**：
- `WebScannerPort`（适配器：SQLMap MCP, Nuclei MCP）

#### 3.4.3 Pwn Context

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `PwnChallenge` | Aggregate Root | 二进制利用题目 |
| `Binary` | Entity | 目标二进制文件 |
| `Protection` | Value Object | 保护机制（NX, ASLR, PIE, Canary, RELRO） |
| `MemoryLayout` | Value Object | 内存布局信息 |
| `GadgetChain` | Value Object | ROP gadget 链 |
| `ExploitScript` | Entity | 利用脚本（pwntools 代码） |

**端口**：
- `DisassemblerPort`（适配器：GhidraMCP）
- `DebuggerPort`（适配器：GDB MCP）

#### 3.4.4 Crypto Context

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `CryptoChallenge` | Aggregate Root | 密码学题目 |
| `Cipher` | Value Object | 密码算法标识 + 参数 |
| `CryptoAttack` | Value Object | 攻击方法（Wiener, Hastad, Padding Oracle...） |
| `PlainText` | Value Object | 解密结果 |

#### 3.4.5 Reverse Context

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `ReverseChallenge` | Aggregate Root | 逆向题目 |
| `BinaryAnalysis` | Entity | 反编译分析结果 |
| `Algorithm` | Value Object | 识别出的算法（加密、校验、变换） |
| `Constraint` | Value Object | 提取的约束条件（用于 z3 求解） |

**端口**：
- `DisassemblerPort`（复用 GhidraMCP 适配器）

#### 3.4.6 Misc Context

| 概念 | DDD 类型 | 说明 |
|------|----------|------|
| `MiscChallenge` | Aggregate Root | 杂项题目 |
| `FileArtifact` | Entity | 文件样本（镜像、pcap、内存转储等） |
| `HiddenData` | Value Object | 隐写/嵌入数据 |

---

## 4. 六边形架构（端口与适配器）

```
                    ┌─────────────────────────────────┐
                    │       Application Service       │
                    │   (Mission Orchestration)        │
                    └──────────┬──────────────────────┘
                               │
            ┌──────────────────┼──────────────────────┐
            │                  │                      │
    ┌───────▼───────┐  ┌──────▼──────┐  ┌────────────▼──────────┐
    │  Domain Model │  │  Domain     │  │  Domain Events        │
    │  (Aggregates, │  │  Services   │  │  (EventStore,         │
    │   Entities,   │  │             │  │   EventBus)           │
    │   VOs)        │  │             │  │                       │
    └───────────────┘  └─────────────┘  └───────────────────────┘
            │                  │                      │
    ┌───────▼──────────────────▼──────────────────────▼──────────┐
    │                      Ports (interfaces)                    │
    │                                                            │
    │  CodeAnalyzerPort   NetworkScannerPort   DisassemblerPort  │
    │  TaintEnginePort    VulnScannerPort      DebuggerPort      │
    │  SandboxPort        ExploitFrameworkPort  CVEDatabasePort   │
    │  AssetIntelPort     ExploitDBPort         WebScannerPort    │
    │  C2Port             PayloadGeneratorPort                    │
    │                                                            │
    │  EventStorePort     RepositoryPort<T>                      │
    └───────────────────────────┬────────────────────────────────┘
                                │
    ┌───────────────────────────▼────────────────────────────────┐
    │                   Adapters (实现)                          │
    │                                                            │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
    │  │ Semgrep MCP  │  │  Nmap MCP    │  │  Ghidra MCP      │ │
    │  │ Adapter      │  │  Adapter     │  │  Adapter         │ │
    │  └──────────────┘  └──────────────┘  └──────────────────┘ │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
    │  │ Nuclei MCP   │  │ Metasploit   │  │  Shodan MCP      │ │
    │  │ Adapter      │  │ MCP Adapter  │  │  Adapter         │ │
    │  └──────────────┘  └──────────────┘  └──────────────────┘ │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
    │  │ SQLMap MCP   │  │ ExploitDB    │  │  GDB/LLDB MCP    │ │
    │  │ Adapter      │  │ MCP Adapter  │  │  Adapter         │ │
    │  └──────────────┘  └──────────────┘  └──────────────────┘ │
    │  ┌──────────────┐  ┌──────────────────────────────────┐   │
    │  │ SQLite       │  │  Claude Agent SDK Adapter        │   │
    │  │ EventStore   │  │  (Agent 执行 + MCP 连接管理)      │   │
    │  └──────────────┘  └──────────────────────────────────┘   │
    └────────────────────────────────────────────────────────────┘
```

---

## 5. 事件溯源与 SQLite 持久化

### 5.1 EventStore 设计

```sql
CREATE TABLE events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT UNIQUE NOT NULL,        -- UUID
    event_type    TEXT NOT NULL,                -- 全限定类名
    aggregate_id  TEXT NOT NULL,                -- 聚合根 ID
    aggregate_type TEXT NOT NULL,               -- 聚合根类型
    context       TEXT NOT NULL,                -- 限界上下文名
    mission       TEXT NOT NULL,                -- "zeroday" | "oneday" | "ctf"
    payload       TEXT NOT NULL,                -- JSON 序列化的事件数据
    metadata      TEXT NOT NULL,                -- JSON: timestamp, correlation_id, causation_id
    version       INTEGER NOT NULL,             -- 聚合版本号（乐观并发控制）
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id);
CREATE INDEX idx_events_context ON events(context, mission);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_correlation ON events((json_extract(metadata, '$.correlation_id')));
```

### 5.2 EventStore Port & Adapter

```python
# Port（领域层）
class EventStorePort(Protocol):
    async def append(self, events: list[DomainEvent], expected_version: int) -> None: ...
    async def load(self, aggregate_id: str) -> list[DomainEvent]: ...
    async def load_by_context(self, context: str) -> list[DomainEvent]: ...
    async def load_all(self, since: datetime | None = None) -> list[DomainEvent]: ...

# Adapter（基础设施层）
class SQLiteEventStore(EventStorePort):
    def __init__(self, db_path: Path): ...
```

### 5.3 Blackboard 作为事件投影

```python
class Blackboard:
    """从 EventStore 投影出的当前状态视图"""

    def __init__(self, event_store: EventStorePort):
        self._store = event_store
        self._projectors: dict[str, Projector] = {}

    async def rebuild(self) -> None:
        """从 EventStore 重建所有投影"""
        events = await self._store.load_all()
        for event in events:
            for projector in self._projectors.values():
                projector.apply(event)

    # 投影后的查询接口
    @property
    def assets(self) -> dict[str, Asset]: ...
    @property
    def vulnerabilities(self) -> dict[str, Vulnerability]: ...
    @property
    def attack_graph(self) -> AttackGraph: ...
```

---

## 6. Agent 与 MCP 集成架构

### 6.1 Agent 映射

每个限界上下文对应一个 Claude Sub-Agent。Agent 通过 MCP 工具执行领域操作。

```
Mission: 1-day
├── ReconAgent         → Nmap MCP + Shodan MCP
├── ScanAgent          → Nuclei MCP
├── VulnAgent          → ExploitDB MCP + WebSearch
├── ExploitAgent       → Metasploit MCP + SQLMap MCP
└── PostAgent          → Bash + Metasploit MCP

Mission: 0-day
├── EntryPointAgent    → Semgrep MCP + Grep/Glob
├── DataFlowAgent      → Semgrep MCP (taint mode)
├── SinkAgent          → Semgrep MCP + WebSearch
└── PoCAgent           → Bash + Write/Edit

Mission: CTF
├── WebAgent           → SQLMap MCP + Nuclei MCP + Bash
├── PwnAgent           → GhidraMCP + GDB MCP + Bash
├── CryptoAgent        → Bash (sage/python) + WebSearch
├── ReverseAgent       → GhidraMCP + GDB MCP
└── MiscAgent          → Bash + WebSearch
```

### 6.2 MCP 服务器集成清单

| MCP Server | GitHub | Transport | 用于 |
|------------|--------|-----------|------|
| **semgrep/mcp** | `semgrep/mcp` | stdio / streamable-http | 0-day: 代码分析 + 污点追踪 |
| **Nmap MCP** | `mohdhaji87/Nmap-MCP-Server` | stdio (FastMCP) | 1-day: 网络扫描 |
| **Nuclei MCP** | `addcontent/nuclei-mcp` | stdio / http | 1-day: 漏洞扫描; CTF: Web |
| **Shodan MCP** | `BurtTheCoder/mcp-shodan` | stdio | 1-day: 资产情报 |
| **MetasploitMCP** | `GH05TCREW/MetasploitMCP` | stdio | 1-day: 漏洞利用 |
| **SQLMap MCP** | `mohdhaji87/SQLMap-MCP` | stdio (FastMCP) | 1-day: SQL注入; CTF: Web |
| **ExploitDB MCP** | `CyberRoute/mcp_exploitdb` | stdio | 1-day: 利用搜索 |
| **GhidraMCP** | `LaurieWired/GhidraMCP` | stdio | CTF: Pwn/Reverse |
| **GDB MCP** | `smadi0x86/MDB-MCP` | stdio | CTF: Pwn/Reverse 调试 |

### 6.3 MCP 适配器模式

```python
# 每个 Port 的 MCP 适配器遵循统一模式：
class NmapMCPAdapter(NetworkScannerPort):
    """将 NetworkScannerPort 领域接口适配到 Nmap MCP 服务器"""

    MCP_SERVER_CONFIG = {
        "type": "stdio",
        "command": "uvx",
        "args": ["nmap-mcp-server"],
    }

    async def scan(self, target: str, options: ScanOptions) -> ScanResult:
        # 1. 将领域概念转换为 MCP 工具调用参数
        # 2. 通过 Claude Agent SDK 的 MCP 连接调用工具
        # 3. 将 MCP 工具返回的原始结果转换为领域对象
        ...
```

---

## 7. 应用服务层

### 7.1 Mission 调度

```python
class MissionService:
    """应用服务：接收用户请求，组装拓扑+上下文+Agent，执行 Mission"""

    def __init__(
        self,
        topology_registry: TopologyRegistry,
        event_store: EventStorePort,
        mcp_registry: MCPRegistry,
    ): ...

    async def execute(
        self,
        mission_type: Literal["zeroday", "oneday", "ctf"],
        target: Target,
        topology: str = "ooda",           # 可切换
        **options,
    ) -> MissionReport:
        # 1. 从注册表获取拓扑策略
        topo = self.topology_registry.get(topology)
        # 2. 构建 Blackboard（从 EventStore 投影）
        blackboard = Blackboard(self.event_store)
        await blackboard.rebuild()
        # 3. 根据 mission_type 组装对应的 Agent 集合
        agents = self._build_agents(mission_type, self.mcp_registry)
        # 4. 执行拓扑
        async for event in topo.execute(mission, blackboard, agents):
            await self.event_store.append([event], ...)
        # 5. 生成报告
        return self._generate_report(blackboard)
```

---

## 8. 目录结构

```
miya-bot/
├── pyproject.toml
├── miya/
│   ├── __init__.py
│   ├── main.py                          # CLI 入口
│   │
│   ├── shared/                          # ═══ Shared Kernel ═══
│   │   ├── __init__.py
│   │   ├── types.py                     # 跨上下文值对象: Target, Finding, Severity, Credential, Asset
│   │   ├── events.py                    # DomainEvent 基类 + EventBus
│   │   ├── ports.py                     # EventStorePort, RepositoryPort<T> 等通用端口
│   │   ├── blackboard.py               # Blackboard + Projector
│   │   └── attack_graph.py             # AttackGraph DAG 模型（共享数据结构）
│   │
│   ├── topology/                        # ═══ 编排拓扑引擎 ═══
│   │   ├── __init__.py
│   │   ├── base.py                      # Topology Protocol + TopologyRegistry
│   │   ├── ooda.py                      # OODA 拓扑实现
│   │   └── attack_graph_topo.py         # AttackGraph 拓扑实现
│   │
│   ├── mission/                         # ═══ Application Service ═══
│   │   ├── __init__.py
│   │   └── service.py                   # MissionService: 调度 Mission 执行
│   │
│   ├── zeroday/                         # ═══ Mission: 0-day ═══
│   │   ├── __init__.py
│   │   ├── entrypoint/                  # 限界上下文: 入口发现
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # CodeBase, EntryPoint, InputVector
│   │   │   ├── service.py               # EntryPointDiscoveryService
│   │   │   ├── ports.py                 # CodeAnalyzerPort
│   │   │   └── agent.py                 # EntryPointAgent 定义
│   │   ├── dataflow/                    # 限界上下文: 数据流追踪
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # TaintSession, TaintSource, TaintSink, TaintPath
│   │   │   ├── service.py               # TaintAnalysisService
│   │   │   ├── ports.py                 # TaintEnginePort
│   │   │   └── agent.py                 # DataFlowAgent 定义
│   │   ├── sink/                        # 限界上下文: 危险函数分析
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # SinkAnalysis, SinkPattern, Exploitability
│   │   │   ├── service.py               # SinkEvaluationService
│   │   │   └── agent.py                 # SinkAgent 定义
│   │   ├── poc/                         # 限界上下文: 证明构造
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # PoCProject, PoCPayload, PoCResult
│   │   │   ├── service.py               # PoCGeneratorService
│   │   │   ├── ports.py                 # SandboxPort
│   │   │   └── agent.py                 # PoCAgent 定义
│   │   └── acl.py                       # 0-day 内部的反腐层转换
│   │
│   ├── oneday/                          # ═══ Mission: 1-day ═══
│   │   ├── __init__.py
│   │   ├── recon/                       # 限界上下文: 侦察
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # ReconMission, Asset, Fingerprint, ServiceBanner
│   │   │   ├── service.py               # ReconService
│   │   │   ├── ports.py                 # NetworkScannerPort, AssetIntelPort
│   │   │   └── agent.py                 # ReconAgent 定义
│   │   ├── scan/                        # 限界上下文: 扫描
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # ScanTask, ScanTarget, ScanResult
│   │   │   ├── service.py               # ScanService
│   │   │   ├── ports.py                 # VulnScannerPort
│   │   │   └── agent.py                 # ScanAgent 定义
│   │   ├── vuln/                        # 限界上下文: 漏洞匹配
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # VulnAssessment, CVE, VulnMatch, ExploitAvailability
│   │   │   ├── service.py               # VulnMatchService
│   │   │   ├── ports.py                 # CVEDatabasePort, ExploitDBPort
│   │   │   └── agent.py                 # VulnAgent 定义
│   │   ├── exploit/                     # 限界上下文: 漏洞利用
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # ExploitCampaign, ExploitAttempt, Payload, ExploitChain
│   │   │   ├── service.py               # ExploitService
│   │   │   ├── ports.py                 # ExploitFrameworkPort, PayloadGeneratorPort
│   │   │   └── agent.py                 # ExploitAgent 定义
│   │   ├── post/                        # 限界上下文: 后渗透
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # PostSession, AccessLevel, LootItem, PivotTarget
│   │   │   ├── service.py               # PostExploitService
│   │   │   ├── ports.py                 # C2Port
│   │   │   └── agent.py                 # PostAgent 定义
│   │   └── acl.py                       # 1-day 杀伤链各阶段间的反腐层
│   │
│   ├── ctf/                             # ═══ Mission: CTF ═══
│   │   ├── __init__.py
│   │   ├── shared/                      # CTF 共享子域
│   │   │   ├── __init__.py
│   │   │   └── domain.py                # Competition, Challenge, Flag, WriteUp
│   │   ├── web/                         # 限界上下文: Web 安全
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # WebChallenge, HttpEndpoint, InjectionPoint
│   │   │   ├── service.py               # WebSolverService
│   │   │   ├── ports.py                 # WebScannerPort
│   │   │   └── agent.py                 # WebAgent 定义
│   │   ├── pwn/                         # 限界上下文: 二进制利用
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # PwnChallenge, Binary, Protection, GadgetChain
│   │   │   ├── service.py               # PwnSolverService
│   │   │   ├── ports.py                 # DisassemblerPort, DebuggerPort
│   │   │   └── agent.py                 # PwnAgent 定义
│   │   ├── crypto/                      # 限界上下文: 密码学
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # CryptoChallenge, Cipher, CryptoAttack
│   │   │   ├── service.py               # CryptoSolverService
│   │   │   └── agent.py                 # CryptoAgent 定义
│   │   ├── reverse/                     # 限界上下文: 逆向工程
│   │   │   ├── __init__.py
│   │   │   ├── domain.py                # ReverseChallenge, BinaryAnalysis, Constraint
│   │   │   ├── service.py               # ReverseSolverService
│   │   │   ├── ports.py                 # 复用 DisassemblerPort
│   │   │   └── agent.py                 # ReverseAgent 定义
│   │   └── misc/                        # 限界上下文: 杂项/取证
│   │       ├── __init__.py
│   │       ├── domain.py                # MiscChallenge, FileArtifact, HiddenData
│   │       ├── service.py               # MiscSolverService
│   │       └── agent.py                 # MiscAgent 定义
│   │
│   └── infra/                           # ═══ Infrastructure Layer ═══
│       ├── __init__.py
│       ├── event_store.py               # SQLiteEventStore 实现
│       ├── mcp_registry.py              # MCP 服务器注册与管理
│       ├── adapters/                    # MCP 适配器集合
│       │   ├── __init__.py
│       │   ├── semgrep.py               # Semgrep MCP → CodeAnalyzerPort, TaintEnginePort
│       │   ├── nmap.py                  # Nmap MCP → NetworkScannerPort
│       │   ├── nuclei.py                # Nuclei MCP → VulnScannerPort
│       │   ├── shodan.py                # Shodan MCP → AssetIntelPort
│       │   ├── metasploit.py            # Metasploit MCP → ExploitFrameworkPort
│       │   ├── sqlmap.py                # SQLMap MCP → WebScannerPort (partial)
│       │   ├── exploitdb.py             # ExploitDB MCP → ExploitDBPort
│       │   ├── ghidra.py                # GhidraMCP → DisassemblerPort
│       │   └── gdb.py                   # GDB MCP → DebuggerPort
│       └── repositories/               # 仓储实现
│           ├── __init__.py
│           └── sqlite_repo.py           # 通用 SQLite Repository 实现
│
└── tests/
    ├── __init__.py
    ├── unit/                            # 领域模型单元测试
    │   ├── test_shared_types.py
    │   ├── test_events.py
    │   ├── test_attack_graph.py
    │   ├── test_blackboard.py
    │   ├── test_zeroday_domain.py
    │   ├── test_oneday_domain.py
    │   └── test_ctf_domain.py
    ├── integration/                     # 集成测试
    │   ├── test_event_store.py
    │   ├── test_topology_ooda.py
    │   └── test_topology_attack_graph.py
    └── conftest.py                      # 共享 fixtures
```

**文件统计**：约 90 个源文件 + 10 个测试文件

---

## 9. 关键接口与协议定义

### 9.1 Topology Protocol

```python
class Topology(Protocol):
    @property
    def name(self) -> str: ...

    async def execute(
        self,
        mission: Mission,
        blackboard: Blackboard,
        agents: dict[str, AgentHandle],
        event_store: EventStorePort,
    ) -> AsyncIterator[DomainEvent]: ...


class TopologyRegistry:
    _topologies: dict[str, Callable[..., Topology]] = {}

    @classmethod
    def register(cls, name: str, factory: Callable[..., Topology]) -> None: ...

    @classmethod
    def get(cls, name: str) -> Topology: ...

    @classmethod
    def available(cls) -> list[str]: ...
```

### 9.2 Repository Protocol

```python
T = TypeVar("T")

class RepositoryPort(Protocol[T]):
    async def save(self, aggregate: T) -> None: ...
    async def get(self, id: str) -> T | None: ...
    async def list(self, **filters) -> list[T]: ...
    async def delete(self, id: str) -> None: ...
```

### 9.3 AgentHandle

```python
@dataclass
class AgentHandle:
    """对一个 Claude Sub-Agent 的抽象引用"""
    definition: AgentDefinition
    context_name: str
    mission_type: str
    mcp_servers: dict[str, McpServerConfig]  # 该 Agent 需要的 MCP 连接
```

---

## 10. 用户交互

### 10.1 CLI

```bash
# 1-day 渗透 (默认 OODA 拓扑)
miya oneday --target 192.168.1.0/24 --topology ooda

# 1-day 渗透 (AttackGraph 拓扑)
miya oneday --target https://app.example.com --topology attack_graph

# 0-day 审计
miya zeroday --target ./vulnerable-app --language python

# CTF 解题
miya ctf --target https://ctf.example.com/chall/3 --category web

# 交互模式
miya interactive
```

### 10.2 Python SDK

```python
from miya.mission.service import MissionService
from miya.shared.types import Target

service = MissionService.create()  # 自动加载配置和 MCP

report = await service.execute(
    mission_type="oneday",
    target=Target(uri="192.168.1.100", kind="service"),
    topology="ooda",
)

print(report.findings)
```

---

## 11. 待讨论

1. **报告生成**：是否需要独立的 Report 限界上下文？还是作为 Application Service 的一部分？
2. **并发控制**：多个 Agent 同时写 Blackboard 时的并发策略？
3. **人工介入点**：哪些操作需要人工确认（如 exploit 执行前）？
4. **配置管理**：MCP 服务器配置用 YAML 文件还是代码内定义？
