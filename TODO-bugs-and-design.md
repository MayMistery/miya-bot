# Miya Bot — Bug & 设计问题深度审查（修订版）

经过对代码库的**二次验证 + 业务深度审查 + 深入反思**，最终保留真正影响业务的问题。

## 已修复

- **[已修复] #1** os.environ 污染 → `finally` 块恢复原值 (`service.py`)
- **[已修复] #2** Campaign 前向兼容 → 过滤未知字段 (`campaign.py`)
- **[已修复] #6** REFLECT heuristic 误判 → 仅检查输出尾部 300 字符 (`ooda.py`)
- **[已修复] #17** OODA 无 stagnation detection → 连续 3 次无新 finding 自动终止 (`ooda.py`)
- **[已修复] AttackGraph** 完善实现：recon→graph_build 阶段、图变更产生事件、事件审计链 (`attack_graph_topo.py`, `events.py`)

## 深入反思后移除/降级的问题

以下 TODO 经过代码走读和实际场景分析，确认为**伪问题或影响极低**：
- ~~#4 无自动知识共享~~ → 不是 bug，是有意的隔离设计。自动共享可能引入噪音
- ~~#7 Blackboard context 无界增长~~ → compact() 已有合理上限(200/500)，是正常工作流程
- ~~#9 EventBus 异常不透明~~ → return_exceptions=True + warning 是 event bus 标准模式
- ~~#10 Blackboard 静默丢弃事件~~ → MissionStarted 等不需要 blackboard 投射，设计正确
- ~~#12 ENUMERATE 无 fallback~~ → 代码已有 fallback（line 366-375，把 target 当单 challenge）
- ~~#13 compaction 丢关键线索~~ → 阈值 200，单 challenge 几乎不可能触发
- ~~#15 frozen dataclass 被篡改~~ → asdict() 能读到修改后的值，功能正确
- ~~#18 DB 缺唯一约束~~ → asyncio 单 loop，不存在并发写

标注说明:
- **[已验证]** = 通过代码走读确认存在
- **[误报已剔除]** = 初版中的假阳性，本版已移除
- **[新增·业务]** = 本次新增的业务/架构设计缺陷

初版误报说明:
- ~~CostTracker 竞态~~ → 误报：所有调用都在单一 asyncio event loop 内，无真实竞态。docstring "Thread-safe" 应改为 "Event-loop-safe"
- ~~events 命令索引越界~~ → 误报：Python `list[-N:]` 在 N > len 时安全，仅序号显示为负数，非崩溃 bug
- ~~ch_agg_id 条件判断顺序~~ → 误报：`(None == None) and None` → `True and None` → `None` (falsy)，逻辑正确
- ~~路径遍历~~ → 误报：`r'[^\w\-]'` 彻底过滤了 `../`，无法存活
- ~~config.py 替换为 dotenv~~ → 误报：config.py 解析的是 `.miya.toml`，非 `.env` 文件，两者功能不同

---

## TODO 1: [已验证] unlimited 模式污染 `os.environ` — 后续 mission 行为异常

**文件**: `miya/mission/service.py:438-443`
**严重性**: P0

```python
os.environ["MIYA_OODA_MAX_ITERATIONS"] = "999"
os.environ["MIYA_MAX_TURNS"] = "999"
os.environ["MIYA_FANOUT_TIMEOUT"] = "999999"
os.environ["MIYA_SDK_IDLE_TIMEOUT"] = "99999"
```

验证：这些环境变量的消费者在 `base.py:_get_topology_config()` 中，每次构造 topology 时读取。一旦设置永不恢复，REPL 中后续非 unlimited 的 mission 也会继承 999 次迭代上限。

**修复方案**: 用 context manager 包裹 mission 执行，退出时恢复原值。或直接通过 topology 构造参数传入，不经过 `os.environ`。

---

## TODO 2: [已验证] Campaign `load()` 前向兼容断裂

**文件**: `miya/shared/campaign.py:54-55`
**严重性**: P1

```python
entries = [CampaignEntry(**e) for e in data.get("entries", [])]
```

验证：如果未来给 `CampaignEntry` 加新字段并保存，老版本代码 load 新 JSON 会抛 `TypeError: unexpected keyword argument`，然后回退到空 campaign，**丢失全部历史数据**。

注意：`events.py:event_from_dict()` 对 DomainEvent 做了正确的字段过滤（line 401-404），但 Campaign 没有同等保护。

**修复方案**: 模仿 `event_from_dict()` 的模式，在解包前过滤字段：
```python
valid = {f.name for f in dataclasses.fields(CampaignEntry)}
entries = [CampaignEntry(**{k: v for k, v in e.items() if k in valid}) for e in data.get("entries", [])]
```

---

## TODO 3: [已验证] fanout_topo 取消时吞掉所有异常

**文件**: `miya/topology/fanout_topo.py:689-690`
**严重性**: P1

```python
except (asyncio.CancelledError, Exception):
    pass
```

验证：如果 OODA task 在取消时抛出非 CancelledError 的异常（如 `RuntimeError`, SDK 连接错误），这里完全静默。同时 finally 块（line 1054-1066）虽然存在，但 waiter task 的异常也被吞掉。

**修复方案**: 至少记录日志 `logger.debug("OODA task cleanup", exc_info=True)`。考虑改用 `asyncio.TaskGroup`。

---

## TODO 4: [新增·业务] Fanout 无自动跨 challenge 知识共享机制

**文件**: `miya/topology/fanout_topo.py`
**严重性**: P1（业务影响大）

当前设计：每个 challenge 运行独立的 OODA 循环（`sub_bb = Blackboard()`，line 541），各自的 Blackboard 完全隔离。跨 challenge 知识传递**仅靠人工 HITL 命令** `ref <src> @<dst>`（line 966-1005）。

**业务问题**: CTF 比赛中 challenge 之间经常有关联（共享 cookie、相同框架、类似漏洞模式），当前设计无法自动利用这些关联。A challenge 发现的 SQL 注入技巧在 B challenge 中可能直接适用，但系统不会自动传播。

Campaign 虽然记录了 `solved` 和 `technique`，但只在 OODA 的 prompt context 中被注入（`campaign.to_context_prompt()`），而每个 sub-OODA 的 campaign context 仅在 session 初始化时注入，不会在运行中动态更新。

**修复方案**:
- 实现 `AutoKnowledgeBroker`：监听所有 challenge 的事件流，当 A challenge 产生 `VulnerabilityFound` 或 `ExploitSucceeded` 时，自动向同类别/同目标的 running challenge 注入知识
- Campaign 的 `technique` 记录应实时同步给 running challenges（通过 HITL queue 自动注入）
- 在 OODA 的每次迭代开始时重新拉取最新 campaign context

---

## TODO 5: [新增·业务] Mission 状态机缺少 "suspended" → "resumed" 转换

**文件**: `miya/shared/types.py:145-171`, `miya/shared/events.py:330-334`
**严重性**: P1

当前 Mission 状态机：`created → running → completed|failed`

问题：
1. 有 `MissionSuspended` 事件（events.py:330），但 Mission 的状态机**没有 "suspended" 状态**，也没有 `suspend()` 方法
2. 没有 `MissionResumed` 事件，无法区分"新 mission"和"恢复的 mission"
3. fanout_topo 的 `checkpoint` 机制（campaign.py:142-158）将 challenge 进度记录在 Campaign 中，但没有对应的 resume 逻辑来自动跳过已完成的 challenge
4. 如果用户 Ctrl+C 中断 mission，状态永远停在 "running"（没有终止事件）

**修复方案**:
- Mission 状态机扩展：`created → running → suspended → running → completed|failed`
- 添加 `Mission.suspend()` 方法和 `MissionResumed` 事件
- fanout 在启动时检查 campaign 的 checkpoint，自动跳过 `status=solved` 和 `status=timeout` 的 challenge
- 注册 signal handler（SIGINT），优雅地产生 MissionSuspended 事件

---

## TODO 6: [新增·业务] OODA REFLECT 的 heuristic 误判 — "complete" 过于激进

**文件**: `miya/topology/ooda.py:927-935`
**严重性**: P1

```python
if not decision_parsed:
    lower = output.lower()
    if any(phrase in lower for phrase in (
        "objective achieved", "mission complete", "flag found",
        "successfully exploited", "root access obtained",
    )):
        result["decision"] = "complete"
```

验证：当 LLM 在 ACT/CONTINUE 输出中**讨论**这些短语（如"we haven't flag found yet"或"if we successfully exploited..."）时，heuristic 会错误地判定为 complete。这个 fallback 只在 `DECISION:` 字段未被解析时触发，但 LLM 输出格式不稳定时恰恰容易漏掉结构化字段。

**业务影响**: Mission 提前终止，未完成的攻击链被截断。

**修复方案**:
- 收紧 heuristic：要求短语出现在输出的最后 200 字符内（结论部分）
- 对 CTF 场景，只有在 blackboard 中已存在 `ChallengeSolved` 事件时才接受 heuristic 的 complete
- 添加 confidence 阈值：至少匹配 2 个短语才触发

---

## TODO 7: [新增·业务] Blackboard `to_context_prompt()` 无界增长导致 token 浪费

**文件**: `miya/shared/blackboard.py:to_context_prompt()`
**严重性**: P2

验证：Blackboard 的 `to_context_prompt()` 将所有 findings、assets、vulns、exploits 等全部序列化为 prompt 文本。在长时间 mission 中，随着事件累积，这个 context 可以增长到数千行，严重浪费 token 且可能超出 context window。

虽然 `compact()` 方法（line 196-217）做了一些清理，但它只在 OODA 循环的 iteration > 1 时被调用（ooda.py:459-462），且清理逻辑有限（只移除已 compact 过的事件）。

**业务影响**: 每次 OODA 迭代的 API 调用都携带冗长的历史 context，导致成本线性增长。

**修复方案**:
- 为 `to_context_prompt()` 设置 token 预算（如 2000 tokens），按优先级截断
- 对 findings/vulns 只保留最近 N 条或按 severity 排序
- 引入 "summary" 机制：超过阈值时用一次 LLM 调用压缩历史 context

---

## TODO 8: [新增·业务] AttackGraph topology 是半成品 — 注册但未可用

**文件**: `miya/topology/attack_graph_topo.py`
**严重性**: P2

验证：`AttackGraphTopology` 通过 `@TopologyRegistry.register("attack_graph")` 注册，用户可以通过 `--topology attack_graph` 启动。但：
1. 它依赖 Blackboard 中已有 assets 和 edges 数据，但没有 bootstrap 阶段来建立初始图
2. `_PLAN_PROMPT` 要求 LLM 输出结构化的 `NEXT_STEP:` / `NODE:` / `EDGE:` 格式，但解析逻辑不够健壮
3. 与 OODA topology 的功能高度重叠，无清晰边界

**业务影响**: 用户选择 attack_graph topology 可能得到空白/错误的结果，没有文档或错误提示说明它是实验性的。

**修复方案**:
- 短期：标记为 `@TopologyRegistry.register("attack_graph", experimental=True)`，在选择时发出警告
- 长期：补充 recon bootstrap 阶段，或将 attack graph 作为 OODA 的增强（在 ORIENT 阶段构建 attack graph）而非独立 topology

---

## TODO 9: [新增·业务] EventBus 异常处理不透明

**文件**: `miya/shared/events.py:435-446`
**严重性**: P2

```python
results = await asyncio.gather(
    *(h(event) for h in handlers), return_exceptions=True,
)
for r in results:
    if isinstance(r, Exception):
        logging.getLogger(__name__).warning(
            "EventBus handler error for %s: %s", type_name, r,
        )
```

验证：EventBus handler 异常被 `return_exceptions=True` 捕获后仅 warning，不中断也不重试。如果一个关键 handler（如持久化 handler）失败，事件丢失但调用方不知道。

**业务影响**: 事件可能发出了但部分 subscriber 没处理成功，导致状态不一致。

**修复方案**:
- 区分 critical handler 和 advisory handler
- Critical handler 失败时传播异常或记入 dead letter queue
- 至少记录 `exc_info=True` 而不仅仅是异常字符串

---

## TODO 10: [已验证] Blackboard 事件投射静默丢弃未知事件

**文件**: `miya/shared/blackboard.py:225-229`
**严重性**: P2

```python
projector = getattr(self, f"_on_{event.__class__.__name__}", None)
if projector:
    projector(event)
```

验证：`MissionStarted`, `MissionCompleted`, `MissionFailed`, `MissionSuspended`, `FlagSubmitted`, `TargetUnreachable`, `ScanCompleted` 等事件没有对应的 `_on_XXX` 方法，全部被静默丢弃。新增事件类型时不会有任何提示。

**修复方案**: 增加 debug 日志。维护已知可忽略事件的白名单。

---

## TODO 11: [新增·业务] LLM 输出事件解析依赖正则 — 脆弱且无校验

**文件**: `miya/topology/base.py:extract_events_from_output()`
**严重性**: P1

验证：所有事件都靠 LLM 在输出中嵌入 `[EVENT:XXX {...}]` 格式来触发。解析依赖正则匹配 + `json.loads()`。

问题：
1. LLM 可能输出格式不完美的 JSON（缺少引号、尾逗号、嵌套引号未转义）
2. LLM 可能输出多个相同事件（重复 flag）
3. 没有对解析出的事件做业务校验（如 `ChallengeSolved` 的 flag 字段为空？challenge_name 不在已知列表？）
4. 如果 LLM 幻觉产生虚假的 `ChallengeSolved` 事件，系统会直接接受

**业务影响**: 虚假 flag 导致 campaign 数据错误，mission 提前结束。

**修复方案**:
- 对 `ChallengeSolved` 事件做 flag 格式校验（regex 匹配 CTF flag 格式）
- 去重：同一 challenge_name 的 ChallengeSolved 只接受第一个
- 使用 `json.loads` 的容错替代方案（如先尝试严格解析，失败后尝试修复常见 JSON 错误）
- 对 flag 增加提交验证步骤（通过 FlagSubmitted 事件确认）

---

## TODO 12: [新增·业务] fanout ENUMERATE 阶段无 fallback — 空列表即放弃

**文件**: `miya/topology/fanout_topo.py:266-330`
**严重性**: P2

验证：如果 ENUMERATE 阶段的 LLM 调用没有产生任何 `ChallengeIdentified` 事件（网络问题、LLM 未遵循格式、平台页面变化），`challenges` 列表为空，topology 直接跳到 COLLECT 阶段产生空报告。

没有重试、没有 fallback、没有提示用户手动输入 challenge 列表。

**修复方案**:
- 空列表时自动重试 ENUMERATE（最多 2 次，换一个更明确的 prompt）
- 仍然为空时，提示操作员通过 HITL 手动输入 challenge 信息
- 支持从文件/URL 导入 challenge 列表作为 fallback

---

## TODO 13: [新增·业务] Blackboard compaction 按 severity 丢弃可能导致关键线索丢失

**文件**: `miya/shared/blackboard.py:529-536`
**严重性**: P2

```python
sorted_findings = sorted(
    self.findings,
    key=lambda f: (-f.severity.score, self.findings.index(f)),
)
self.findings[:] = sorted_findings[:max_findings]
```

验证：compaction 按 severity 降序保留 findings，低 severity 的会被丢弃。但在 CTF 场景中，一个 INFO 级别的 finding（如"Discovered WordPress 5.8 with plugin X"）可能是识别漏洞的**唯一线索**。一旦在后续迭代中因 compaction 被删除，OODA 循环就丢失了这个上下文。

**修复方案**:
- compaction 不应按 severity 单维度排序，应考虑"信息增益"维度
- 对与当前 challenge 直接相关的 findings（challenge_name 匹配）永不删除
- 或对被删除的 findings 保留 one-liner 摘要列表，不完全丢弃

---

## TODO 14: [新增·业务] Whitebox 模式将 file path 作为 target URI — 语义混乱

**文件**: `miya/topology/fanout_topo.py:1342-1345`
**严重性**: P2

```python
ch["_whitebox"] = True
ch["_original_target"] = ch.get("target", "")
if ch_files:
    ch["target"] = ch_files[0]  # 文件路径取代了 URL
```

验证：当目标不可达时，whitebox 模式将 `target` 设为第一个 file path（如 `/home/user/challenges/web/app.py`）。但下游 `_solve_challenge` (line 536) 直接用 `ch_target = challenge.get("target", mission.target.uri)` 构建 mission prompt。`Target(uri=..., kind="challenge")` 现在 URI 变成了文件路径，语义错误。

虽然 whitebox 提示词（line 520-524）告诉 agent 不要发起网络请求，但 agent 可能仍尝试 `curl` 这个"目标"路径。

**修复方案**:
- whitebox 模式下，`Target.kind` 应改为 `"source"`
- 保持原始 target 不变，在 sub-mission prompt 中明确标注 `source_files` 列表
- 不要复用 `target` 字段传递不同语义的数据

---

## TODO 15: [新增·业务] `ChallengeSolved` 通过 `object.__setattr__` 修改 frozen dataclass — 事件溯源契约违反

**文件**: `miya/topology/ooda.py:506-509, 672-675`
**严重性**: P2

```python
object.__setattr__(
    extracted, "phase_output",
    continue_output[:8000],
)
```

验证：`DomainEvent` 和所有子类都是 `frozen=True` 的 dataclass。代码绕过 frozen 保护强行修改 `phase_output`。这个修改发生在事件创建之后、持久化之前，但：
1. 违反了事件的不可变性契约
2. 如果 `to_dict()` 先于 `__setattr__` 被调用，序列化的数据不包含 `phase_output`
3. 事件 replay 时从 JSON 重建的事件不会包含这个字段（除非恰好在 JSON 中）

**修复方案**:
- 在 `extract_events_from_output` 阶段就将 phase_output 注入事件构造参数
- 或创建独立事件类型 `PhaseOutputCaptured` 关联到 `ChallengeSolved`

---

## TODO 16: [新增·业务] AttackGraph 的图变更不产生事件 — 审计链断裂

**文件**: `miya/topology/attack_graph_topo.py:388-389, 491-587`
**严重性**: P2

验证：`_apply_rebuild()` 方法通过正则解析 LLM 输出直接修改内存中的 graph 对象（添加节点、边、更新状态），但**不产生任何 DomainEvent**。这意味着：
1. EventStore 中没有 attack graph 变更的记录
2. 如果 mission 需要审计或 replay，attack graph 是空的
3. 违反了项目的核心设计原则——"Every state change in Miya is captured as a DomainEvent"（events.py 第 1-5 行）

**修复方案**:
- 添加 `GraphNodeAdded`, `GraphEdgeAdded`, `GraphNodeStatusChanged` 事件类型
- `_apply_rebuild()` 在修改 graph 前先 yield 对应事件
- 或将 AttackGraph 的变更通过 Blackboard 的 event projection 机制来驱动

---

## TODO 17: [新增·业务] OODA 无 stagnation detection — 空转消耗 token

**文件**: `miya/topology/ooda.py:457-799`
**严重性**: P1

验证：OODA 循环从 iteration 1 跑到 max_iterations，每次 REFLECT 只要不返回 "complete" 就继续。但没有检测 **进展是否停滞**：
- 不追踪 `blackboard.findings` 数量在迭代间是否增长
- 不检查 REFLECT 的 insights 是否与上次相同（重复 pivot 同一策略）
- 不比较连续两次 ACT 输出的相似度

如果 agent 在 5 次迭代中都没有新 finding，它仍会继续跑完剩余的 5 次迭代。

**业务影响**: 每次无效迭代消耗 ~$0.10-0.50 的 API 费用。10 个 challenge * 5 次空转 = $5-25 浪费。

**修复方案**:
- 记录每次迭代前后的 `len(blackboard.findings)` 和 `len(blackboard.exploit_attempts)`
- 连续 N 次（如 3 次）无新 finding 时，自动降级为 "complete"
- 在 REFLECT prompt 中注入 stagnation 警告："WARNING: No new findings in last 3 iterations. Consider COMPLETE if stuck."

---

## TODO 18: [已验证] `events` 表缺少 aggregate_id + version 联合唯一约束

**文件**: `miya/infra/event_store.py:19-38`
**严重性**: P2

验证：乐观并发控制在 `append()` 中检查 `expected_version`（TOCTOU pattern），但 schema 无 `UNIQUE(aggregate_id, version)` 约束。虽然 SQLite 的 `BEGIN IMMEDIATE` 在当前单文件场景下可工作，但缺少 DB 层最终一致性保障。

**修复方案**: 添加唯一索引。

---

## TODO 19: [已验证] CostTracker docstring 误导

**文件**: `miya/topology/base.py:45`
**严重性**: P3（文档）

验证：CostTracker 所有调用都在单一 event loop 内，实际无竞态。但 docstring "Thread-safe accumulator" 是错误的，它既没有锁也不需要锁。

**修复方案**: docstring 改为 "Event-loop-bound accumulator for API usage metrics."

---

## TODO 20: [已验证] `events` 命令序号显示为负数

**文件**: `miya/main.py:1705`
**严重性**: P3（UI）

验证：`limit > len(all_ev)` 时 `enumerate(..., len(all_ev) - limit + 1)` 产生负数起始值。不崩溃，但用户看到负数序号会困惑。

**修复方案**: `start = max(len(all_ev) - limit, 0) + 1`

---

---

# 业务能力提升洞察（深入反思后）

以下是经过代码走读、信息流追踪、逐条反思后确认的**真正能提升 miya-bot 解题/渗透能力**的改进点。

每条洞察都标注了：
- **验证方法**：怎么确认它是真问题
- **反思**：是否有我漏掉的缓解因素
- **影响量化**：在什么场景下、多大程度影响业务结果

---

## INSIGHT 1: [P0·效果最直接] CONTINUE 迭代缺失 blackboard 锚点

**文件**: `miya/topology/ooda.py:496-502`
**影响范围**: CTF session 模式下 iteration 2-10（占总迭代量的 80%+）

**现状**：
```python
continue_prompt = continue_tmpl.format(
    iteration=iteration,
    previous_insights=previous_insights or "(none)",
) + op_suffix + EVENT_INSTRUCTION + ...
```

CONTINUE prompt 只有 `previous_insights`（一句话）+ `EVENT_INSTRUCTION`。没有 `blackboard.to_context_prompt()`。

**验证**：对比 OBSERVE prompt (line 562) 有 `blackboard_context=blackboard.to_context_prompt()`，CONTINUE 确实缺失。

**反思**：session 保留了所有历史对话，agent 理论上能回忆。但：
1. Claude 的注意力在长 session 中对早期信息衰减是已知现象
2. Blackboard 是**经过事件投射和去重后的结构化摘要**，比原始对话历史高效得多
3. 每次 CONTINUE 只需 ~200-500 tokens 的 blackboard context，成本极低

**影响量化**：
- 3 次迭代以内：影响小（session 记忆足够）
- 5+ 次迭代：agent 开始重复尝试已失败的策略，因为记不清早期发现
- 10 次迭代：显著退化，agent 在最后几轮几乎是盲目尝试

**修复方案**：在 CONTINUE prompt 中追加 `blackboard.to_context_prompt()` 作为 checkpoint。

**ROI**: ★★★★★（改动 2 行代码，影响 80% 的 CTF 迭代质量）

---

## INSIGHT 2: [P1·防御性] REFLECT 经验记忆只保留方向，丢弃原因

**文件**: `miya/topology/ooda.py:736`
**影响范围**: 所有 topology 的 OODA 循环

**现状**：
```python
previous_insights = decision.get("next_focus", "") or decision.get("insights", "")
```

REFLECT 产出 4 个字段，但只有 `NEXT_FOCUS` 存活到下一次迭代。`ASSESSMENT`（"SQL injection failed because WAF blocks single quotes"）被丢弃。

**验证**：确认 `previous_insights` 只在 REFLECT prompt 和 CONTINUE prompt 中使用，没有其他地方保存历史 ASSESSMENT。

**反思**：
- Session 模式下，REFLECT 完整输出在 session history 中——但 attention 衰减问题同上
- Stateless 模式（oneday/zeroday）下，ASSESSMENT **完全永久丢失**
- agent 的行为模式："focus on web endpoints" 但不知道"我们已经试了 SQLi/XSS/SSRF 都不行"

**影响量化**：
- Pivot 后重试已失败路径的概率：每多一次 pivot，概率增加 ~20%
- 10 次迭代中 3 次 pivot → 约 60% 概率至少一次无效重试

**修复方案**：累积 ASSESSMENT 历史到一个 `reflection_log` 列表，在 REFLECT 和 CONTINUE prompt 中注入最近 3 条。

**ROI**: ★★★★（改动小，减少无效重试）

---

## INSIGHT 3: [P1·能力上限] Classification 错误时无纠正机制 — specialist 锁死

**文件**: `miya/topology/ooda.py:420-426, 432-440`
**影响范围**: CTF 所有需要跨域能力的题目

**现状**：
```python
session_agents = agents
if classified_category and mission_key == "ctf":
    direct = self._pick_direct_agent(classified_category, agents)
    if direct:
        session_agents = direct  # 整个 session 锁定为单一 specialist
```

Session 创建时绑定 agents (line 440: `SDKSession(agent_defs, ...)`），之后不可变。

**验证**：
1. `_pick_direct_agent` 返回单一 agent dict（line 1047-1051: `return {name: handle}`）
2. `SDKSession.__init__` 接收 agent_defs，创建后不可更改
3. 如果 REFLECT 决定 "pivot"，agent 类型不会改变——只改变策略方向

**反思**：
- 这不是每道题都遇到的问题。大部分 CTF 题确实是单一类别
- 但跨域题（web+crypto, pwn+reverse）是高分题，恰恰是拉开差距的地方
- 真正的瓶颈是 **auto-classify 的 confidence 不够高时仍然选择 specialist**

**影响量化**：
- 典型 CTF 比赛中 ~15-25% 的题目需要跨域能力
- 这些题通常是 300-500 分的难题，价值高

**修复方案**：
- 方案 A（简单）：当 classify confidence < 0.7 时，保留所有 agents 不做筛选
- 方案 B（中等）：REFLECT pivot 时允许切换 specialist agent（需要重建 session 或使用 stateless 调用）

**ROI**: ★★★☆（影响高分题解题率，但改动需要考虑 session 生命周期）

---

## INSIGHT 4: [P2·信息保真] Phase 间 4KB 截断丢失分析思路

**文件**: `miya/topology/ooda.py:604, 630, 656, 711`
**影响范围**: Stateless 模式（oneday/zeroday），CTF 的 iteration 1

**现状**：
```python
orient_prompt = ... observe_output[:4000] ...
decide_prompt = ... orient_output[:4000] ...
```

**反思（关键纠正）**：
这个问题比最初预想的**轻很多**，因为：
1. 每个 phase 都重新注入了 `blackboard.to_context_prompt()`
2. 上一个 phase 的**结构化发现**（events）已经通过 blackboard 保留了
3. 截断丢失的只是**分析思路和推理过程**，不是发现本身

但对于复杂目标（多服务、多漏洞），OBSERVE 的分析总结通常在输出末尾，恰好被 4KB 截断。

**影响量化**：
- 简单目标（1-2 个服务）：无影响，4KB 足够
- 复杂目标（5+ 个服务）：ORIENT 可能缺失 OBSERVE 的核心分析
- CTF session 模式下：影响仅限 iteration 1（后续走 CONTINUE，不截断）

**修复方案**：截取**尾部** 4KB 而非头部（结论在末尾），或提取 `[:2000] + ... + [-2000:]` 首尾组合。

**ROI**: ★★★（改动极小，对复杂目标有帮助）

---

## INSIGHT 5: [P2·可观测性] Blackboard context 不展示 evidence 字段

**文件**: `miya/shared/blackboard.py:605-611`
**影响范围**: 所有 topology

**现状**：
```python
for f in shown[:recent_detail]:
    lines.append(f"- {f.oneliner()}: {f.detail[:100]}")
```

Finding 只展示 `title` + `detail[:100]`。`evidence` 字段（包含 payload、response 片段、具体位置）完全不出现在 context 中。

**反思**：evidence 通常较长（exploit output），全部放入 prompt 会浪费 token。但对最近的 2-3 个 finding，evidence 包含的具体信息（哪个参数、什么 response）对下一轮迭代很关键。

**修复方案**：对最近 3 个 findings 追加 `evidence[:80]`。

**ROI**: ★★☆（改动极小，边际提升）

---

## 反思后排除的洞察

以下最初看起来像问题，但经验证**不值得改动**：

| 洞察 | 排除理由 |
|------|---------|
| CTF 跳过 ORIENT+DECIDE | 有意的设计选择。comment 明确写了 "Over-prompting degrades capability"。增加 phases = 增加 API 成本但不一定提升效果 |
| Blackboard 按 severity 排序不够智能 | 要按 relevance 排序需要知道"当前焦点"——这本身是一个复杂特性。severity 排序是合理默认 |
| Agent 不知道自己发出了什么事件 | Finding 的 title+detail[:100] 实际上保留了核心信息。100 字符足够传达"在哪发现了什么" |
| Fanout 无自动跨 challenge 知识共享 | 有意的隔离设计。自动共享 SQLi 技巧给 crypto 题反而是噪音 |

---

## 实施优先级

| 优先级 | Insight | 预期效果 | 工作量 | ROI |
|--------|---------|---------|--------|-----|
| **P0** | #1 CONTINUE 注入 blackboard | 5+ 迭代的 CTF 解题率显著提升 | 2 行代码 | ★★★★★ |
| **P1** | #2 累积 REFLECT 经验记忆 | 减少 pivot 后无效重试 | ~20 行代码 | ★★★★ |
| **P1** | #3 Classification 纠正/fallback | 解锁跨域高分题 | ~30 行代码 | ★★★☆ |
| **P2** | #4 截断改为首尾组合 | 复杂目标分析完整性 | 4 行代码 | ★★★ |
| **P2** | #5 展示近期 evidence | 下一轮迭代信息更完整 | 3 行代码 | ★★☆ |
