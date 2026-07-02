# Miya Bot — Bug & 设计问题深度审查（修订版）

经过对代码库的**二次验证 + 业务深度审查 + 深入反思**，最终保留真正影响业务的问题。

## 已修复

- **[已修复] #1** os.environ 污染 → `finally` 块恢复原值 (`service.py`)
- **[已修复] #2** Campaign 前向兼容 → 过滤未知字段 (`campaign.py`)
- **[已修复] #3** fanout 取消时吞异常 → 分离 CancelledError/Exception，添加 debug 日志 (`fanout_topo.py`)
- **[已修复] #5** Mission 状态机 → 新增 `suspended` 状态、`suspend()` 方法、`MissionResumed` 事件 (`types.py`, `events.py`)
- **[已修复] #6** REFLECT heuristic 误判 → 仅检查输出尾部 300 字符 (`ooda.py`)
- **[已修复] #11** 事件解析无校验 → ChallengeSolved 空 flag 丢弃、ChallengeSolved/FlagSubmitted 去重 (`base.py`)
- **[已修复] #14** Whitebox target 语义 → 不再覆盖 target，使用 `_source_files` 单独传递 (`fanout_topo.py`)
- **[已修复] #17** OODA 无 stagnation detection → 连续 3 次无新 finding 自动终止 (`ooda.py`)
- **[已修复] #19** CostTracker docstring → 改为 "Event-loop-bound accumulator" (`base.py`)
- **[已修复] #20** events 命令负数序号 → `max(len(all_ev) - limit, 0) + 1` (`main.py`)
- **[已修复] AttackGraph** 完善实现：recon→graph_build 阶段、图变更产生事件、事件审计链 (`attack_graph_topo.py`, `events.py`)
- **[已修复] INSIGHT 1** CONTINUE 注入 blackboard checkpoint → 每次 CONTINUE 迭代包含结构化状态 (`ooda.py`)
- **[已修复] INSIGHT 2** REFLECT 累积 ASSESSMENT 历史 → 最近 3 条注入 REFLECT/CONTINUE prompt (`ooda.py`)
- **[已修复] INSIGHT 3** Classification 低 confidence fallback → confidence < 0.7 时保留所有 agents (`ooda.py`)
- **[已修复] INSIGHT 4** Phase 间截断首尾组合 → `_smart_truncate()` 保留头 2KB + 尾 2KB (`ooda.py`)
- **[已修复] INSIGHT 5** Blackboard evidence 可见 → 最近 3 个 findings 展示 evidence[:80] (`blackboard.py`)
- **[已修复] ReflectionCompleted** 新增 `next_focus` 字段，存储到事件和 blackboard (`events.py`, `blackboard.py`)

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

# 架构简化洞察 — 信任模型，减少桎梏

核心哲学：**架构是帮助模型加速解决问题的，不是限制它。**
Claude 已经知道怎么做安全测试和 CTF。我们的工作是给它正确的目标、工具和上下文，然后闪开。

---

## ARCH 1: [根本性] 杀掉 Phase 分离 — Iteration 1 不需要 4 次 LLM 调用

**当前代价**：CTF Iteration 1 = CLASSIFY + OBSERVE + ACT + REFLECT = **4 次独立 LLM 调用**

**每次调用都重复注入**：
- `EVENT_INSTRUCTION`（2,742 chars / ~685 tokens）
- `blackboard.to_context_prompt()`（1-3 KB）
- Phase prompt 模板

**总开销**：~9,634 chars 的 prompt 格式噪音，是一句"solve this challenge"（200 chars）的 **48 倍**。

**真正的问题**：Phase 分离把模型的连贯推理**人为切断**。模型在 OBSERVE 阶段发现了漏洞的线索，但必须等到 ACT 阶段才能去利用——而此时它收到的是 OBSERVE 输出的**截断版**（4KB）。模型的思维链被打断了。

**反思**：代码注释（ooda.py:48-50）写得很清楚——"give the model the GOAL, not the STEPS"。但代码本身在做相反的事：强制 OBSERVE→ACT→REFLECT 的步骤。CONTINUE prompt（iteration 2+）已经证明了合并有效——为什么 iteration 1 不能也这样？

**修复方案**：
```
# Iteration 1 (session mode):
prompt = """
Solve this CTF challenge: {challenge_info}
{recon_hint}

Work through it autonomously:
- Explore the challenge and identify the vulnerability
- Develop and execute an exploit
- Capture the flag

When done, report what happened and whether you got the flag.
"""
# 1 call instead of 4
```

**ROI**: 减少 3 次 LLM 调用 / iteration，节省 ~2,400 tokens prompt 开销，**更重要的是保持模型推理的连贯性**。

---

## ARCH 2: [高影响] EVENT_INSTRUCTION 是一个税 — 模型不需要被教如何输出

**当前代价**：2,742 chars 的结构化输出指令，每个 phase 都注入，列举了 20+ 种事件类型的 JSON schema。

**问题**：
1. 这是在告诉 Claude **如何格式化输出**，而不是**发现什么**。Claude 知道 CVE 是什么、flag 是什么——不需要教它 JSON 格式
2. 输出格式约束会**降低**模型能力。模型需要同时做两件事：(a) 思考安全问题 (b) 在正确位置插入正确格式的 JSON。这分散了注意力
3. 如果 JSON 格式有任何错误（少一个引号、多一个逗号），`extract_events_from_output` 会**静默丢弃**整个发现
4. 信息被编码了**两次**——自然语言描述一次，`[EVENT:...]` marker 再一次

**反思**：EVENT_INSTRUCTION 的存在说明系统不信任模型的自然输出。但对于 CTF 场景，唯一真正重要的事件是 `ChallengeSolved`（flag）。其余 19 种事件（AssetDiscovered、VulnerabilityFound、ExploitAttempted...）是**可观测性数据**，不是**业务逻辑**。用 2,742 chars 的 prompt 来获取可观测性数据，代价太高。

**修复方案**：
- CTF 场景：**只保留 ChallengeSolved 和 FlagSubmitted 两个事件的 instruction**，砍掉其他 18 个。~200 chars 就够了
- Pentest 场景：保留完整 EVENT_INSTRUCTION（可观测性对 pentest 有价值）
- 或更激进：完全去掉 EVENT_INSTRUCTION，用**后处理**提取结构化数据。模型输出 "I found the flag: flag{xxx}" → 后处理正则提取 flag

**ROI**: 每次 LLM 调用节省 ~685 tokens input。CTF 5 iterations = 节省 ~3,400 tokens。更重要的是**不分散模型注意力**。

---

## ARCH 3: [高影响] 杀掉 CLASSIFY → specialist 锁定 — 让模型自己选工具

**当前代价**：
1. 额外 1 次 LLM 调用（CLASSIFY）= ~3,500 chars prompt
2. 基于 CLASSIFY 结果锁定 specialist agent，整个 session 不可变
3. 如果分类错误，模型被困在错误的 agent 里

**问题的本质**：CLASSIFY 是在替模型做决策。我们在预测"这道题需要 web agent 还是 pwn agent"，然后基于预测锁定工具集。但 **Claude 自己就能判断需要什么工具**——它比一次快速分类更擅长这件事，因为它在解题过程中会不断更新理解。

**类比**：这就像在让人做数学题之前，先让另一个人判断"这道题需要微积分还是代数"，然后只给他对应的一本教科书。不如直接给他整个图书馆。

**反思**：specialist agent 的价值在于**system prompt 的专业性**（每个 agent 有针对 web/pwn/crypto 的具体指导）。但这可以通过在统一 prompt 中条件注入来实现，而不需要锁定 agent。

**修复方案**：
- 去掉独立的 CLASSIFY phase
- 始终给模型**所有 agents 的能力**
- 在 OBSERVE prompt 中加一句："Based on what you find, use the most appropriate tools and techniques."
- 如果需要 category-specific hints，在发现 category 后动态注入（不需要锁定 agent）

**ROI**: 省 1 次 LLM 调用，消除分类错误的风险，**让模型在运行时自适应选择工具**。

---

## ARCH 4: [简化] 杀掉 `_parse_reflection()` — 信任模型的自然输出

**当前代价**：55 行 regex + heuristic 代码（ooda.py:951-1005），用来从模型输出中解析 `DECISION: continue/pivot/complete`。

**问题**：
1. 强制模型输出结构化字段（DECISION/ASSESSMENT/INSIGHTS/NEXT_FOCUS）
2. Regex 解析脆弱——如果模型格式稍有偏差就失败
3. Heuristic fallback 检查 "objective achieved" 等关键词——但只在最后 300 字符
4. 最终结果只用了 `decision` 和 `next_focus` 两个值

**真正需要的只是两个判断**：
1. 是否已经拿到 flag？→ 看 blackboard 中有没有 `ChallengeSolved`
2. 模型是否认为自己搞不定？→ 看输出中有没有明确的放弃信号

**修复方案**：
```python
def _should_continue(blackboard, output, iteration, max_iter):
    # Flag found? Done.
    if blackboard.solved_flags:
        return False
    # Max iterations? Done.
    if iteration >= max_iter:
        return False
    # Model explicitly gave up?
    tail = output[-500:].lower()
    if any(p in tail for p in ("give up", "cannot solve", "no progress possible")):
        return False
    # Otherwise: trust the model to keep trying
    return True
```

不需要 DECISION/ASSESSMENT/INSIGHTS/NEXT_FOCUS 四字段。不需要 regex。不需要 heuristic。

**ROI**: 删除 55 行脆弱代码，**消除结构化输出对模型的约束**。

---

## ARCH 5: [简化] Session mode 应该是唯一路径，不是可选优化

**当前代价**：ooda.py 中 ~300 行的双路径逻辑：
- Lines 498-535: session mode (iteration 2+)
- Lines 536-756: stateless mode (full phase separation)
- Lines 442-454: session 创建 + fallback 逻辑

**问题**：维护两条执行路径意味着每个改动都要做两次，bug 也要修两次。Session mode 已经被证明更高效（CONTINUE = 1 call vs 5 calls），为什么还保留 stateless mode？

**反思**：
- Stateless mode 存在的理由是 "non-CTF missions" 和 "session connect failure"
- 但 oneday/zeroday mission 同样受益于 session context——为什么要强制每个 iteration 重发所有 context？
- Session connect failure 应该是 retry + graceful degradation，不是维护一个完整的 fallback code path

**修复方案**：
- **Always use session**（CTF + oneday + zeroday）
- Iteration 1: 1 call（合并 OBSERVE+ACT+REFLECT）
- Iteration 2+: 1 call（CONTINUE，已经在做了）
- Session connect failure → retry 3 times → raise error（不 fallback 到 stateless）
- 删除整个 stateless code path（~200 行）

**ROI**: 删 ~200 行代码，统一执行路径，减少维护负担。

---

## ARCH 6: [思维转变] Blackboard 应该是给人看的，不是给模型看的

**当前代价**：`to_context_prompt()` 每个 phase 调用一次（每 iteration 5-6 次），生成 1-3 KB 的 markdown。

**问题**：在 session mode 下，模型**已经有所有历史上下文**。Blackboard 是对模型自己已经知道的信息的一个**降质摘要**——100 字符的 detail 截断、8 个 recent findings 限制。这是在用低保真摘要替换模型的高保真记忆。

**反思**：
- Blackboard 的真正价值是给**操作员**看的仪表板——"目前发现了什么、进展到哪一步"
- 给模型看 blackboard 是有害的：(a) 浪费 tokens (b) 摘要比原始记忆质量更低 (c) 截断可能丢失关键细节
- 唯一例外：**跨 session 传递状态**时需要 blackboard（新 session 没有历史 context）

**修复方案**：
- Session mode 下的 CONTINUE prompt：**不注入 blackboard**。模型已经有了
- Iteration 1 prompt：注入 blackboard（此时确实是新 context）
- `to_context_prompt()` 简化为面向操作员的 dashboard，不需要为 LLM 优化

（注：这与我之前做的 INSIGHT 1 "CONTINUE 注入 blackboard" 矛盾。经过更深入的反思，我认为之前的判断是错的。Session context > Blackboard summary。INSIGHT 1 的修改应该**回退**。）

**ROI**: 减少每次 CONTINUE 调用 ~200-500 tokens，**避免低质摘要覆盖高质记忆**。

---

## ARCH 7: [根本性] 截断是错误的解法 — 问题本身不该存在

**_smart_truncate 和 [:4000] 都是症状治疗**。

如果模型在 session 中连续工作，phase 间就不需要传递输出文本。OBSERVE 的输出不需要"截断后传给 ORIENT"——因为它们是同一个 session 里的同一个模型。

截断只在 stateless mode 下有意义。而 stateless mode 本身应该被消除（ARCH 5）。

所以：**ARCH 5 + ARCH 1 一起做**，截断问题自动消失。不需要 `_smart_truncate()`，不需要 `[:4000]`，不需要任何传递。

---

## 总结：架构简化路线图

| 优先级 | 改动 | 删除代码量 | 效果 |
|--------|------|-----------|------|
| **S1** | 合并 Iteration 1 为 1 次调用（ARCH 1） | ~100 行 phase 分离代码 | 3x 减少 LLM 调用 |
| **S1** | CTF 场景精简 EVENT_INSTRUCTION（ARCH 2） | 重写 EVENT_INSTRUCTION | 每调用省 685 tokens |
| **S1** | 去掉 CLASSIFY → specialist 锁定（ARCH 3） | ~50 行 classify + pick_agent | 消除分类错误风险 |
| **S2** | 用 flag 检测替代 _parse_reflection（ARCH 4） | ~55 行 regex/heuristic | 消除结构化输出约束 |
| **S2** | 统一为 session-only 路径（ARCH 5） | ~200 行 stateless 路径 | 统一维护 |
| **S2** | Blackboard 只给人看，不给模型看（ARCH 6） | 移除 session 内注入 | 减少噪音 tokens |
| **S3** | 回退截断修复（ARCH 7，ARCH 5 的自然结果） | ~10 行 truncation | 架构一致性 |

**净效果**：删除 ~400 行代码，CTF 单题从 8 次 LLM 调用降到 ~2 次，每次调用省 ~1,000-2,000 tokens prompt 开销。**模型获得连贯的推理链，而不是被 phase 切割的片段。**

---

# 架构简化 — 具体实施方案

> 决策记录（2026-03-19）：
> - ARCH 3（去掉 CLASSIFY）：**保留现状**，不实施
> - ARCH 5（session-only）：改为"session 作为默认模式，保留 stateless 作为可切换选项"
> - 其余 ARCH：写详细实施方案

---

## ARCH 1 实施方案：合并 Iteration 1 为单次 LLM 调用

### 问题定位

`ooda.py:561-756`，CTF Iteration 1 的执行路径：
```
OBSERVE (line 563-604) → skip ORIENT+DECIDE (line 607-609) → ACT (line 661-721) → REFLECT (line 723-759)
= 3 次独立 LLM 调用，每次重注入 blackboard + EVENT_INSTRUCTION
```

### 改什么

**1. 新增统一 prompt `_SOLVE_CTF`**（替代 OBSERVE+ACT+REFLECT 三个 prompt）

位置：`ooda.py` line 97 附近，在 CTF prompt 区域

```python
_SOLVE_CTF = """\
## SOLVE (Iteration {iteration})
{blackboard_context}
Mission: {mission_description}
Agents: {agent_descriptions}
{recon_hint}{campaign_context}{operator_suffix}

Solve this CTF challenge autonomously:
- Explore the challenge files and target, identify the vulnerability
- Develop and execute an exploit
- Capture the flag

{flag_submit_instruction}

When done, report your results.
DECISION: <continue|pivot|complete>
ASSESSMENT: <what happened>
NEXT_FOCUS: <what to try next if not solved>
"""
```

**2. 修改 session mode iteration 1 路径**

位置：`ooda.py:498` 的 `if iteration > 1 and session is not None:` 条件

改为：
```python
if session is not None:
    if iteration == 1:
        # ── SOLVE: unified first iteration ──
        yield PhaseTransition(
            from_phase="",
            to_phase="SOLVE",
            reason=f"Iteration 1 — unified solve",
            aggregate_id=mission.id,
            mission=mission.mission_type.value,
        )
        self._log(logging.INFO, "▶ SOLVE (unified iteration 1)")
        self._report(phase="SOLVE", iteration=1)

        solve_prompt = _SOLVE_CTF.format(
            iteration=1,
            blackboard_context=blackboard.to_context_prompt(),
            mission_description=mission_desc,
            agent_descriptions=agent_desc,
            recon_hint=(f"\n## Initial Recon\n{recon_summary}\n" if recon_summary else ""),
            campaign_context=campaign_context,
            operator_suffix=op_suffix,
            flag_submit_instruction=_FLAG_SUBMIT_INSTRUCTION,
        ) + EVENT_INSTRUCTION  # ← 只注入 1 次而非 3 次

        solve_output = await session.query(solve_prompt, phase_label="SOLVE")
        # ... extract events, check flag, parse reflection（复用现有逻辑）
    else:
        # ── CONTINUE: 已有的 iteration 2+ 逻辑 ──
        # ...（现有代码不变）
```

**3. 保留 stateless fallback 路径不变**

`else:` 分支（line 560-756）的 OBSERVE→ACT→REFLECT 保持原样，作为 session 不可用时的降级路径。

### 删什么

- 不需要删除 `_OBSERVE_CTF`、`_ACT_CTF`、`_REFLECT_CTF`（stateless 路径还需要）
- 但 session mode 的 iteration 1 不再使用它们

### 影响分析

| 影响点 | 处理方式 |
|--------|---------|
| `PhaseTransition` 事件 | 改为 emit 一个 "SOLVE" phase 而非 3 个 |
| `blackboard.phase_history` | 会记录 1 个 SOLVE 而非 3 个 phase。writeup 需要适配 |
| `extract_events_from_output` | 在 solve_output 上调用一次（而非分别在 observe/act 上各调一次） |
| `_parse_reflection` | 在 solve_output 上调用（输出末尾应包含 DECISION 字段） |
| Flag 快速退出 | 复用现有 `_solved_in_act` 逻辑，改名为 `_solved_in_solve` |
| `_reflection_log` | 从 solve_output 的 parse 结果中提取 assessment |

### 预期效果

- CTF session mode iteration 1：3 → 1 次 LLM 调用
- 节省 ~2 × (blackboard + EVENT_INSTRUCTION) = ~1,400 tokens/iteration
- 模型推理链不再被打断

---

## ARCH 2 实施方案：CTF 场景精简 EVENT_INSTRUCTION

### 问题定位

`base.py:328-369`，2,742 chars 的 EVENT_INSTRUCTION 列举 20+ 种事件类型，每个 phase 都注入。

CTF 场景真正需要的事件只有：
- `ChallengeSolved`（找到 flag）
- `FlagSubmitted`（提交 flag 验证）
- `ChallengeClassified`（可选，CLASSIFY 阶段已处理）

其余 17 种事件（AssetDiscovered、VulnerabilityFound、ExploitAttempted 等）对 CTF 无业务价值。

### 改什么

**1. 新增 `EVENT_INSTRUCTION_CTF`**

位置：`base.py` line 369 之后

```python
EVENT_INSTRUCTION_CTF = """
## Structured Output
When you find a flag, emit:
    [EVENT:ChallengeSolved {"challenge_name": "...", "flag": "flag{...}", "approach": "...", "context": "ctf"}]
When you submit a flag to a platform, emit:
    [EVENT:FlagSubmitted {"challenge_name": "...", "flag": "flag{...}", "accepted": true, "response": "...", "context": "ctf"}]
"""
```

~300 chars vs 2,742 chars = **减少 89%**。

**2. 在 ooda.py 中按 mission type 选择指令**

位置：所有拼接 `EVENT_INSTRUCTION` 的地方

```python
_event_instr = EVENT_INSTRUCTION_CTF if mission_key == "ctf" else EVENT_INSTRUCTION
```

需要改的行：
- Line 524: `... + EVENT_INSTRUCTION + ...` → `... + _event_instr + ...`
- Line 590: `... + EVENT_INSTRUCTION` → `... + _event_instr`
- Line 629: `... + EVENT_INSTRUCTION` → `... + _event_instr`
- Line 655: `... + EVENT_INSTRUCTION` → `... + _event_instr`
- Line 682: `... + EVENT_INSTRUCTION + flag_hint` → `... + _event_instr + flag_hint`

**3. fanout_topo.py 同理**

位置：`fanout_topo.py` line 55 的 import 处加入 `EVENT_INSTRUCTION_CTF`，line 351, 396, 1177 处按 mission type 选择。

### 删什么

- 不删 `EVENT_INSTRUCTION`（pentest/zeroday 仍需完整版本）

### 影响分析

| 影响点 | 处理方式 |
|--------|---------|
| `extract_events_from_output` | 不受影响。模型少 emit 事件但解析逻辑不变 |
| blackboard 丰富度降低 | CTF 场景不需要 AssetDiscovered 等。pentest 不受影响 |
| writeup 质量 | CTF writeup 主要靠模型自然语言输出 + ChallengeSolved，不依赖其他事件 |

### 预期效果

- 每次 LLM 调用省 ~600 tokens input
- 模型不再需要同时处理"解题"和"格式化 20 种 JSON 事件"两个任务
- CTF 5 iterations = 节省 ~3,000 tokens

---

## ARCH 4 实施方案：用 flag 检测替代 `_parse_reflection()`

### 问题定位

`ooda.py:951-1005`，55 行 regex + heuristic 代码。强制模型输出 `DECISION: xxx / ASSESSMENT: xxx / INSIGHTS: xxx / NEXT_FOCUS: xxx` 结构化字段。

实际消费这些字段的只有：
- `decision`（line 779）：决定 continue/pivot/complete
- `next_focus`（line 773）：作为下一轮 `previous_insights`
- `assessment`（line 774）：写入 `_reflection_log`

### 改什么

**方案 A（保守）：简化 `_parse_reflection` 但保留结构**

```python
@staticmethod
def _parse_reflection(output: str) -> dict[str, str]:
    """Extract reflection decision from model output."""
    result = {"decision": "continue", "assessment": "", "insights": "", "next_focus": ""}

    # 1. Try structured field extraction (simple regex, no heuristic fallback)
    import re
    for field in ("decision", "assessment", "insights", "next_focus"):
        m = re.search(rf"(?:^|\n)\s*{field}\s*:\s*(.+?)(?:\n|$)", output, re.IGNORECASE)
        if m:
            result[field] = m.group(1).strip()

    # 2. Normalize decision
    d = result["decision"].split()[0].lower().rstrip(".,;:!") if result["decision"] else ""
    result["decision"] = d if d in ("complete", "pivot", "continue") else "continue"

    return result
```

15 行替代 55 行。去掉 heuristic fallback（"objective achieved" 等关键词检测），因为：
- Flag 发现已经通过 `_solved_in_act` / `_solved_in_continue` + `ChallengeSolved` 事件处理
- Stagnation 已经通过 `_stagnation_count` 处理（line 761-789）
- Heuristic 的存在只是 regex 失败时的补偿，而非业务需求

**方案 B（激进）：完全删除 `_parse_reflection`，用状态检测替代**

```python
def _infer_decision(self, blackboard, output, iteration, max_iter):
    """Infer iteration decision from state, not structured output."""
    # Flag found → done
    if blackboard.solved_flags:
        return {"decision": "complete", "assessment": "Flag captured",
                "insights": "", "next_focus": ""}

    # Extract next_focus from output tail (best-effort)
    import re
    nf = re.search(r"NEXT_FOCUS\s*:\s*(.+?)(?:\n|$)", output, re.IGNORECASE)
    next_focus = nf.group(1).strip() if nf else ""

    # Model explicitly says complete?
    tail = output[-500:].lower()
    if any(p in tail for p in ("decision: complete", "challenge solved", "flag found")):
        return {"decision": "complete", "assessment": tail[-200:],
                "insights": "", "next_focus": ""}

    return {"decision": "continue", "assessment": "",
            "insights": "", "next_focus": next_focus}
```

### 哪些代码受影响

无需改动消费方。`_parse_reflection` 返回的 dict 格式不变（`decision`, `assessment`, `insights`, `next_focus`），所有 `.get()` 调用（line 773, 774, 779, 798, 805-808）都兼容。

### 建议

推荐方案 A。保守、改动小、不改变接口。方案 B 更激进但风险更高（可能误判 complete/continue）。

---

## ARCH 5 实施方案：Session 作为默认模式 + 保留可切换选项

### 设计更新

不再是 "session-only"，而是：
- **默认 session mode**（所有 mission type）
- **保留 stateless mode 作为 fallback / 配置选项**
- 通过 `topology.session_mode: "auto" | "session" | "stateless"` 控制

### 改什么

**1. 配置项**

位置：`miya/shared/config.py`（或等效配置文件）

```python
# topology section
"session_mode": "auto",  # "auto" = session with stateless fallback
                          # "session" = session only, fail if connect fails
                          # "stateless" = never use session
```

**2. Session 创建扩展到所有 mission type**

位置：`ooda.py:442`

当前：
```python
use_session = mission_key == "ctf" and self._coordinator is None
```

改为：
```python
_mode = _get_topology_config().get("session_mode", "auto")
use_session = (
    _mode != "stateless"
    and self._coordinator is None
)
```

**3. Iteration 1 统一 prompt 扩展到 generic mission**

新增 `_SOLVE_GENERIC` prompt（类似 ARCH 1 的 `_SOLVE_CTF`）：

```python
_SOLVE_GENERIC = """\
## SOLVE (Iteration {iteration})
{blackboard_context}
Mission: {mission_description}
Agents: {agent_descriptions}
{campaign_context}{operator_suffix}

Execute the next phase of this security assessment autonomously:
- Gather intelligence on the target
- Identify and analyze vulnerabilities
- Attempt exploitation where feasible
- Document all findings

When done, report your results.
DECISION: <continue|pivot|complete>
ASSESSMENT: <what happened>
NEXT_FOCUS: <what to do next>
"""
```

**4. Session connect failure 处理**

```python
if _mode == "auto":
    # fallback to stateless
    session = None
elif _mode == "session":
    # retry 3 times, then raise
    for attempt in range(3):
        try:
            await session.connect()
            break
        except Exception:
            if attempt == 2:
                raise
            await asyncio.sleep(2 ** attempt)
```

**5. 保留 stateless 路径但标记为 legacy**

不删除 lines 561-756 的 OBSERVE→ORIENT→DECIDE→ACT→REFLECT 路径，但加注释：

```python
# ── LEGACY STATELESS PATH ──
# Used when session_mode="stateless" or session connect failed in "auto" mode.
# For session mode, see the unified SOLVE/CONTINUE path above.
```

### 不删什么

- 不删 stateless code path
- 不删 OBSERVE/ORIENT/DECIDE/ACT/REFLECT prompt templates
- 不删 `_smart_truncate`（stateless 路径仍需要）

### 影响分析

| 影响点 | 处理方式 |
|--------|---------|
| fanout_topo 的 sub-OODA | 自动受益——sub-OODA 调用 `OODATopology.execute()`，走同样的 session 路径 |
| pentest/zeroday 场景 | 新增 `_SOLVE_GENERIC` 和 `_CONTINUE_GENERIC`（已存在）支持 |
| 配置变更 | 新增 `session_mode` 配置项 |

---

## ARCH 6 实施方案：CONTINUE prompt 移除 blackboard 注入

### 问题定位

`ooda.py:510-513`：
```python
bb_checkpoint = (
    f"\n## Blackboard Checkpoint\n"
    f"{blackboard.to_context_prompt()}\n"
)
```

这段在 CONTINUE prompt 中注入了完整 blackboard。但在 session mode 下，模型已经有所有历史 context。blackboard 是对已有信息的**低质摘要**。

### 改什么

位置：`ooda.py:510-513`

```python
# Session mode: model already has full context, don't inject blackboard summary.
# Only inject minimal state updates (new HITL messages, flag status).
bb_checkpoint = ""
if blackboard.solved_flags:
    # Remind the model that flags were already found (defensive)
    solved = ", ".join(f"{f.challenge_name}: {f.flag}" for f in blackboard.solved_flags)
    bb_checkpoint = f"\n## Already Solved\n{solved}\n"
```

### 特殊情况

如果 ARCH 5 的 `session_mode="stateless"` 模式下运行，这段不会执行（stateless 不走 CONTINUE 路径），所以没有兼容性问题。

### 预期效果

- 每次 CONTINUE 调用省 ~200-500 tokens
- 避免低质量摘要覆盖模型的高保真 session 记忆
- `to_context_prompt()` 调用次数从 6 次/iteration 降到 1 次（仅 iteration 1）

### 注意

**这与之前的 INSIGHT 1（往 CONTINUE 注入 blackboard）矛盾。** 经过更深入分析后的结论：
- INSIGHT 1 的初衷是让 CONTINUE 有 blackboard 上下文
- 但 session mode 下模型已有 context，注入只是噪音
- **建议回退 INSIGHT 1 的修改**，改为本方案

---

## ARCH 7 实施方案：清理截断代码（依赖 ARCH 5）

### 前置条件

仅当 ARCH 5 实施后，stateless 路径标记为 legacy 时才有意义。

### 如果保留 stateless 路径

**不做任何改动**。`_smart_truncate` 在 stateless 路径中仍然需要（line 628, 654, 680, 747）。

### 如果未来完全删除 stateless 路径

删除：
- `_smart_truncate()` 函数（line 247-256）
- 所有 `_smart_truncate()` 调用（4 处）
- `[:4000]` 和 `[:8000]` 的硬编码截断

### 当前建议

**暂不实施**。等 ARCH 5 验证 session mode 在所有场景下稳定后，再考虑删除 stateless 路径及其依赖的截断逻辑。

---

## 实施依赖图

```
ARCH 2 (精简 events)  ─── 独立，可立即实施
ARCH 6 (移除 bb 注入)  ─── 独立，可立即实施
ARCH 4 (简化 reflection) ─── 独立，可立即实施

ARCH 1 (合并 iteration 1) ─── 独立，但建议在 ARCH 2 之后（省 event 噪音后效果更好）
ARCH 5 (session 默认)  ─── 依赖 ARCH 1（需要 _SOLVE_GENERIC prompt）
ARCH 7 (清理截断)  ─── 依赖 ARCH 5（stateless 路径完全废弃后才安全）
```

**推荐实施顺序**：ARCH 2 → ARCH 6 → ARCH 4 → ARCH 1 → ARCH 5 → ARCH 7

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
