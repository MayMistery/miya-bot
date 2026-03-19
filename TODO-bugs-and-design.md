# Miya Bot — Bug & 设计问题深度审查（修订版）

经过对代码库的**二次验证**，剔除误报、补充业务设计缺陷。共 **15 个 TODO**。

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

## TODO 13: [已验证] `events` 表缺少 aggregate_id + version 联合唯一约束

**文件**: `miya/infra/event_store.py:19-38`
**严重性**: P2

验证：乐观并发控制在 `append()` 中检查 `expected_version`（TOCTOU pattern），但 schema 无 `UNIQUE(aggregate_id, version)` 约束。虽然 SQLite 的 `BEGIN IMMEDIATE` 在当前单文件场景下可工作，但缺少 DB 层最终一致性保障。

**修复方案**: 添加唯一索引。

---

## TODO 14: [已验证] CostTracker docstring 误导

**文件**: `miya/topology/base.py:45`
**严重性**: P3（文档）

验证：CostTracker 所有调用都在单一 event loop 内，实际无竞态。但 docstring "Thread-safe accumulator" 是错误的，它既没有锁也不需要锁。

**修复方案**: docstring 改为 "Event-loop-bound accumulator for API usage metrics."

---

## TODO 15: [已验证] `events` 命令序号显示为负数

**文件**: `miya/main.py:1705`
**严重性**: P3（UI）

验证：`limit > len(all_ev)` 时 `enumerate(..., len(all_ev) - limit + 1)` 产生负数起始值。不崩溃，但用户看到负数序号会困惑。

**修复方案**: `start = max(len(all_ev) - limit, 0) + 1`

---

## 总结

| 优先级 | TODO | 类型 | 风险 | 工作量 |
|--------|------|------|------|--------|
| P0 | #1 os.environ 污染 | Bug | REPL 下 mission 行为异常 | 小 |
| P1 | #2 Campaign 前向兼容 | Bug | 升级后数据丢失 | 小 |
| P1 | #3 fanout 异常吞没 | Bug | 调试困难/资源泄漏 | 小 |
| P1 | #4 无自动知识共享 | 业务设计 | 多 challenge 效率低下 | 大 |
| P1 | #5 Mission 状态机不完整 | 业务设计 | resume/中断功能缺失 | 中 |
| P1 | #6 REFLECT heuristic 误判 | 业务设计 | Mission 提前终止 | 中 |
| P1 | #11 事件解析无校验 | 业务设计 | 虚假 flag / 幻觉事件 | 中 |
| P2 | #7 Blackboard context 无界增长 | 业务设计 | Token 浪费 / 成本增长 | 中 |
| P2 | #8 AttackGraph 半成品 | 业务设计 | 用户体验差 | 大 |
| P2 | #9 EventBus 异常不透明 | 设计 | 状态不一致 | 小 |
| P2 | #10 Blackboard 静默丢弃事件 | 设计 | 调试困难 | 小 |
| P2 | #12 ENUMERATE 无 fallback | 业务设计 | 空列表直接放弃 | 中 |
| P2 | #13 DB 缺唯一约束 | 设计 | 数据完整性 | 小 |
| P3 | #14 CostTracker docstring | 文档 | 误导 | 极小 |
| P3 | #15 events 命令负数序号 | UI | 用户困惑 | 极小 |
