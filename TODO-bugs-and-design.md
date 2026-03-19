# Miya Bot — Bug & 设计问题审查

经过对整个代码库的深度审查，以下是 **14 个可切实落实的 TODO**，按优先级排序。

---

## TODO 1: CostTracker 声称线程安全但实际不安全（竞态条件）

**文件**: `miya/topology/base.py:44-78`

`CostTracker` 的 docstring 写着 "Thread-safe accumulator"，但 `add()` 和 `reset()` 对共享状态的读写没有任何同步机制。`fanout_topo.py` 中多个并发 challenge 会同时调用 `add()`，导致计数器丢失更新。而且 `_cost_tracker` 是全局单例（line 78），跨 mission 共享。

**修复方案**:
- 用 `threading.Lock` 保护 `add()` 和 `reset()`
- 或改用 `asyncio`-safe 的方式（因为项目是 async-first），例如在同一个 event loop 里保证单线程访问
- 去掉全局单例，改为每个 mission 持有独立的 CostTracker 实例

---

## TODO 2: unlimited 模式直接污染 `os.environ` 全局状态

**文件**: `miya/mission/service.py:438-443`

```python
os.environ["MIYA_OODA_MAX_ITERATIONS"] = "999"
os.environ["MIYA_MAX_TURNS"] = "999"
os.environ["MIYA_FANOUT_TIMEOUT"] = "999999"
os.environ["MIYA_SDK_IDLE_TIMEOUT"] = "99999"
```

一旦开启 unlimited 模式，这些环境变量永远不会被恢复。后续在同一进程中的所有 mission 都会继承这些值——即使用户没有传 `--unlimited`。在 interactive 模式（REPL）下尤其危险。

**修复方案**:
- 使用 context manager 在 mission 执行前后保存/恢复环境变量
- 或者不依赖环境变量，将这些参数作为 topology 构造函数参数直接传入

---

## TODO 3: Blackboard 事件投射静默丢弃未知事件类型

**文件**: `miya/shared/blackboard.py:225-229`

```python
projector = getattr(self, f"_on_{event.__class__.__name__}", None)
if projector:
    projector(event)
# else: 什么都不做，没有日志
```

当添加新事件类型时，如果忘记在 Blackboard 上加对应的 `_on_XXX` 方法，事件会被静默忽略，不会有任何警告。这在快速迭代中极易造成数据丢失。

**修复方案**:
- 对未匹配的事件类型至少输出 `logger.debug` 日志
- 考虑维护一份"已知可忽略"的事件类型白名单，对白名单外的未处理事件发出 `logger.warning`
- 或使用 `@singledispatchmethod` 替代字符串拼接的动态分发

---

## TODO 4: `events` 表缺少 `aggregate_id` + `version` 联合唯一约束

**文件**: `miya/infra/event_store.py:19-38`

乐观并发控制依赖 `expected_version` 参数，但数据库层面没有 `UNIQUE(aggregate_id, version)` 约束。如果两个并发写入恰好在 check 和 insert 之间发生（TOCTOU），数据库不会拒绝重复版本号。虽然 `BEGIN IMMEDIATE` 在 SQLite 单文件场景下能缓解，但在 WAL 模式或未来迁移到其他数据库时会暴露。

**修复方案**:
- 添加 `CREATE UNIQUE INDEX IF NOT EXISTS idx_events_aggregate_version ON events(aggregate_id, version)`
- 这是数据完整性的最后一道防线

---

## TODO 5: fanout_topo 中异步任务泄漏

**文件**: `miya/topology/fanout_topo.py:685-716`

```python
except (asyncio.CancelledError, Exception):
    pass  # line 689-690: 吞掉所有异常
```

以及 line 705-716: `_wait_all()` waiter task 和 `_hitl_router()` task 缺乏结构化的生命周期管理。如果 HITL router 抛异常，waiter task 可能永远挂起；反过来如果所有 challenge task 都完成了但 router 没退出，也会泄漏。

**修复方案**:
- 使用 `asyncio.TaskGroup`（Python 3.11+）管理所有子任务的生命周期
- 或在 finally 块中确保所有 task 都被 cancel 并 await
- 把 `except (asyncio.CancelledError, Exception): pass` 改为至少记录日志

---

## TODO 6: Campaign 的 `load()` 缺少 schema 校验

**文件**: `miya/shared/campaign.py:48-63`

```python
data = json.loads(p.read_text(encoding="utf-8"))
entries = [CampaignEntry(**e) for e in data.get("entries", [])]
```

直接将 JSON 字典解包为 `CampaignEntry`。如果文件被手动编辑或版本升级导致字段变化（新增/移除字段），会抛出 `TypeError` 然后回退到空 campaign，丢失所有历史数据。

**修复方案**:
- 用 Pydantic model（项目已有 Pydantic 依赖）校验 campaign JSON
- 对缺失字段提供默认值，对多余字段忽略，保证前向兼容
- 在 save 时写入 schema version，load 时做版本迁移

---

## TODO 7: 全局 30+ 处 bare `except Exception` 需要收敛

**涉及文件**: `main.py`(14处), `mission/service.py`(5处), `topology/ooda.py`(3处), `topology/fanout_topo.py`(4处), `shared/campaign.py`(5处), `infra/event_store.py`(3处) 等

大量 `except Exception` 配合 `pass` 或仅 `logger.warning` 的模式：
- 掩盖了真实错误类型（网络错误 vs 逻辑错误 vs 权限问题完全不同的处理方式）
- 增加调试难度
- 部分地方连 `exc_info=True` 都没加

**修复方案**:
- 逐步替换为具体异常类型（`json.JSONDecodeError`, `OSError`, `aiosqlite.Error`, `asyncio.CancelledError` 等）
- 确保所有 except 块至少记录 `exc_info=True`
- 为项目定义统一的异常层级（`MiyaError` → `StorageError`, `TopologyError`, `AgentError` 等）

---

## TODO 8: `events` 命令的索引越界 bug

**文件**: `miya/main.py:1705`

```python
for i, ev in enumerate(all_ev[-limit:], len(all_ev) - limit + 1)
```

当 `limit > len(all_ev)` 时，`len(all_ev) - limit + 1` 变成负数，导致序号显示错误（从负数开始编号）。

**修复方案**:
```python
start = max(len(all_ev) - limit, 0) + 1
for i, ev in enumerate(all_ev[-limit:], start):
```

---

## TODO 9: writeup 输出路径缺乏路径遍历防护

**文件**: `miya/mission/service.py:62`

```python
filepath = out / f"{safe_name}_{safe_flag}.md"
```

虽然 `safe_name` 和 `safe_flag` 做了 regex 清洗，但 `out` 目录本身来自用户输入（`--output-dir`），没有验证最终路径是否还在预期目录内。如果 flag 内容恰好包含 `../`（regex 不一定能完全过滤），可能写到任意位置。

**修复方案**:
- 在写入前 `filepath.resolve()` 并验证是否以 `out.resolve()` 开头
- 即 `assert filepath.resolve().is_relative_to(out.resolve())`

---

## TODO 10: main.py 中 API key 通过 `os.environ` 传递的安全隐患

**文件**: `miya/main.py:37-39`

```python
os.environ["ANTHROPIC_API_KEY"] = api_key
os.environ["ANTHROPIC_BASE_URL"] = base_url
```

API key 被写入进程环境变量，意味着：
1. 任何子进程（MCP server 等）都能读取
2. `/proc/self/environ` 可泄露（Linux）
3. crash dump 或 debug 日志可能包含

**修复方案**:
- 将 API key 仅通过 SDK 构造参数传递，不写入 `os.environ`
- 如果 MCP server 需要，通过临时环境变量（仅在 subprocess 的 `env` 参数中传递）

---

## TODO 11: OODA topology 的 reflection gate 缺少最大重试上限的全局保障

**文件**: `miya/topology/ooda.py`

OODA 循环的 `max_iterations` 虽然从环境变量读取有默认值，但 reflection 阶段的 pivot 决策可能导致循环在"观察到新信息 → 重新决策 → 又 pivot"的模式中空转。每次 pivot 可能重置某些内部计数器。

**修复方案**:
- 添加一个不可重置的全局 `wall_clock_timeout`（硬性时间上限）
- 在 reflection 结果中追踪 pivot 次数，超过阈值后强制终止
- 记录每次 pivot 的 reason，防止循环 pivot 相同的策略

---

## TODO 12: `config.py` 自定义配置解析器的边界情况

**文件**: `miya/infra/config.py:47-60`

自己实现的 `.env` 文件解析器：
- 不处理转义引号（`value = "he said \"hello\""`）
- 不处理多行值
- 不处理行内注释（`KEY=value # comment` 会把注释作为值的一部分）
- 对无效行静默跳过

**修复方案**:
- 项目已依赖 `python-dotenv`，直接用 `dotenv_values()` 替代自定义解析
- 删除自定义解析代码，减少维护负担

---

## TODO 13: Blackboard 和 Campaign 的线程安全问题

**文件**: `miya/shared/blackboard.py`, `miya/shared/campaign.py`

Blackboard 在 fanout 场景下可能被多个并发 challenge task 同时 `apply()` 事件，导致内部集合（`assets`, `findings`, `credentials` 等字典/列表）的并发修改。Campaign 的 `add()` → `save()` 在并发场景下也可能产生覆写丢失。

**修复方案**:
- Blackboard: 每个 challenge 使用独立的 Blackboard 实例，最终 merge 回主 Blackboard
- Campaign: `save()` 加文件锁（`fcntl.flock` 或 `filelock` 库）
- 或统一通过 event queue 串行化所有写操作

---

## TODO 14: `ch_agg_id` 在比较后才做 truthiness 检查

**文件**: `miya/mission/service.py:488-494`

```python
ch_agg_id = event.aggregate_id
ch_events = [
    e for e in collected_events
    if getattr(e, "challenge_name", "") == event.challenge_name
    or (
        e.aggregate_id == ch_agg_id
        and ch_agg_id  # ← 先比较了再判断非空
        ...
    )
]
```

`e.aggregate_id == ch_agg_id` 在 `ch_agg_id` 为 `None` 时也会匹配所有 `aggregate_id` 为 `None` 的事件，但 `and ch_agg_id` 这个检查在 short-circuit 中永远不会触发（因为 `None == None` 是 `True`，已经通过了第一个条件）。应该把 `ch_agg_id` 检查放在前面。

**修复方案**:
```python
or (
    ch_agg_id  # 先检查非空
    and e.aggregate_id == ch_agg_id
    ...
)
```

---

## 总结优先级

| 优先级 | TODO | 风险 | 工作量 |
|--------|------|------|--------|
| P0 紧急 | #1 CostTracker 竞态 | 数据不准确 | 小 |
| P0 紧急 | #2 os.environ 污染 | 行为异常 | 中 |
| P0 紧急 | #5 async 任务泄漏 | 资源泄漏/挂起 | 中 |
| P1 重要 | #4 缺少 DB 唯一约束 | 数据损坏 | 小 |
| P1 重要 | #8 索引越界 bug | UI 错误 | 小 |
| P1 重要 | #9 路径遍历 | 安全风险 | 小 |
| P1 重要 | #10 API key 泄露 | 安全风险 | 中 |
| P1 重要 | #14 条件判断顺序 | 错误过滤 | 小 |
| P2 改进 | #3 静默丢弃事件 | 调试困难 | 小 |
| P2 改进 | #6 Campaign schema | 数据丢失 | 中 |
| P2 改进 | #7 bare except 收敛 | 维护性差 | 大 |
| P2 改进 | #11 OODA pivot 保障 | 成本浪费 | 中 |
| P2 改进 | #12 配置解析器替换 | 边界 bug | 小 |
| P2 改进 | #13 并发安全 | 数据竞争 | 中 |
