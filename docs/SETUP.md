# Hunter-Agent 从零跑通（Setup Guide）

目标：全新机器上，按本说明 clone 并初始化后，Hunter-Agent 四个专业能力
（PentestGPT / FuzzingBrain / TRUDI / Kong）可运行。

## 1. 前置环境

需要本机安装（版本为已验证值，其他接近版本通常也可）：

| 依赖 | 用途 | 参考版本 |
|------|------|---------|
| Docker + Compose | MongoDB/Redis 容器、OSS-Fuzz 构建 | Docker 29.x |
| Python | 主环境 / 子项目 venv | 3.12 |
| JDK | Kong 的 Ghidra 分析 | OpenJDK 21 |
| Ghidra | Kong 逆向后端 | 12.0.4 / 12.1.3 |
| Node.js | TRUDI full（Claude Code runtime） | 22 |
| gcc | 本地测试靶标编译 | 13 |
| DeepSeek API Key | 全局模型（deepseek-v4-flash，仅 flash） | — |

## 2. Clone（包含全部子模块）

```bash
git clone --recurse-submodules https://github.com/zhiduoxing56-sys/new-Hunter-Agent.git
cd new-Hunter-Agent
git submodule update --init --recursive
```

仓库使用以下开源子项目（均为独立仓库，commit 已锁定）：

| 子模块 | 仓库 | 用途 |
|--------|------|------|
| `pentestgpt-core` | https://github.com/zhiduoxing56-sys/pentestgpt-core | 核心协议/任务契约 + PentestGPT |
| `third_party/fuzzingbrain` | https://github.com/zhiduoxing56-sys/FuzzingBrain-V2 | 漏洞挖掘后端（含 DeepSeek 补丁与本地靶标） |
| `third_party/kong` | https://github.com/amruth-sn/kong | 逆向分析后端 |
| `third_party/trudi` | https://github.com/nebulae/trudi | DFIR 取证后端 |
| `fuzzingbrain` 内嵌 `Z-VulnSentinel` | https://github.com/OwenSanzas/Z-VulnSentinel | 静态分析（子模块内自动拉取） |

## 3. 基础服务（MongoDB / Redis / Docker 镜像）

```bash
# 启动 fuzzingbrain 依赖的 Mongo + Redis（项目内非破坏性 compose）
scripts/fuzzingbrain_services.sh up

# 拉取 OSS-Fuzz 基础构建镜像
docker pull gcr.io/oss-fuzz/base-builder

# 初始化 fuzzingbrain 独立 venv 并安装依赖
scripts/fuzzingbrain_bootstrap.sh
```

## 4. DeepSeek 密钥（只进子进程，不进代码/日志）

```bash
# 交互式写入统一密钥存储（不会回显），供 Kong/FuzzingBrain 子进程注入
python3 scripts/set_kong_deepseek.py

# 验证本机真实 flash 调用（不含密钥输出）
third_party/fuzzingbrain/.venv/bin/python scripts/fuzzingbrain_deepseek_audit.py
```

密钥仅注入到 fuzzingbrain / Kong 子进程环境变量，不写入任务、日志与 AgentResult。

## 5. 环境健康自检

```bash
third_party/fuzzingbrain/.venv/bin/python scripts/fuzzingbrain_healthcheck.py
# 期望全部 ok：python / mongodb / redis / docker / oss_fuzz_base_builder
```

## 6. 单能力验证

### FuzzingBrain（漏洞挖掘）—— 真实可复现 PoV
```bash
# 运行固定靶标（hunterdemo）完整任务，产出 ASan heap-buffer-overflow PoV
third_party/fuzzingbrain/.venv/bin/python scripts/fuzzingbrain_run.py \
  --workspace third_party/fuzzingbrain/fixtures/hunterdemo \
  --project hunterdemo --ossfuzz-project hunterdemo \
  --task-type pov-patch --sanitizers address --timeout 25 --budget 5 --pov-count 1

# 无漏洞路径（hunterdemo_fixed，应有 0 POV、超时干净收尾）
third_party/fuzzingbrain/.venv/bin/python scripts/fuzzingbrain_run.py \
  --workspace third_party/fuzzingbrain/fixtures/hunterdemo_fixed \
  --project hunterdemo_fixed --ossfuzz-project hunterdemo_fixed \
  --task-type pov-patch --sanitizers address --timeout 7 --budget 3 --pov-count 1
```

### Web 自主入口（TRUDI/Kong 自动化路由）
```bash
cd pentestgpt-core/pentestgpt_agent && uv sync --extra web
cd ../../..
python3 scripts/run_hunter_web_deepseek.py   # http://127.0.0.1:8000
```

### 自动化测试
```bash
export PYTHONPATH=$PWD:$PWD/pentestgpt-core/pentestgpt_agent/src
pentestgpt-core/.venv/bin/python -m pytest integrations hunter_brain/tests \
  integrations/fuzzingbrain/tests -q
# 期望 113 passed, 10 skipped；FuzzingBrain 真实后端测试在
# HUNTER_FUZZINGBRAIN_LIVE=1 时执行（见下）

# 真实后端 Layer 3 / Layer 4（需要第 3、4 步的服务与密钥）
HUNTER_FUZZINGBRAIN_LIVE=1 \
  pentestgpt-core/.venv/bin/python -m pytest \
  integrations/fuzzingbrain/tests/test_fuzzingbrain_adapter_live.py \
  integrations/fuzzingbrain/tests/test_fuzzingbrain_layer4_live.py -q
```

## 7. 常见问题

- **模型只允许 deepseek-v4-flash**：FuzzingBrain 已严格 flash-only（限流不回退 pro）；
  全局大脑默认 `deepseek-v4-flash`（`HUNTER_MODEL_NAME` 可覆盖为 flash 系）。
- **Kong 需要推理配置**：`KONG_MODEL` / `KONG_BASE_URL` 以及 JDK/Ghidra 路径
  （`HUNTER_KONG_JAVA_HOME`、`GHIDRA_INSTALL_DIR`、`KONG_CONFIG_DIR`）。
- **TRUDI full 需要 Claude Code runtime**：见 `integrations/trudi` 的 lite/full 说明。
- 若 clone 后子模块为空：先 `git submodule update --init --recursive` 再操作。
