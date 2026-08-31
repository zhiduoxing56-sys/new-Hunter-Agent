const terminalStates = new Set(["success", "failed", "partial", "unsupported_domain"]);

function text(tag, value, className = "") {
  const element = document.createElement(tag);
  element.textContent = value ?? "—";
  if (className) element.className = className;
  return element;
}

function apiError(payload, fallback) {
  const detail = payload?.detail;
  if (typeof detail === "string") return detail;
  return detail?.message || detail?.code || fallback;
}

async function uploadPage() {
  const form = document.querySelector("#upload-form");
  const input = document.querySelector("#file-input");
  const label = document.querySelector("#file-label");
  const button = document.querySelector("#submit-button");
  const error = document.querySelector("#upload-error");
  const mode = document.querySelector("#mode-input");
  const goal = document.querySelector("#goal-input");
  input.addEventListener("change", () => { label.textContent = input.files[0]?.name || "选择一个文件"; });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!input.files.length) return;
    button.disabled = true;
    button.textContent = "正在安全接收…";
    error.classList.add("hidden");
    const body = new FormData();
    body.append("file", input.files[0]);
    body.append("mode", mode.value);
    if (goal.value.trim()) body.append("goal", goal.value.trim());
    try {
      const response = await fetch("/api/tasks", { method: "POST", body });
      const payload = await response.json();
      if (!response.ok) throw new Error(apiError(payload, "上传失败"));
      window.location.assign(payload.task_url);
    } catch (reason) {
      error.textContent = reason.message;
      error.classList.remove("hidden");
      button.disabled = false;
      button.textContent = "开始分析";
    }
  });
}

function addInfo(container, label, value) {
  const group = document.createElement("div");
  group.append(text("dt", label), text("dd", value));
  container.append(group);
}

function renderTask(task) {
  document.querySelector("#task-title").textContent = task.original_filename || task.task_id;
  const badge = document.querySelector("#status-badge");
  badge.textContent = task.status.replaceAll("_", " ");
  badge.className = `badge ${task.status}`;
  const info = document.querySelector("#task-info");
  info.replaceChildren();
  addInfo(info, "文件名", task.original_filename);
  addInfo(info, "文件类型", task.file_description || task.file_type);
  addInfo(info, "SHA-256", task.sha256);
  addInfo(info, "自动识别领域", task.domain);
  addInfo(info, "专业后端", task.backend || "尚未接入");
  addInfo(info, "执行模式", task.execution_mode);
  addInfo(info, "Task ID", task.task_id);
  addInfo(info, "当前状态", task.status);
  addInfo(info, "当前阶段", task.stage);
  const errorPanel = document.querySelector("#error-panel");
  if (task.error || task.status === "unsupported_domain") {
    const detail = task.error || { category: "unsupported_domain", code: "ANALYSIS_DOMAIN_UNSUPPORTED", message: `文件已成功识别为 ${task.domain}，但当前 Web Demo 尚未接入该专业后端。` };
    const target = document.querySelector("#error-info");
    target.replaceChildren();
    addInfo(target, "错误类别", detail.category);
    addInfo(target, "错误代码", detail.code);
    addInfo(target, "简短原因", task.status === "unsupported_domain" ? `文件已成功识别为 ${task.domain}，但当前 Web Demo 尚未接入该专业后端。` : detail.message);
    addInfo(target, "当前阶段", task.stage);
    errorPanel.classList.remove("hidden");
  } else {
    errorPanel.classList.add("hidden");
  }
}

function renderEvents(payload) {
  const list = document.querySelector("#event-list");
  list.replaceChildren();
  if (!payload.events.length) { list.append(text("li", "等待真实事件…", "muted")); return; }
  payload.events.forEach((event) => {
    const item = document.createElement("li");
    if (["failed", "timeout", "cancelled"].includes(event.status)) item.classList.add("failed");
    item.append(text("span", payload.labels[event.event_type] || event.event_type));
    item.append(text("small", `${event.status} · ${new Date(event.timestamp).toLocaleString()}`, "event-meta"));
    list.append(item);
  });
}

function renderCards(containerId, items, titleKeys, bodyKeys) {
  const container = document.querySelector(containerId);
  container.replaceChildren();
  if (!items?.length) { container.append(text("p", "无", "muted")); return; }
  items.forEach((item) => {
    const card = document.createElement("div"); card.className = "result-card";
    const title = titleKeys.map((key) => item[key]).find(Boolean) || "记录";
    const body = bodyKeys.map((key) => item[key]).find(Boolean);
    card.append(text("strong", title));
    if (body) card.append(text("p", body));
    card.append(text("small", item.type || item.finding_id || item.evidence_id || "", "event-meta"));
    container.append(card);
  });
}

const classificationLabels = {
  init: "程序初始化",
  cleanup: "程序清理",
  math: "数学计算",
  utility: "业务/辅助逻辑",
  crypto: "密码学",
  networking: "网络通信",
  io: "输入输出",
  memory: "内存处理",
  string: "字符串处理",
  handler: "事件处理",
  parser: "数据解析",
  unknown: "用途未确定",
};

const runtimeFunctionNames = new Set([
  "_init",
  "_start",
  "_fini",
  "register_tm_clones",
  "deregister_tm_clones",
  "__do_global_dtors_aux",
  "frame_dummy",
]);

function findingName(finding) {
  return finding.metadata?.original_name || finding.title || "未知函数";
}

function isRuntimeFinding(finding) {
  const name = findingName(finding);
  return runtimeFunctionNames.has(name) || name.startsWith("__libc_");
}

function findingCard(finding) {
  const metadata = finding.metadata || {};
  const card = document.createElement("article");
  card.className = "function-card";

  const heading = document.createElement("div");
  heading.className = "function-heading";
  const identity = document.createElement("div");
  identity.append(text("strong", findingName(finding)));
  identity.append(text("code", metadata.signature || metadata.address || ""));
  const kind = text(
    "span",
    classificationLabels[metadata.classification] || metadata.classification || "函数",
    "function-kind",
  );
  heading.append(identity, kind);

  const description = text("p", finding.description || "后端没有提供功能说明。", "function-description");
  const facts = document.createElement("dl");
  facts.className = "function-facts";
  addInfo(facts, "可信度", metadata.confidence == null ? "未提供" : `${metadata.confidence}%`);
  addInfo(facts, "内存地址", metadata.address || "未提供");
  card.append(heading, description, facts);
  return card;
}

function renderFindings(findings) {
  const container = document.querySelector("#findings");
  container.replaceChildren();
  if (!findings?.length) {
    container.append(text("p", "没有得到有效的函数分析结果。", "muted"));
    return;
  }

  const core = findings.filter((finding) => !isRuntimeFinding(finding));
  const runtime = findings.filter(isRuntimeFinding);
  const overview = document.createElement("div");
  overview.className = "finding-overview";
  overview.append(text("strong", `建议先看 ${core.length} 个核心函数`));
  overview.append(text("p", `另外 ${runtime.length} 个是编译器或操作系统生成的启动/清理函数，通常不是程序自身业务逻辑。`));
  container.append(overview);

  core.forEach((finding) => container.append(findingCard(finding)));
  if (runtime.length) {
    const details = document.createElement("details");
    details.className = "runtime-functions";
    details.append(text("summary", `查看 ${runtime.length} 个系统辅助函数`));
    const list = document.createElement("div");
    list.className = "card-list runtime-list";
    runtime.forEach((finding) => list.append(findingCard(finding)));
    details.append(list);
    container.append(details);
  }
}

function interpretationBlock(title, body, tone) {
  const block = document.createElement("div");
  block.className = `interpretation-block ${tone}`;
  block.append(text("strong", title), text("p", body));
  return block;
}

function renderInterpretation(result) {
  const container = document.querySelector("#interpretation");
  container.replaceChildren();
  if (result.agent_id === "kong") {
    const metrics = result.metrics || {};
    const complete = (metrics.errors || 0) === 0 && (metrics.analyzed || 0) > 0;
    container.append(
      interpretationBlock(
        "执行是否正常",
        complete
          ? `正常。Kong 成功分析 ${metrics.analyzed} 个函数，函数级错误为 0。`
          : `不完整。成功分析 ${metrics.analyzed || 0} 个函数，发生 ${metrics.errors || 0} 个函数级错误。`,
        complete ? "verified" : "warning",
      ),
      interpretationBlock(
        "哪些内容可以核验",
        "文件哈希、函数地址和反编译代码来自工具执行；可以下载 decompiled.c 与 analysis.json 复核。",
        "fact",
      ),
      interpretationBlock(
        "这能否证明文件安全",
        "不能。函数名称、用途和可信度是模型基于反编译代码给出的推断；逆向完成不等于无恶意、无漏洞。",
        "warning",
      ),
    );
    return;
  }
  if (result.agent_id === "trudi") {
    const metrics = result.metrics || {};
    const fullMode = metrics.mode === "full";
    const reasoningUsed = metrics.reasoning_backend_used === true;
    const toolCalls = fullMode ? metrics.mcp_tool_calls : metrics.tool_calls;
    container.append(
      interpretationBlock(
        "执行是否正常",
        fullMode
          ? `正常。TRUDI Full 完成了 ${toolCalls || 0} 次有 Trace 的真实工具执行，Reason ${metrics.reason_calls || 0} 次，DAIR ${metrics.dair_calls || 0} 次。`
          : `正常。TRUDI Lite 完成了 ${toolCalls || 0} 次真实 MCP 工具调用。`,
        "verified",
      ),
      interpretationBlock(
        "哪些内容可以核验",
        "SHA-256、文件大小、文件属性和提取字符串来自取证工具，可通过 Trace 和原始产物逐项复核。",
        "fact",
      ),
      interpretationBlock(
        "这能否证明存在恶意行为",
        fullMode && reasoningUsed
          ? "已运行完整自主调查循环；最终裁决是基于当前上传证据的有限结论，仍需结合 Finding、Evidence、Trace 和 Report 人工复核，不能外推为整机安全。"
          : "不能。当前是轻量文件采集，没有运行完整自主推理、IOC 关联或恶意性裁决。",
        "warning",
      ),
    );
  }
}

function renderDfirFindings(result) {
  const container = document.querySelector("#findings");
  container.replaceChildren();
  if (result.metrics?.mode === "full") {
    if (!result.findings?.length) {
      container.append(text("p", "完整调查没有生成可展示的 Finding，请查看 Trace 和 Report。", "muted"));
      return;
    }
    result.findings.forEach((finding) => {
      const metadata = finding.metadata || {};
      const card = document.createElement("article");
      card.className = "result-card";
      card.append(text("strong", finding.title || "TRUDI 调查发现"));
      card.append(text("p", finding.description || "后端没有提供发现说明。"));
      const facts = document.createElement("dl");
      facts.className = "dfir-facts";
      addInfo(facts, "置信度", metadata.confidence || "未提供");
      addInfo(facts, "Trace Call ID", metadata.trace_call_id);
      addInfo(facts, "证据调用", metadata.linked_call_id);
      card.append(facts);
      container.append(card);
    });
    return;
  }
  const finding = result.findings?.[0];
  const metadata = finding?.metadata || {};
  const hashes = document.createElement("dl");
  hashes.className = "dfir-facts";
  addInfo(hashes, "SHA-256", metadata.sha256);
  addInfo(hashes, "SHA-1", metadata.sha1);
  addInfo(hashes, "MD5", metadata.md5);
  container.append(hashes);

  const extracted = result.raw_output?.trudi?.tools?.strings_extract?.ascii_stdout;
  const strings = document.createElement("details");
  strings.className = "runtime-functions";
  strings.append(text("summary", "查看从证据中提取的可读字符串"));
  strings.append(text("pre", extracted || "没有提取到 ASCII 字符串。", "json-block evidence-text"));
  container.append(strings);
}

function renderResult(result) {
  document.querySelector("#result-panel").classList.remove("hidden");
  const metrics = result.metrics || {};
  const kongSummary = result.agent_id === "kong"
    ? `Kong 共发现 ${metrics.total_functions ?? "未知数量"} 个待处理函数，成功分析 ${metrics.analyzed ?? result.findings?.length ?? 0} 个，跳过 ${metrics.skipped ?? 0} 个，失败 ${metrics.errors ?? 0} 个。下面优先展示程序自身的核心逻辑。`
    : null;
  document.querySelector("#summary").textContent = kongSummary || result.summary || "无摘要";
  renderInterpretation(result);
  if (result.agent_id === "trudi") {
    document.querySelector("#result-detail-heading").textContent =
      metrics.mode === "full" ? "自主调查发现" : "取证采集结果";
    renderDfirFindings(result);
  } else {
    document.querySelector("#result-detail-heading").textContent = "函数分析";
    renderFindings(result.findings);
  }
  renderCards("#evidence", result.evidence, ["description", "evidence_id"], ["path"]);
  const artifacts = document.querySelector("#artifacts"); artifacts.replaceChildren();
  if (!result.artifacts?.length) artifacts.append(text("p", "无", "muted"));
  result.artifacts?.forEach((artifact) => {
    const row = document.createElement("div"); row.className = "artifact";
    const meta = document.createElement("div");
    meta.append(text("strong", artifact.type), text("small", `${artifact.size} bytes · ${artifact.sha256}`));
    const link = text("a", "查看 / 下载"); link.href = artifact.download_url;
    row.append(meta, link); artifacts.append(row);
  });
  document.querySelector("#metrics").textContent = JSON.stringify(result.metrics || {}, null, 2);
  document.querySelector("#raw-output").textContent = JSON.stringify(result.raw_output || {}, null, 2);
}

async function taskPage() {
  const taskId = decodeURIComponent(window.location.pathname.split("/").pop());
  let resultLoaded = false;
  async function poll() {
    try {
      const [taskResponse, eventResponse] = await Promise.all([
        fetch(`/api/tasks/${encodeURIComponent(taskId)}`),
        fetch(`/api/tasks/${encodeURIComponent(taskId)}/events`),
      ]);
      if (!taskResponse.ok) throw new Error("任务不存在或无法读取");
      const task = await taskResponse.json();
      renderTask(task);
      if (eventResponse.ok) renderEvents(await eventResponse.json());
      if (task.result_available && !resultLoaded) {
        const response = await fetch(`/api/tasks/${encodeURIComponent(taskId)}/result`);
        if (response.ok) { renderResult(await response.json()); resultLoaded = true; }
      }
      if (!terminalStates.has(task.status)) window.setTimeout(poll, 2000);
    } catch (reason) {
      const panel = document.querySelector("#error-panel"); panel.classList.remove("hidden");
      const target = document.querySelector("#error-info"); target.replaceChildren(); addInfo(target, "错误", reason.message);
    }
  }
  poll();
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.body.dataset.page === "upload") uploadPage();
  if (document.body.dataset.page === "task") taskPage();
});
