const pptxgen = require('pptxgenjs');

const pres = new pptxgen();
pres.layout = 'LAYOUT_16x9';
pres.author = 'SecAgent Team';
pres.title = 'SecAgent 安全 AI Agent 功能演示';

// ── Color Palette (Midnight Security) ──
const C = {
  bgDark:    '0D1B2A',   // deep navy bg
  bgMid:     '162B3D',   // mid-dark for cards
  primary:   '1B6B9A',   // accent blue
  teal:      '1C7293',   // teal accent
  green:     '0EA371',   // success green
  red:       'D14343',   // alert red
  orange:    'E08B35',   // warning orange
  white:     'FFFFFF',
  lightGray: 'E8ECF1',   // light bg for content slides
  textDark:  '1A2332',
  textMid:   '4A5568',
  textLight: '8899AA',
  cardBg:    'F0F4F8',
  border:    'D0D8E0',
};

// ── Helpers ──
function darkSlide(slide, title, subtitle) {
  slide.background = { color: C.bgDark };
  if (title) {
    slide.addText(title, {
      x: 0.7, y: 1.4, w: 8.6, h: 1.0,
      fontSize: 38, fontFace: 'Cambria', bold: true,
      color: C.white, align: 'left',
    });
  }
  if (subtitle) {
    slide.addText(subtitle, {
      x: 0.7, y: 2.3, w: 8.6, h: 0.8,
      fontSize: 16, fontFace: 'Calibri',
      color: C.textLight, align: 'left',
    });
  }
}

function sectionSlide(slide, num, title, desc) {
  slide.background = { color: C.bgDark };
  // accent line (thin strip at top - actually let me avoid accent lines per the instructions)
  // Use a subtle number badge instead
  slide.addShape(pres.shapes.OVAL, {
    x: 0.7, y: 1.2, w: 0.6, h: 0.6,
    fill: { color: C.primary },
  });
  slide.addText(String(num), {
    x: 0.7, y: 1.2, w: 0.6, h: 0.6,
    fontSize: 20, fontFace: 'Calibri', bold: true,
    color: C.white, align: 'center', valign: 'middle',
  });
  slide.addText(title, {
    x: 0.7, y: 2.0, w: 8.6, h: 0.9,
    fontSize: 32, fontFace: 'Cambria', bold: true,
    color: C.white, align: 'left',
  });
  slide.addText(desc, {
    x: 0.7, y: 2.8, w: 8.0, h: 0.7,
    fontSize: 14, fontFace: 'Calibri',
    color: C.textLight, align: 'left',
  });
}

function contentSlide(slide, title) {
  slide.background = { color: C.white };
  // Title bar
  slide.addText(title, {
    x: 0.7, y: 0.35, w: 8.6, h: 0.65,
    fontSize: 26, fontFace: 'Cambria', bold: true,
    color: C.bgDark, align: 'left',
  });
  // subtle separator
  slide.addShape(pres.shapes.RECTANGLE, {
    x: 0.7, y: 1.0, w: 1.2, h: 0.04,
    fill: { color: C.primary },
  });
}

function addCard(slide, x, y, w, h, icon, title, desc, color) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h,
    fill: { color: C.cardBg },
    rectRadius: 0.08,
    shadow: { type: 'outer', blur: 6, offset: 2, color: '00000020', opacity: 0.15 },
  });
  // icon circle
  slide.addShape(pres.shapes.OVAL, {
    x: x + 0.15, y: y + 0.15, w: 0.45, h: 0.45,
    fill: { color: color || C.primary },
  });
  slide.addText(icon, {
    x: x + 0.15, y: y + 0.15, w: 0.45, h: 0.45,
    fontSize: 18, color: C.white, align: 'center', valign: 'middle',
  });
  slide.addText(title, {
    x: x + 0.15, y: y + 0.68, w: w - 0.3, h: 0.35,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark,
    align: 'left', margin: 0,
  });
  slide.addText(desc, {
    x: x + 0.15, y: y + 1.0, w: w - 0.3, h: h - 1.15,
    fontSize: 11, fontFace: 'Calibri', color: C.textMid,
    align: 'left', valign: 'top', margin: 0,
  });
}

function addStatBox(slide, x, y, w, h, number, label, color) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h,
    fill: { color: C.cardBg },
    rectRadius: 0.06,
  });
  slide.addText(number, {
    x, y: y + 0.1, w, h: 0.5,
    fontSize: 28, fontFace: 'Calibri', bold: true,
    color: color || C.primary, align: 'center', valign: 'middle',
  });
  slide.addText(label, {
    x, y: y + 0.55, w, h: 0.3,
    fontSize: 11, fontFace: 'Calibri', color: C.textMid,
    align: 'center', valign: 'top',
  });
}

function addFlowStep(slide, x, y, num, label, desc) {
  slide.addShape(pres.shapes.OVAL, {
    x, y, w: 0.45, h: 0.45, fill: { color: C.primary },
  });
  slide.addText(String(num), {
    x, y, w: 0.45, h: 0.45,
    fontSize: 16, fontFace: 'Calibri', bold: true,
    color: C.white, align: 'center', valign: 'middle',
  });
  slide.addText(label, {
    x: x + 0.55, y: y - 0.03, w: 1.8, h: 0.28,
    fontSize: 12, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  slide.addText(desc, {
    x: x + 0.55, y: y + 0.25, w: 1.8, h: 0.28,
    fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0,
  });
}

// ═══════════════════════════════════════════
// SLIDE 1: COVER
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  s.background = { color: C.bgDark };
  // decorative circles
  s.addShape(pres.shapes.OVAL, {
    x: 6.8, y: -0.8, w: 4.5, h: 4.5,
    fill: { color: '1A2D40', transparency: 60 },
  });
  s.addShape(pres.shapes.OVAL, {
    x: 7.5, y: 2.5, w: 3.0, h: 3.0,
    fill: { color: '1A3350', transparency: 50 },
  });
  // Main title
  s.addText('SecAgent', {
    x: 0.8, y: 1.5, w: 6.0, h: 1.0,
    fontSize: 48, fontFace: 'Cambria', bold: true,
    color: C.white, align: 'left',
  });
  s.addText('安全 AI Agent — 功能演示', {
    x: 0.8, y: 2.4, w: 6.0, h: 0.7,
    fontSize: 24, fontFace: 'Calibri',
    color: C.primary, align: 'left',
  });
  s.addText('基于大模型的安全事件智能分析与自动响应平台', {
    x: 0.8, y: 3.1, w: 6.0, h: 0.5,
    fontSize: 14, fontFace: 'Calibri',
    color: C.textLight, align: 'left',
  });
  // version tag
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.8, y: 3.8, w: 1.3, h: 0.38,
    fill: { color: C.primary, transparency: 30 },
    rectRadius: 0.19,
  });
  s.addText('v0.1.0', {
    x: 0.8, y: 3.8, w: 1.3, h: 0.38,
    fontSize: 11, fontFace: 'Calibri', color: C.white, align: 'center', valign: 'middle',
  });
  // date and footer
  s.addText('2026-07-23  |  项目演示', {
    x: 0.8, y: 4.7, w: 4.0, h: 0.35,
    fontSize: 11, fontFace: 'Calibri', color: C.textLight, align: 'left',
  });
}

// ═══════════════════════════════════════════
// SLIDE 2: 项目概述
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  darkSlide(s, '项目概述', 'SecAgent 是什么？解决了什么问题？');

  // 4 capability cards
  const cards = [
    { icon: '🔍', title: '告警智能研判', desc: 'Kafka/HTTP 双入口接入\nLLM 自动分流 + 多步推理链\n置信度评分 + IOC 自动提取\nATT&CK 知识图谱增强', color: C.primary },
    { icon: '🛡️', title: '漏洞主动扫描', desc: 'Agent 端规则引擎 + Nuclei\n表单式 / 对话式任务创建\n实时 SSE 进度监控\nAI 漏洞等级二次评估', color: C.teal },
    { icon: '⚡', title: '自动响应处置', desc: '10 套 YAML 预设剧本\nL1-L5 分级 HITL 审批\n企微/钉钉实时通知\n幂等执行 + 失败回滚', color: C.orange },
    { icon: '💬', title: '对话式 AI 助手', desc: '4 路意图智能路由\n项目文档 RAG 问答\n联网安全情报搜索\n自然语言驱动扫描', color: C.green },
  ];
  cards.forEach((c, i) => {
    addCard(s, 0.5 + i * 2.25, 3.6, 2.05, 1.75, c.icon, c.title, c.desc, c.color);
  });
}

// ═══════════════════════════════════════════
// SLIDE 3: 系统架构
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '系统架构全景');

  // Left: architecture layers
  const layers = [
    { label: '前端层', tech: 'React 18 + antd5 + TypeScript\nSSE / WebSocket 实时通信', color: '1B6B9A' },
    { label: 'API 网关', tech: 'FastAPI + JWT + RBAC(4角色)\nOpenAPI 强类型 + SSE 推送', color: '1C7293' },
    { label: '编排引擎', tech: 'LangGraph 主图 + 3 子图\ninvestigation · vuln_hunter · responder', color: '0EA371' },
    { label: 'AI 模型', tech: 'DeepSeek / Claude / OpenAI\nModelAdapter 统一抽象', color: 'E08B35' },
    { label: '数据存储', tech: 'ES (事件+审计) · Redis (审批+总线)\nMilvus (向量) · Neo4j (ATT&CK)', color: '8B5CF6' },
    { label: 'Agent 端', tech: 'Go 跨平台 · WebSocket 长连接\n规则引擎 + Nuclei · 自升级', color: 'D14343' },
  ];
  layers.forEach((l, i) => {
    const y = 1.3 + i * 0.65;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.5, y, w: 4.5, h: 0.55,
      fill: { color: C.cardBg },
      rectRadius: 0.06,
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x: 0.5, y, w: 0.07, h: 0.55,
      fill: { color: l.color },
    });
    s.addText(l.label, {
      x: 0.75, y: y + 0.04, w: 1.0, h: 0.25,
      fontSize: 12, fontFace: 'Calibri', bold: true, color: l.color, margin: 0,
    });
    s.addText(l.tech, {
      x: 0.75, y: y + 0.26, w: 4.1, h: 0.26,
      fontSize: 9, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Right: key stats
  const stats = [
    { num: '5/6', label: '中间件就绪' },
    { num: '257', label: '单元测试' },
    { num: '4', label: 'E2E 场景' },
    { num: '4 套', label: 'UI 主题' },
  ];
  stats.forEach((st, i) => {
    addStatBox(s, 5.5 + (i % 2) * 2.1, 1.3 + Math.floor(i / 2) * 1.7, 1.9, 1.5, st.num, st.label, C.primary);
  });
}

// ═══════════════════════════════════════════
// SLIDE 4: 功能地图
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '功能地图 — 五大模块全景');

  const modules = [
    {
      title: '安全告警研判',
      items: ['Kafka/HTTP 双入口', 'LLM 智能分流', '多步推理链', 'IOC 提取+脱敏', 'GraphRAG 知识增强', '全程审计追踪'],
      color: C.primary,
    },
    {
      title: '漏洞扫描',
      items: ['表单式+对话式创建', 'matcher + Nuclei 双引擎', 'SSE 实时进度监控', 'AI 等级二次评估', '漏洞生命周期管理', 'HTML 报告导出'],
      color: C.teal,
    },
    {
      title: '响应处置',
      items: ['10套 YAML 预设剧本', 'L1-L5 分级 HITL 审批', 'Redis 原子 quorum', '企微/钉钉通知', '幂等执行+失败回滚', 'Celery 超时兜底'],
      color: C.orange,
    },
    {
      title: '主机纳管',
      items: ['Agent 注册入网', 'WS 长连接通信', '主机分组管理', '远程升级推送', '规则签名分发', '资源实时监控'],
      color: C.green,
    },
    {
      title: 'AI 对话 & 平台',
      items: ['4路意图路由', '项目文档 RAG', '联网安全搜索', '多模型管理', '规则离线导入', '四套 UI 主题'],
      color: '8B5CF6',
    },
  ];
  modules.forEach((m, i) => {
    const x = 0.4 + i * 1.88;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 1.3, w: 1.72, h: 3.4,
      fill: { color: C.cardBg },
      rectRadius: 0.08,
    });
    s.addText(m.title, {
      x, y: 1.4, w: 1.72, h: 0.4,
      fontSize: 12, fontFace: 'Calibri', bold: true, color: m.color, align: 'center',
    });
    m.items.forEach((item, j) => {
      s.addText('▸ ' + item, {
        x: x + 0.12, y: 1.9 + j * 0.38, w: 1.48, h: 0.3,
        fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0,
      });
    });
  });

  // Bottom: tech stack line
  s.addText('Python 3.11 · FastAPI · LangGraph 0.2.28 · React 18 · antd5 · Go 1.22 · ES · Redis · Milvus · Neo4j · Kafka · Docker', {
    x: 0.5, y: 4.9, w: 9.0, h: 0.35,
    fontSize: 9, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 5: 登录与主题
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '认证体系 & 多主题切换');

  // Left: RBAC table
  s.addText('RBAC 四角色权限矩阵', {
    x: 0.5, y: 1.3, w: 4.0, h: 0.35,
    fontSize: 15, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const roles = [
    ['角色', '权限', '菜单数'],
    ['admin (管理员)', '全部读写', '9'],
    ['analyst (分析师)', '分析+查看', '7'],
    ['responder (响应员)', '响应+审批', '7'],
    ['viewer (观察者)', '只读', '6'],
  ];
  roles.forEach((row, ri) => {
    const y = 1.75 + ri * 0.42;
    const bg = ri === 0 ? C.bgDark : (ri % 2 === 0 ? C.cardBg : C.white);
    row.forEach((cell, ci) => {
      s.addShape(pres.shapes.RECTANGLE, {
        x: 0.5 + ci * 1.5, y, w: ci === 0 ? 1.8 : 1.5, h: 0.42,
        fill: { color: bg },
      });
      s.addText(cell, {
        x: 0.55 + ci * 1.5, y, w: (ci === 0 ? 1.7 : 1.4), h: 0.42,
        fontSize: ri === 0 ? 11 : 10, fontFace: 'Calibri',
        bold: ri === 0, color: ri === 0 ? C.white : C.textDark,
        align: 'center', valign: 'middle', margin: 0,
      });
    });
  });

  // Right: 4 themes
  s.addText('四套 UI 主题', {
    x: 5.5, y: 1.3, w: 4.0, h: 0.35,
    fontSize: 15, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const themes = [
    { name: '亮色模式', desc: '白底黑字 · 亮侧栏', bg: C.white, fg: C.textDark, border: C.border },
    { name: '暗色模式', desc: '黑底白字 · 暗侧栏', bg: C.bgDark, fg: C.white, border: '2A3A4A' },
    { name: '混合-亮侧栏', desc: '亮侧栏 + 暗内容区', bg: C.cardBg, fg: C.textDark, border: C.border },
    { name: '混合-暗侧栏', desc: '暗侧栏 + 亮内容区', bg: '1A2D40', fg: C.white, border: '2A3A4A' },
  ];
  themes.forEach((t, i) => {
    const y = 1.75 + i * 0.8;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 5.5, y, w: 4.0, h: 0.65,
      fill: { color: t.bg },
      rectRadius: 0.06,
      line: { color: t.border, width: 0.5 },
    });
    s.addText(t.name, {
      x: 5.7, y: y + 0.05, w: 1.6, h: 0.28,
      fontSize: 12, fontFace: 'Calibri', bold: true, color: t.fg, margin: 0,
    });
    s.addText(t.desc, {
      x: 5.7, y: y + 0.32, w: 3.6, h: 0.25,
      fontSize: 10, fontFace: 'Calibri', color: t.fg === C.white ? C.textLight : C.textMid, margin: 0,
    });
  });

  // Bottom
  s.addText('JWT 认证  ·  axios 401 拦截器  ·  SSE 通过 ?token= 鉴权  ·  演示数据一键注入（管理员可见）', {
    x: 0.5, y: 5.0, w: 9.0, h: 0.35,
    fontSize: 10, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 6: 态势感知大屏
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '态势感知大屏 — 实时数据可视化');

  // 4 stat cards on top
  const stats = [
    { num: '1,284', label: '总事件数', color: C.primary },
    { num: '356', label: '真阳性', color: C.green },
    { num: '12', label: '待审批', color: C.orange },
    { num: '2.3s', label: '平均处理时长', color: C.teal },
  ];
  stats.forEach((st, i) => {
    addStatBox(s, 0.5 + i * 2.3, 1.25, 2.1, 1.15, st.num, st.label, st.color);
  });

  // Chart descriptions (3 columns)
  const charts = [
    { title: '结论分布（饼图）', desc: '真阳性 / 假阳性 / 未知 / 忽略\n中文标签 + 颜色映射', icon: '◉' },
    { title: '定级分布（柱状图）', desc: '严重 → 高危 → 中危 → 低危 → 提示\n五级颜色梯度映射', icon: '📊' },
    { title: '事件趋势（折线图）', desc: '24h 时间序列\n按 verdict 分类展示\n支持时间窗口切换', icon: '📈' },
  ];
  charts.forEach((ch, i) => {
    const x = 0.5 + i * 3.1;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 2.7, w: 2.9, h: 1.65,
      fill: { color: C.cardBg },
      rectRadius: 0.08,
    });
    s.addText(ch.icon + '  ' + ch.title, {
      x: x + 0.15, y: 2.85, w: 2.6, h: 0.35,
      fontSize: 13, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
    });
    s.addText(ch.desc, {
      x: x + 0.15, y: 3.25, w: 2.6, h: 0.9,
      fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // SSE note
  s.addText('⚡ SSE 实时推送：Redis pub/sub 跨 worker fan-out → 前端无需手动刷新 → 指标/事件/审批状态秒级更新', {
    x: 0.5, y: 4.6, w: 9.0, h: 0.35,
    fontSize: 11, fontFace: 'Calibri', bold: true, color: C.primary, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 7: 事件研判
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '事件队列 & 推理链详情');

  // Left: Event Queue features
  s.addText('事件队列', {
    x: 0.5, y: 1.3, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const queueFeatures = [
    '事件列表：ID / 源 / 定级 / 结论 / 置信度 / 状态',
    '筛选：按定级、结论、状态过滤',
    '分页查询 + SSE 实时追加新事件',
    '事件状态：processing → completed / pending_approval / ignored',
  ];
  queueFeatures.forEach((f, i) => {
    s.addText('• ' + f, {
      x: 0.5, y: 1.7 + i * 0.3, w: 4.5, h: 0.28,
      fontSize: 9.5, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Right: Reasoning chain
  s.addText('推理链 Timeline', {
    x: 5.5, y: 1.3, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const steps = [
    { label: 'entry', desc: '校验事件、写审计' },
    { label: 'orchestrator', desc: '蜜罐规则 / LLM 分流决策' },
    { label: 'cti_analyst', desc: 'VT 查询 + GraphRAG 情报召回' },
    { label: 'investigator', desc: 'CoT 提示 → verdict + confidence' },
    { label: 'aggregator', desc: '汇聚结果 → 写审计 → 决定下一步' },
    { label: 'route_after', desc: 'conf≥0.8→respond / 0.5-0.8→vuln / <0.5→done' },
  ];
  steps.forEach((st, i) => {
    const y = 1.7 + i * 0.52;
    s.addShape(pres.shapes.OVAL, {
      x: 5.5, y: y + 0.02, w: 0.32, h: 0.32, fill: { color: C.primary },
    });
    s.addText(String(i + 1), {
      x: 5.5, y: y + 0.02, w: 0.32, h: 0.32,
      fontSize: 10, fontFace: 'Calibri', bold: true, color: C.white, align: 'center', valign: 'middle',
    });
    if (i < steps.length - 1) {
      s.addShape(pres.shapes.RECTANGLE, {
        x: 5.65, y: y + 0.34, w: 0.02, h: 0.2, fill: { color: C.border },
      });
    }
    s.addText(st.label, {
      x: 6.0, y, w: 1.5, h: 0.22,
      fontSize: 11, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
    });
    s.addText(st.desc, {
      x: 6.0, y: y + 0.22, w: 3.5, h: 0.22,
      fontSize: 9, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Bottom feature bar
  s.addText('IOC 自动提取（IP/域名/Hash/URL） → 自动脱敏（密码/PII/Hash） → SSE 实时推送推理步骤 → 全程 ES 审计', {
    x: 0.5, y: 5.05, w: 9.0, h: 0.3,
    fontSize: 9.5, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 8: 审批流程
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, 'HITL 分级审批流程');

  // Flow diagram
  const flow = [
    { label: '事件完成研判', desc: 'true_positive\nconf ≥ 0.8', color: C.primary },
    { label: '剧本匹配', desc: '10 YAML 剧本\nLLM 兜底', color: C.teal },
    { label: 'L1/L2 自动', desc: '低风险\n自动批准执行', color: C.green },
    { label: 'L3 单人审批', desc: 'Redis quorum\n1 人即可', color: C.orange },
    { label: 'L4/L5 双人', desc: '高敏感操作\n2 人 quorum', color: C.red },
    { label: '执行/拒绝', desc: 'ActionDispatcher\ndry_run 安全闸', color: C.bgDark },
  ];
  flow.forEach((f, i) => {
    const x = 0.3 + i * 1.6;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 1.45, w: 1.4, h: 1.35, fill: { color: C.cardBg }, rectRadius: 0.08,
    });
    s.addShape(pres.shapes.RECTANGLE, {
      x, y: 1.45, w: 1.4, h: 0.06, fill: { color: f.color },
    });
    s.addText(f.label, {
      x, y: 1.6, w: 1.4, h: 0.3,
      fontSize: 11, fontFace: 'Calibri', bold: true, color: C.textDark, align: 'center',
    });
    s.addText(f.desc, {
      x: x + 0.1, y: 1.95, w: 1.2, h: 0.7,
      fontSize: 9, fontFace: 'Calibri', color: C.textMid, align: 'center',
    });
    // arrow
    if (i < flow.length - 1) {
      s.addText('→', {
        x: x + 1.4, y: 1.8, w: 0.2, h: 0.5,
        fontSize: 18, color: C.textLight, align: 'center', valign: 'middle',
      });
    }
  });

  // Detail cards below
  const details = [
    { title: '审批存储', desc: 'Redis Hash + Set + ZSet\nLua 脚本原子 quorum\npub/sub 实时通知' },
    { title: '通知渠道', desc: '企微 Webhook\n钉钉 Webhook\n审批卡推送' },
    { title: '超时兜底', desc: 'Celery 定时任务\n超时自动 timeout\n双保险机制' },
    { title: '处置动作', desc: 'notify / siem_tag\ndns_block / firewall\ndry_run 默认开启' },
  ];
  details.forEach((d, i) => {
    const x = 0.5 + i * 2.35;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 3.15, w: 2.15, h: 1.5, fill: { color: C.cardBg }, rectRadius: 0.08,
    });
    s.addText(d.title, {
      x: x + 0.15, y: 3.25, w: 1.85, h: 0.3,
      fontSize: 13, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
    });
    s.addText(d.desc, {
      x: x + 0.15, y: 3.6, w: 1.85, h: 0.85,
      fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });
}

// ═══════════════════════════════════════════
// SLIDE 9: 主机纳管
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '主机纳管 — Agent 注册 · 分组 · 升级');

  // Enrollment flow
  s.addText('Agent 注册入网流程', {
    x: 0.5, y: 1.25, w: 4.5, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const enrollSteps = [
    { num: '1', label: '创建注册令牌', desc: '服务端生成一次性 enroll token，设置 TTL 过期' },
    { num: '2', label: '安装 Agent', desc: 'curl pipe bash / 下载脚本 / 手动安装二进制' },
    { num: '3', label: 'Ed25519 密钥交换', desc: 'Agent 携带 token 注册，获取 agent_id + 签名公钥' },
    { num: '4', label: '建立 WS 长连接', desc: 'Agent 连接 WebSocket，开始心跳，可接收指令' },
  ];
  enrollSteps.forEach((es, i) => {
    const y = 1.65 + i * 0.56;
    s.addShape(pres.shapes.OVAL, {
      x: 0.6, y: y + 0.03, w: 0.35, h: 0.35, fill: { color: C.primary },
    });
    s.addText(es.num, {
      x: 0.6, y: y + 0.03, w: 0.35, h: 0.35,
      fontSize: 14, fontFace: 'Calibri', bold: true, color: C.white, align: 'center', valign: 'middle',
    });
    s.addText(es.label, {
      x: 1.15, y, w: 2.2, h: 0.22,
      fontSize: 11, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
    });
    s.addText(es.desc, {
      x: 1.15, y: y + 0.22, w: 3.8, h: 0.22,
      fontSize: 9, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Right: feature list
  s.addText('纳管功能', {
    x: 5.5, y: 1.25, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const mgmtFeatures = [
    ['主机分组', '按业务/环境创建分组，主机拖拽归类'],
    ['状态监控', '在线 / 离线 / 已下线，最后心跳时间'],
    ['远程升级', '服务端推送新版本 → Agent 自升级 → 确认回执'],
    ['规则分发', '规则包 Ed25519 签名 → WS 下发 → Agent 热加载'],
    ['生命周期', '注册 → 在线 → 下线(decommission) → 永久删除'],
    ['资源采集', 'Agent 端采集 CPU/内存/磁盘，心跳上报'],
  ];
  mgmtFeatures.forEach((f, i) => {
    const y = 1.6 + i * 0.46;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 5.5, y, w: 4.2, h: 0.38, fill: { color: C.cardBg }, rectRadius: 0.05,
    });
    s.addText(f[0], {
      x: 5.65, y: y + 0.04, w: 1.2, h: 0.3,
      fontSize: 10, fontFace: 'Calibri', bold: true, color: C.primary, margin: 0,
    });
    s.addText(f[1], {
      x: 6.9, y: y + 0.04, w: 2.65, h: 0.3,
      fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Bottom badge
  s.addText('Go 跨平台 Agent (Linux/Windows/macOS)  ·  Ed25519 签名防篡改  ·  WebSocket 双向通信  ·  进程自我保护', {
    x: 0.5, y: 4.95, w: 9.0, h: 0.3,
    fontSize: 9.5, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 10: 漏洞扫描
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '漏洞扫描 — 表单式 & 对话式双入口');

  // Left: Form-based
  s.addText('表单式创建', {
    x: 0.5, y: 1.3, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const formFeatures = [
    '目标选择器：按主机组 / 主机名 / IP-CIDR',
    '扫描模块：系统漏洞 (sys_vuln) / 安全基线 (baseline)',
    '双引擎：matcher (CVE 精确匹配) / Nuclei (YAML 模板)',
    '资源限制：CPU / 内存上限，避免影响业务',
    '定时调度：cron 表达式定时执行',
    '任务列表：查看历史任务，跳转监控',
  ];
  formFeatures.forEach((f, i) => {
    s.addText('• ' + f, {
      x: 0.5, y: 1.7 + i * 0.35, w: 4.5, h: 0.3,
      fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Right: Chat-based
  s.addText('对话式创建 (ChatScan)', {
    x: 5.5, y: 1.3, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  // Chat example box
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 5.5, y: 1.7, w: 4.2, h: 2.8, fill: { color: C.cardBg }, rectRadius: 0.08,
  });
  const chatMsgs = [
    { role: '👤', text: '扫描 web-server 组的主机，检查系统漏洞', color: C.textDark },
    { role: '🤖', text: '好的，我将对 web-server 组（3台主机）执行\n系统漏洞扫描。使用 Nuclei 引擎。\n[确认卡片：目标/模块/引擎]  [执行扫描]', color: C.primary },
    { role: '👤', text: '加上基线检查', color: C.textDark },
    { role: '🤖', text: '已更新：扫描模块 = 系统漏洞 + 安全基线。\n[更新确认卡片]  [执行扫描]', color: C.primary },
  ];
  chatMsgs.forEach((m, i) => {
    s.addText(m.role + '  ' + m.text, {
      x: 5.7, y: 1.85 + i * 0.63, w: 3.8, h: 0.55,
      fontSize: 8.5, fontFace: 'Calibri', color: m.color, margin: 0,
    });
  });

  // Bottom
  s.addText('意图解析自动执行  ·  多轮对话细化需求  ·  确认卡片防误操作  ·  对话历史持久化  ·  多会话管理  ·  模型动态切换', {
    x: 0.5, y: 4.85, w: 9.0, h: 0.3,
    fontSize: 9.5, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 11: 扫描监控
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '扫描监控 — SSE 实时进度推送');

  // Left: scan flow
  s.addText('扫描执行链路', {
    x: 0.5, y: 1.25, w: 4.5, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const scanSteps = [
    '① 创建任务 → 放入 Redis Stream',
    '② TaskWorker 消费 → 通过 WS 下发 scan_command',
    '③ Agent 收到指令 → 执行扫描（matcher/Nuclei）',
    '④ Agent 实时上报结果 → WS → TaskWorker 写 ES',
    '⑤ SSE 推送到前端监控页 → 进度条更新',
    '⑥ 任务完成 → 可下载 HTML 报告',
  ];
  scanSteps.forEach((st, i) => {
    const y = 1.7 + i * 0.4;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.5, y, w: 4.5, h: 0.32, fill: { color: i % 2 === 0 ? C.cardBg : C.white }, rectRadius: 0.04,
    });
    s.addText(st, {
      x: 0.65, y, w: 4.2, h: 0.32,
      fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0, valign: 'middle',
    });
  });

  // Right: SSE event types
  s.addText('SSE 事件类型', {
    x: 5.5, y: 1.25, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const sseEvents = [
    { type: 'scan_start', desc: '扫描开始，总主机数/模块数' },
    { type: 'host_start', desc: '开始扫描某台主机' },
    { type: 'finding', desc: '发现一个漏洞（CVE/严重等级/修复建议）' },
    { type: 'host_done', desc: '某台主机扫描完成' },
    { type: 'task_progress', desc: '进度百分比更新' },
    { type: 'task_done', desc: '全部完成（或 task_error 失败）' },
  ];
  sseEvents.forEach((ev, i) => {
    const y = 1.7 + i * 0.46;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 5.5, y, w: 0.9, h: 0.35, fill: { color: C.bgDark }, rectRadius: 0.05,
    });
    s.addText(ev.type, {
      x: 5.5, y, w: 0.9, h: 0.35,
      fontSize: 8.5, fontFace: 'Calibri', color: C.green, align: 'center', valign: 'middle',
    });
    s.addText(ev.desc, {
      x: 6.55, y, w: 3.15, h: 0.35,
      fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0, valign: 'middle',
    });
  });

  // Monitor features
  s.addText('监控页特性：实时进度条  ·  事件流日志  ·  发现列表  ·  取消任务  ·  AI 等级评估  ·  一键下载报告', {
    x: 0.5, y: 4.85, w: 9.0, h: 0.3,
    fontSize: 10, fontFace: 'Calibri', bold: true, color: C.primary, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 12: 漏洞清单与报告
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '漏洞清单 & 扫描报告');

  // Left: Vuln list
  s.addText('漏洞清单', {
    x: 0.5, y: 1.3, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const vulnFeatures = [
    '全量漏洞数据库：CVE / 名称 / 等级 / 主机 / 类别 / 修复建议',
    '筛选器：按严重等级 (critical~info) 和状态过滤',
    '批量操作：勾选多条 → 标记已修复 / 已接受',
    'AI 过滤标记：AI 判断为误报的单独标记',
    '单条操作：查看详情 → 查看修复建议 → 更新状态',
    '状态流转：open → fixed / accepted',
  ];
  vulnFeatures.forEach((f, i) => {
    s.addText('• ' + f, {
      x: 0.5, y: 1.7 + i * 0.32, w: 4.5, h: 0.28,
      fontSize: 9.5, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Right: Report
  s.addText('扫描报告', {
    x: 5.5, y: 1.3, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const reportFeatures = [
    { title: '任务摘要', desc: '任务 ID / 创建时间 / 状态 / 目标主机数' },
    { title: '统计分布', desc: '总数 / 严重 / 高危 / 中危 / 低危 分布统计' },
    { title: '主机汇总', desc: '每台主机的问题数量排行' },
    { title: '详细发现', desc: '每条漏洞的 CVE + 修复建议 + 来源' },
    { title: 'HTML 导出', desc: '包含统计图表 + 详细列表的完整报告' },
    { title: '按 task_id', desc: '查询任意已完成任务的报告' },
  ];
  reportFeatures.forEach((rf, i) => {
    const y = 1.7 + i * 0.45;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 5.5, y, w: 4.2, h: 0.38, fill: { color: C.cardBg }, rectRadius: 0.05,
    });
    s.addText(rf.title, {
      x: 5.65, y: y + 0.04, w: 1.3, h: 0.3,
      fontSize: 10, fontFace: 'Calibri', bold: true, color: C.primary, margin: 0,
    });
    s.addText(rf.desc, {
      x: 7.0, y: y + 0.04, w: 2.55, h: 0.3,
      fontSize: 9.5, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  s.addText('漏洞数据存储于 ES  ·  报告支持导出 HTML（含 echarts 图表）  ·  支持按 task_id / hostname / severity 筛选', {
    x: 0.5, y: 4.9, w: 9.0, h: 0.3,
    fontSize: 9.5, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 13: 规则与模型管理
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '规则管理 & 模型管理');

  // Top: Rule management
  s.addText('规则管理', {
    x: 0.5, y: 1.25, w: 4.5, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const ruleFeatures = [
    '规则列表浏览（名称 / CVE / 分类 / 严重等级 / 修复建议）',
    '筛选搜索（按分类 sys_vuln/baseline、等级、关键词）',
    '规则详情查看（匹配条件、检测逻辑）',
    '离线导入 ZIP 规则包',
    '一键同步到所有在线 Agent（Ed25519 签名）',
    '版本号追踪，增量更新',
  ];
  ruleFeatures.forEach((f, i) => {
    s.addText('• ' + f, {
      x: 0.5, y: 1.65 + i * 0.32, w: 4.5, h: 0.28,
      fontSize: 9.5, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  // Agent sync flow
  s.addText('规则分发链路：上传包 → 版本递增 → WS 下发 rule_sync (Ed25519 签名) → Agent 验证签名 → 下载 → 热加载', {
    x: 0.5, y: 3.65, w: 4.5, h: 0.35,
    fontSize: 9, fontFace: 'Calibri', color: C.primary, margin: 0,
  });

  // Right: Model management
  s.addText('模型管理', {
    x: 5.5, y: 1.25, w: 4.5, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const modelFeatures = [
    ['多模型支持', 'OpenAI · Claude · vLLM · 本地'],
    ['CRUD 管理', '添加 / 编辑 / 删除 / 启用 / 禁用'],
    ['默认切换', '设置当前生效的默认 LLM'],
    ['参数配置', 'temperature · max_tokens · base_url'],
    ['API Key 安全', '列表不返回明文，仅显示已配置'],
    ['预置模型', '4 家服务商预置参数开箱即用'],
    ['DB 持久化', 'llm_models 表存储，重启不丢失'],
  ];
  modelFeatures.forEach((mf, i) => {
    const y = 1.65 + i * 0.38;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 5.5, y, w: 4.2, h: 0.32, fill: { color: C.cardBg }, rectRadius: 0.05,
    });
    s.addText(mf[0], {
      x: 5.65, y: y + 0.03, w: 1.2, h: 0.26,
      fontSize: 10, fontFace: 'Calibri', bold: true, color: C.teal, margin: 0,
    });
    s.addText(mf[1], {
      x: 6.9, y: y + 0.03, w: 2.65, h: 0.26,
      fontSize: 9.5, fontFace: 'Calibri', color: C.textMid, margin: 0,
    });
  });

  s.addText('ModelAdapter 统一抽象层  ·  structured output (JSON Schema)  ·  模型切换不影响业务代码', {
    x: 0.5, y: 4.9, w: 9.0, h: 0.3,
    fontSize: 9.5, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ═══════════════════════════════════════════
// SLIDE 14: AI 对话助手
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, 'AI 对话助手 — 四路意图智能路由');

  // 4 route cards
  const routes = [
    {
      icon: '🔍', title: 'scan — 扫描意图',
      desc: '自然语言 → 结构化 ScanIntent\n目标/模块/引擎自动提取\n确认卡片 → 一键执行',
      color: C.primary, x: 0.4,
    },
    {
      icon: '📚', title: 'project — 项目问答',
      desc: '基于 docs/ 本地文档检索\nRAG 增强 LLM 回答\n标注文件来源',
      color: C.teal, x: 2.7,
    },
    {
      icon: '🌐', title: 'web — 联网搜索',
      desc: 'DuckDuckGo HTML 搜索\n最新 CVE/安全新闻\n标注 URL 来源',
      color: C.orange, x: 5.0,
    },
    {
      icon: '💬', title: 'chat — 自由对话',
      desc: '通用聊天\n知识问答\n助手介绍',
      color: C.green, x: 7.3,
    },
  ];
  routes.forEach((r) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: r.x, y: 1.4, w: 2.15, h: 2.0, fill: { color: C.cardBg }, rectRadius: 0.08,
    });
    // icon
    s.addShape(pres.shapes.OVAL, {
      x: r.x + 0.7, y: 1.55, w: 0.55, h: 0.55, fill: { color: r.color },
    });
    s.addText(r.icon, {
      x: r.x + 0.7, y: 1.55, w: 0.55, h: 0.55,
      fontSize: 20, align: 'center', valign: 'middle',
    });
    s.addText(r.title, {
      x: r.x + 0.1, y: 2.2, w: 1.95, h: 0.3,
      fontSize: 12, fontFace: 'Calibri', bold: true, color: C.textDark, align: 'center',
    });
    s.addText(r.desc, {
      x: r.x + 0.1, y: 2.55, w: 1.95, h: 0.7,
      fontSize: 9.5, fontFace: 'Calibri', color: C.textMid, align: 'center',
    });
  });

  // Architecture description
  s.addText('技术架构', {
    x: 0.5, y: 3.7, w: 3.0, h: 0.3,
    fontSize: 13, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  s.addText('用户消息 → /api/v1/chat → LLM 意图分类（4选1）\n├─ scan  → ScanIntent 解析 → 前端确认卡片\n├─ project → DocSearch(docs/) → RAG → 带来源回答\n├─ web  → DDG HTML Search → RAG → 带URL来源回答\n└─ chat  → 直接 LLM 回答', {
    x: 0.5, y: 4.0, w: 9.0, h: 1.2,
    fontSize: 10, fontFace: 'Calibri', color: C.textMid, margin: 0,
  });
}

// ═══════════════════════════════════════════
// SLIDE 15: 技术指标
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  contentSlide(s, '工程质量 & 技术指标');

  // Stat cards
  const qualityStats = [
    { num: '257', label: '单元测试', sub: 'pytest (121单测 + 10集成)', color: C.green },
    { num: '52%', label: '代码覆盖率', sub: '核心 Agent 逻辑全覆盖', color: C.primary },
    { num: '0', label: 'ruff 错误', sub: '全量 src/ 通过', color: C.teal },
    { num: '0', label: 'mypy strict 错误', sub: '严格模式类型检查', color: C.orange },
    { num: '4/4', label: 'E2E 通过', sub: 'Playwright 全场景', color: '8B5CF6' },
  ];
  qualityStats.forEach((qs, i) => {
    const x = 0.3 + i * 1.88;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 1.35, w: 1.7, h: 1.55, fill: { color: C.cardBg }, rectRadius: 0.08,
    });
    s.addText(qs.num, {
      x, y: 1.45, w: 1.7, h: 0.55,
      fontSize: 32, fontFace: 'Calibri', bold: true, color: qs.color, align: 'center', valign: 'middle',
    });
    s.addText(qs.label, {
      x, y: 1.95, w: 1.7, h: 0.3,
      fontSize: 13, fontFace: 'Calibri', bold: true, color: C.textDark, align: 'center',
    });
    s.addText(qs.sub, {
      x: x + 0.1, y: 2.3, w: 1.5, h: 0.4,
      fontSize: 9, fontFace: 'Calibri', color: C.textMid, align: 'center',
    });
  });

  // Stack details
  s.addText('技术栈详情', {
    x: 0.5, y: 3.15, w: 4.0, h: 0.3,
    fontSize: 14, fontFace: 'Calibri', bold: true, color: C.textDark, margin: 0,
  });
  const stackItems = [
    ['后端', 'Python 3.11, FastAPI, LangGraph 0.2.28, Celery, aiokafka'],
    ['LLM', 'DeepSeek (默认), Claude, OpenAI, vLLM, ModelAdapter 统一抽象'],
    ['存储', 'ES (事件+审计), Redis (审批+总线), Milvus (向量), Neo4j (ATT&CK)'],
    ['前端', 'React 18, TypeScript, antd5, @ant-design/charts, Vite, Playwright'],
    ['Agent', 'Go 1.22, WebSocket, Ed25519, Nuclei CLI, 规则引擎'],
    ['质量', 'ruff, mypy(strict), pytest, openapi-typescript, Playwright E2E'],
  ];
  stackItems.forEach((si, i) => {
    const y = 3.5 + i * 0.35;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.5, y, w: 9.0, h: 0.3, fill: { color: i % 2 === 0 ? C.cardBg : C.white }, rectRadius: 0.04,
    });
    s.addText(si[0], {
      x: 0.65, y, w: 0.8, h: 0.3,
      fontSize: 10, fontFace: 'Calibri', bold: true, color: C.primary, margin: 0, valign: 'middle',
    });
    s.addText(si[1], {
      x: 1.55, y, w: 7.8, h: 0.3,
      fontSize: 9.5, fontFace: 'Calibri', color: C.textMid, margin: 0, valign: 'middle',
    });
  });
}

// ═══════════════════════════════════════════
// SLIDE 16: 总结
// ═══════════════════════════════════════════
{
  const s = pres.addSlide();
  s.background = { color: C.bgDark };

  s.addText('总结与展望', {
    x: 0.8, y: 0.7, w: 8.4, h: 0.8,
    fontSize: 34, fontFace: 'Cambria', bold: true, color: C.white, align: 'left',
  });

  // Key achievements
  s.addText('已实现能力', {
    x: 0.8, y: 1.6, w: 4.0, h: 0.35,
    fontSize: 16, fontFace: 'Calibri', bold: true, color: C.primary, margin: 0,
  });
  const achievements = [
    '告警智能研判 — 从接入到结论全自动',
    '漏洞主动扫描 — 双引擎 + 对话式交互',
    '响应处置 — 分级审批 + 自动执行',
    '主机纳管 — Agent 全生命周期管理',
    'AI 对话 — 四路路由 + 知识检索',
    '平台能力 — RBAC + SSE 实时 + 4 主题',
  ];
  achievements.forEach((a, i) => {
    s.addText('✓  ' + a, {
      x: 0.8, y: 2.05 + i * 0.35, w: 4.5, h: 0.3,
      fontSize: 11, fontFace: 'Calibri', color: C.white, margin: 0,
    });
  });

  // Next steps
  s.addText('后续方向', {
    x: 5.8, y: 1.6, w: 4.0, h: 0.35,
    fontSize: 16, fontFace: 'Calibri', bold: true, color: C.teal, margin: 0,
  });
  const nextSteps = [
    'Milvus 知识库充实（目前仅6条向量）',
    'vuln_hunter 沙箱端到端验证',
    'Kafka Consumer 接通主图',
    '覆盖率提升至 80%+',
    '接入更多 EDR/防火墙 API',
    'LangGraph checkpointer 替代轮询',
  ];
  nextSteps.forEach((n, i) => {
    s.addText('→  ' + n, {
      x: 5.8, y: 2.05 + i * 0.35, w: 4.0, h: 0.3,
      fontSize: 11, fontFace: 'Calibri', color: C.textLight, margin: 0,
    });
  });

  // Bottom
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0.8, y: 4.3, w: 8.4, h: 0.02, fill: { color: '2A3A4A' },
  });
  s.addText('SecAgent v0.1.0 — 打造 AI 驱动的安全运营闭环', {
    x: 0.8, y: 4.6, w: 8.4, h: 0.5,
    fontSize: 18, fontFace: 'Cambria', bold: true, color: C.white, align: 'center',
  });
  s.addText('2026-07-23  |  257 测试 · 0 lint 错误 · 4/4 E2E 通过  |  https://github.com/security-agent', {
    x: 0.8, y: 5.05, w: 8.4, h: 0.3,
    fontSize: 10, fontFace: 'Calibri', color: C.textLight, align: 'center',
  });
}

// ── Generate ──
pres.writeFile({ fileName: 'V:\\project\\security-agent\\docs\\SecAgent功能演示.pptx' })
  .then(() => console.log('PPTX created successfully!'))
  .catch(err => console.error('Error:', err));
