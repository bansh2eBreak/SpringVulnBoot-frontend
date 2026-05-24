<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">CRLF 注入（HTTP 响应头注入）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              <strong>CRLF 注入</strong>（Carriage Return Line Feed Injection）是指攻击者通过在用户输入中插入 <code>\r\n</code>（即 <code>%0d%0a</code>）字符，将恶意内容注入到 HTTP 响应头中的攻击方式。
              <br /><br />
              <span style="color: red;">HTTP 协议基础：</span>
              <br />
              HTTP 响应由<strong>状态行</strong>、<strong>响应头</strong>、<strong>空行</strong>、<strong>响应体</strong>四部分组成，它们之间用 <code>\r\n</code>（CRLF）分隔：
              <br />
              <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 8px 0; color: #333;">HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
Set-Cookie: sid=abc123\r\n
\r\n                          ← 空行，分隔响应头和响应体
&lt;html&gt;...&lt;/html&gt;</pre>
              <span style="color: red;">攻击原理：</span>
              <br />
              当应用程序将用户输入<strong>直接拼接</strong>到 HTTP 响应头中，而未过滤 <code>\r\n</code> 字符时，攻击者可以：
              <br />
              1. 注入 <code>\r\n</code> 终结当前响应头，插入<strong>任意新的响应头</strong>（如 <code>Set-Cookie</code>）
              <br />
              2. 注入 <code>\r\n\r\n</code>（连续两个换行）终结所有响应头，注入<strong>任意响应体</strong>（如 XSS 脚本）
              <br /><br />
              <span style="color: #e6a23c; font-weight: bold;">⚠️ 关于本靶场的实现说明：</span>
              <br />
              现代 Servlet 容器（如 <strong>Tomcat 7.0.73+ / 8.0.39+ / 9.x</strong>）在调用 <code>response.setHeader()</code> 时已默认拒绝包含 <code>\r\n</code> 的值，会直接抛出 <code>IllegalArgumentException</code>。
              本靶场当前使用的 <strong>Spring Boot 2.7.14（内嵌 Tomcat 9.0.78）</strong> 也具备此防护。
              <br /><br />
              因此漏洞版先在服务端解析用户输入中的 <code>\r\n</code>，将提取出的头部通过 <code>addHeader()</code> 真实注入到 HTTP 响应中（F12 可验证），
              将提取出的响应体内容直接写入 HTML 响应（XSS 可真实触发）。
              <br />
              这模拟了以下<strong>真实场景</strong>：
              <br />
              • 使用 <strong>Netty</strong> 等非 Servlet 容器手动构造 HTTP 响应
              <br />
              • <strong>旧版</strong> Servlet 容器（Tomcat 7.0.72 以下）未做 <code>\r\n</code> 校验
              <br />
              • 开发者在自定义 Filter / Interceptor 中手动拼接响应头
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              CRLF 注入可以造成多种严重安全后果：
              <br /><br />
              <span style="color: red;">主要危害：</span>
              <br />
              • <strong>会话固定（Session Fixation）</strong>：注入 <code>Set-Cookie: JSESSIONID=attacker_session</code>，强制用户使用攻击者控制的会话
              <br />
              • <strong>XSS 跨站脚本</strong>：通过 <code>\r\n\r\n</code> 注入响应体，插入恶意 JavaScript 代码
              <br />
              • <strong>缓存投毒</strong>：注入 <code>Cache-Control</code> 等缓存头，让代理/CDN 缓存恶意内容
              <br />
              • <strong>重定向劫持</strong>：注入 <code>Location</code> 头将用户重定向到钓鱼网站
              <br />
              • <strong>绕过安全头</strong>：注入覆盖 <code>X-Frame-Options</code>、<code>Content-Security-Policy</code> 等安全响应头
              <br /><br />
              <span style="color: red;">真实案例：</span>
              <br />
              • Twitter 曾存在通过 URL 参数注入 Set-Cookie 的 CRLF 漏洞
              <br />
              • 多个 Java Web 框架旧版本未过滤 \r\n（Tomcat 旧版、Jetty 等）
              <br />
              • 大量 Nginx/Apache 反向代理配置不当导致 CRLF 注入
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】过滤 \r\n 字符</span>
              <br />
              在将用户输入设置到 HTTP 响应头之前，必须移除或替换所有 <code>\r</code>（0x0D）和 <code>\n</code>（0x0A）字符。
              <br /><br />
              <span style="color: red;">【必须】使用框架提供的安全 API</span>
              <br />
              使用 <code>HttpServletResponse.setHeader()</code> 等标准 API（现代 Tomcat 已内置防护），避免手动拼接原始响应。
              <br /><br />
              <span style="color: red;">【必须】输入验证</span>
              <br />
              对需要放入 HTTP 头的值做白名单校验（如语言代码只允许 <code>zh</code>、<code>en</code> 等有限值），拒绝包含非预期字符的输入。
              <br /><br />
              <span style="color: red;">【建议】使用安全框架</span>
              <br />
              Spring Security 等框架提供了 <code>HeaderWriterFilter</code>，可统一管理响应头的安全写入。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-community/vulnerabilities/CRLF_Injection" target="_blank" style="text-decoration: underline;">《OWASP - CRLF Injection》</a>：OWASP 对 CRLF 注入的官方说明。<br />
              <a href="https://portswigger.net/kb/issues/00200200_http-response-header-injection" target="_blank" style="text-decoration: underline;">《PortSwigger - HTTP Response Header Injection》</a>：Burp Suite 官方知识库。<br />
              <a href="https://cwe.mitre.org/data/definitions/113.html" target="_blank" style="text-decoration: underline;">《CWE-113: HTTP Response Splitting》</a>：CWE 对 HTTP 响应拆分的分类描述。<br />
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>
    <div class="code-demo">
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - 直接拼接响应头（未过滤 \r\n）
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * CRLF注入 - 漏洞代码
 * 用户输入未过滤，直接拼接到HTTP响应头
 * 模拟无防护的Servlet容器或手动构造响应的场景
 */
@GetMapping("/vuln")
public void vuln(@RequestParam String input,
                 HttpServletResponse response) throws IOException {
    // 直接将用户输入拼接到响应头（未过滤 \r\n）
    response.setHeader("X-Custom-Header", input); // ❌ 漏洞点

    response.setContentType("text/html; charset=utf-8");
    response.getWriter().write("正常响应内容");
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 过滤 \r\n 后设置响应头
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * CRLF注入 - 安全代码
 * 过滤\r\n字符后再设置响应头
 */
@GetMapping("/sec")
public void sec(@RequestParam String input,
                HttpServletResponse response) throws IOException {
    // ✅ 过滤所有\r和\n字符
    String sanitized = input.replaceAll("[\\r\\n]", "");

    response.setHeader("X-Custom-Header", sanitized);
    response.setContentType("text/html; charset=utf-8");
    response.getWriter().write("安全版：头部值已过滤");
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 漏洞版测试对话框 -->
    <el-dialog title="CRLF 注入漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog" width="780px">
      <div style="text-align: left; color: red; font-style: italic;">
        以下 Payload 演示了 CRLF 注入的不同攻击效果：<br>
        攻击者通过在输入中插入 \r\n（%0d%0a）来注入额外的 HTTP 响应头或响应体。
      </div>
      <br />
      <div style="text-align: left; color: #909399; font-size: 12px; margin-top: 6px;">
        💡 说明：因为新标签页打开的是浏览器原生请求，无法携带 Authorization 认证头（JWT 存储在 localStorage 中，浏览器原生导航不会自动附加自定义请求头），所以为了更好的展示 CRLF 漏洞，CRLF 漏洞的后端接口配置了未授权访问。
      </div>
      <br />
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="vulnForm.selectedPayload" placeholder="请选择测试 Payload" @change="updateVulnInput" style="width: 100%;">
            <el-option label="正常输入 - hello" value="normal" />
            <el-option label="注入 Set-Cookie 头（会话固定）" value="set_cookie" />
            <el-option label="注入 Location 头（重定向劫持）" value="location" />
            <el-option label="注入 XSS 响应体（弹框验证）" value="xss" />
            <el-option label="自定义 Payload" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item label="Payload">
          <el-input v-model="vulnForm.input" type="textarea" :rows="3" placeholder="输入内容（可包含 \r\n）" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="buildVulnUrl">构造请求 URL</el-button>
        </el-form-item>
      </el-form>

      <div v-if="vulnForm.url" class="result-display">
        <h4>构造的请求 URL：</h4>
        <div class="result-box result-info" style="word-break: break-all; user-select: all;">
          {{ vulnForm.url }}
        </div>
        <div style="margin-top: 12px;">
          <el-button type="danger" @click="openUrl(vulnForm.url)">在新标签页中打开（查看注入效果）</el-button>
        </div>
        <div class="result-box result-warning" style="margin-top: 10px;">
          <strong>验证方式：</strong>点击上方按钮后，在新标签页中：
          <br>• <strong>正常输入</strong>：页面正常展示，F12 可看到 <code>X-Custom-Header: hello</code>
          <br>• <strong>Set-Cookie 注入</strong>：打开 F12 → Network → 查看响应头，可看到 <code>Set-Cookie</code> 头被注入
          <br>• <strong>Location 重定向</strong>：浏览器直接跳转到注入的目标地址（如百度），F12 可看到 302 状态码和 <code>Location</code> 头
          <br>• <strong>XSS 注入</strong>：页面会直接弹出 <code>alert</code> 对话框，证明脚本被执行
        </div>
      </div>
    </el-dialog>

    <!-- 安全版测试对话框 -->
    <el-dialog title="CRLF 注入安全版测试" :visible.sync="secDialogVisible" class="center-dialog" width="780px">
      <div style="text-align: left; color: green; font-style: italic;">
        安全版会过滤输入中的 \r 和 \n 字符，确保无法注入额外的 HTTP 响应头。<br>
        使用相同的攻击 Payload 对比漏洞版，观察过滤后的效果。
      </div>
      <br />
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="secForm.selectedPayload" placeholder="请选择测试 Payload" @change="updateSecInput" style="width: 100%;">
            <el-option label="正常输入 - hello" value="normal" />
            <el-option label="注入 Set-Cookie 头（会话固定）" value="set_cookie" />
            <el-option label="注入 Location 头（重定向劫持）" value="location" />
            <el-option label="注入 XSS 响应体（弹框验证）" value="xss" />
            <el-option label="自定义 Payload" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item label="Payload">
          <el-input v-model="secForm.input" type="textarea" :rows="3" placeholder="输入内容（\r\n 将被过滤）" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="buildSecUrl">构造请求 URL</el-button>
        </el-form-item>
      </el-form>

      <div v-if="secForm.url" class="result-display">
        <h4>构造的请求 URL：</h4>
        <div class="result-box result-info" style="word-break: break-all; user-select: all;">
          {{ secForm.url }}
        </div>
        <div style="margin-top: 12px;">
          <el-button type="success" @click="openUrl(secForm.url)">在新标签页中打开（查看安全效果）</el-button>
        </div>
        <div class="result-box result-success" style="margin-top: 10px;">
          <strong>预期结果：</strong>新标签页中 \r\n 已被过滤，无 XSS 弹框、无 Set-Cookie 注入。
          <br>F12 → Network → 响应头中 <code>X-Custom-Header</code> 的值是过滤后的纯文本，不包含换行符。
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { buildCrlfUrl } from '@/api/crlf'

const PAYLOADS = {
  normal: 'hello',
  set_cookie: 'hello\\r\\nSet-Cookie: admin=true; Path=/',
  location: 'hello\\r\\nLocation: https://www.baidu.com',
  xss: 'hello\\r\\n\\r\\n<script>alert("XSS via CRLF")<' + '/script>',
  custom: ''
}

export default {
  name: 'CrlfInjection',
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false,
      vulnForm: {
        selectedPayload: 'normal',
        input: PAYLOADS.normal,
        url: ''
      },
      secForm: {
        selectedPayload: 'normal',
        input: PAYLOADS.normal,
        url: ''
      }
    }
  },
  methods: {
    handleClick() {},

    showVulnDialog() {
      this.vulnDialogVisible = true
      this.vulnForm.url = ''
    },
    showSecDialog() {
      this.secDialogVisible = true
      this.secForm.url = ''
    },

    updateVulnInput(val) {
      this.vulnForm.input = PAYLOADS[val] || ''
      this.vulnForm.url = ''
    },
    updateSecInput(val) {
      this.secForm.input = PAYLOADS[val] || ''
      this.secForm.url = ''
    },

    buildVulnUrl() {
      if (!this.vulnForm.input) {
        this.$message.warning('请输入 Payload')
        return
      }
      const rawInput = this.vulnForm.input.replace(/\\r/g, '\r').replace(/\\n/g, '\n')
      this.vulnForm.url = buildCrlfUrl('vuln', rawInput)
    },

    buildSecUrl() {
      if (!this.secForm.input) {
        this.$message.warning('请输入 Payload')
        return
      }
      const rawInput = this.secForm.input.replace(/\\r/g, '\r').replace(/\\n/g, '\n')
      this.secForm.url = buildCrlfUrl('sec', rawInput)
    },

    openUrl(url) {
      window.open(url, '_blank')
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
  margin-top: 10px;
  margin-bottom: 5px;
  color: #303133;
  font-size: 14px;
  font-weight: bold;
}

.result-box {
  padding: 12px 16px;
  border-radius: 4px;
  line-height: 1.6;
  font-size: 14px;
  white-space: pre-wrap;
  word-break: break-all;
}

.result-success {
  background-color: #f0f9ff;
  color: #67c23a;
  border: 1px solid #c6e2ff;
}

.result-error {
  background-color: #fef0f0;
  color: #f56c6c;
  border: 1px solid #fbc4c4;
}

.result-info {
  background-color: #f4f4f5;
  color: #606266;
  border: 1px solid #e9e9eb;
}

.result-warning {
  background-color: #fdf6ec;
  color: #e6a23c;
  border: 1px solid #f5dab1;
}
</style>
