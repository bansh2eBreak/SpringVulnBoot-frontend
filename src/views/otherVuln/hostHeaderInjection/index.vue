<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">Host Header 注入漏洞（密码重置投毒）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              <strong>Host Header 注入</strong>是指服务端直接信任 HTTP 请求头中的 <code>Host</code>（或 <code>X-Forwarded-Host</code>），将其拼接到给被害人发送的链接 / 邮件 / 缓存响应中，导致<strong>密码重置投毒、邮箱验证劫持、Web 缓存投毒</strong>等攻击。
              <br /><br />
              <span style="color: red;">HTTP 协议基础：</span>
              <br />
              HTTP/1.1 强制要求每个请求都必须带 <code>Host</code> 头（同一台服务器靠它区分虚拟主机）。但这个值是<strong>客户端发送的</strong>，攻击者用 <code>curl</code> 或 Burp 可以发任意 Host 值：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">curl http://bank.com/forgot -H "Host: evil.com" -d ...</pre>
              <span style="color: red;">攻击原理（密码重置投毒经典场景）：</span>
              <br />
              ① 攻击者用 curl 发出"忘记密码"请求，<strong>邮箱字段填被害人的</strong>，<strong>Host 头注入 evil.com</strong><br />
              ② 后端按"给被害人发邮件"的合法逻辑跑，但用 <code>request.getHeader("Host")</code> 拼 reset link → <code>https://evil.com/reset?token=ABC</code><br />
              ③ 邮件真实发出（发件人是真正的 bank.com，过 SPF/DKIM），被害人收件箱看不出异常<br />
              ④ 被害人点击邮件链接 → 浏览器跳到 evil.com → 攻击者服务器抓到 token<br />
              ⑤ 攻击者用 token 真改密码 → 接管账号
              <br /><br />
              <span style="color: red;">关键认知（最容易被误解的点）：</span>
              <br />
              "攻击者发请求" 和 "邮件发给谁" 是<strong>两件独立的事</strong>。
              注入 Host 头的请求是攻击者自己发的，但被攻击的对象（邮件接收人）是<strong>被害人</strong>，因为"忘记密码"接口的输入参数本来就允许指定任意账户。
              <br /><br />
              <span style="color: #e6a23c; font-weight: bold;">⚠️ 本靶场如何在没有真实域名的前提下做出完整闭环：</span>
              <br />
              用<strong>端口当域名</strong>：
              <br />
              • <code>127.0.0.1:80</code> = 合法业务方（前端 + 受害人浏览器活跃位置）
              <br />
              • <code>127.0.0.1:8080</code> = 后端 API
              <br />
              • <code>127.0.0.1:81</code> = 攻击者钓鱼站点（已有 Nginx 配置，复用 CORS / ClickJacking 的基础设施）
              <br />
              攻击者用 curl 注入 <code>Host: 127.0.0.1:81</code>，后端生成的 reset link 就指向端口 81。被害人点击链接<strong>真实跳到端口 81</strong>（攻击者抓取页），完整闭环成立，不依赖任何真实域名。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              Host Header 注入根据"反射点"不同可造成多种严重危害：
              <br /><br />
              <span style="color: red;">主要危害：</span>
              <br />
              • <strong>密码重置投毒（Password Reset Poisoning）</strong>：邮件中的重置链接被指向攻击者域名，被害人点击即泄露 token
              <br />
              • <strong>邮箱验证劫持</strong>：注册时的验证链接被投毒，攻击者拿到验证 token 后用别人的邮箱注册自己的账号
              <br />
              • <strong>账号邀请投毒</strong>：邀请其他用户加入时，邀请链接被改为攻击者站点
              <br />
              • <strong>Web 缓存投毒（最严重）</strong>：响应中反射的 Host 被 CDN 缓存，<strong>一次投毒影响所有访问该资源的用户</strong>
              <br />
              • <strong>SSRF via Host</strong>：内部网关用 Host 头做路由时，可触发对内网服务的请求
              <br />
              • <strong>多租户切换</strong>：基于 Host 头判断租户的系统，可越权切到其他租户上下文
              <br /><br />
              <span style="color: red;">真实 CVE 案例：</span>
              <br />
              • <strong>CVE-2017-8295</strong>（WordPress）：密码重置邮件 Host 注入，影响所有版本
              <br />
              • <strong>CVE-2016-7415</strong>（Django）：同类漏洞，X-Forwarded-Host 可绕过
              <br />
              • <strong>CVE-2018-1000200</strong>（GitLab）：密码重置链接被投毒
              <br />
              • <strong>CVE-2020-5249</strong>（Mantis Bug Tracker）：密码重置投毒
              <br />
              • PortSwigger 的 James Kettle 拿过 BlackHat best research，实战中 PayPal、Mozilla、Tinder 都中过 Web 缓存投毒
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【强烈推荐】配置写死 baseUrl</span>
              <br />
              在配置文件（如 <code>application.yml</code>）中固定 <code>app.base-url</code>，代码里只读配置，<strong>永远不读 Host 头拼 URL</strong>。这是最简单也最彻底的防御：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">@Value("${app.base-url}")
private String baseUrl;

public void sendResetEmail(User user, String token) {
    String link = baseUrl + "/reset?token=" + token; // ✅
}</pre>
              <span style="color: red;">【必须】Host 头白名单校验</span>
              <br />
              如果业务确实需要"多域名共用一套代码"（例如 <code>www.bank.com</code> + <code>m.bank.com</code>），必须先做<strong>严格白名单</strong>：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">Set&lt;String&gt; allowed = Set.of("www.bank.com", "m.bank.com");
String host = request.getHeader("Host");
if (!allowed.contains(host)) {
    response.setStatus(400);
    return;
}</pre>
              <span style="color: red;">【必须】Nginx server_name 严格匹配 + 默认拒绝</span>
              <br />
              在反向代理层加一个默认 server 块兜底，把陌生 Host 直接拒绝在 Spring Boot 之前：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">server {
    listen 80 default_server;
    return 444;  # 关闭连接，不暴露后端
}
server {
    listen 80;
    server_name bank.com www.bank.com;
    location /api { proxy_pass http://backend:8080; }
}</pre>
              <span style="color: red;">【必须】不信任 X-Forwarded-Host / X-Forwarded-Server</span>
              <br />
              如果用了 Spring 的 <code>ForwardedHeaderFilter</code>，注意 <code>X-Forwarded-Host</code> 同样可控，必须在网关层清理或重写。
              <br /><br />
              <span style="color: red;">【建议】CDN 缓存键必须包含 Host</span>
              <br />
              如果用了 CDN，确保缓存键 = URL + Host + 关键 Query，避免 Web 缓存投毒。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://portswigger.net/web-security/host-header" target="_blank" style="text-decoration: underline;">《PortSwigger - Host header attacks》</a>：PortSwigger 学院的 Host Header 攻击教程（完整、推荐入门）。<br />
              <a href="https://portswigger.net/research/practical-web-cache-poisoning" target="_blank" style="text-decoration: underline;">《PortSwigger - Practical Web Cache Poisoning》</a>：James Kettle 关于 Web 缓存投毒的经典议题。<br />
              <a href="https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html" target="_blank" style="text-decoration: underline;">《Practical HTTP Host Header Attacks》</a>：最早系统性论述 Host Header 攻击的文章。<br />
              <a href="https://cwe.mitre.org/data/definitions/644.html" target="_blank" style="text-decoration: underline;">《CWE-644: Improper Neutralization of HTTP Headers》</a>：CWE 对该类漏洞的分类描述。<br />
              <a href="https://wpvulndb.com/vulnerabilities/8807" target="_blank" style="text-decoration: underline;">《CVE-2017-8295 - WordPress Password Reset Poisoning》</a>：经典 WordPress 案例。<br />
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
              漏洞代码 - 用 Host 头拼接 reset link
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * Host Header 注入 - 漏洞版
 * 直接信任客户端 Host 头，拼接 reset link
 */
@PostMapping("/forgot-password/vuln")
public Result forgotPasswordVuln(
        @RequestBody Map&lt;String, String&gt; body,
        HttpServletRequest request) {
    String username = body.get("username");
    String token = UUID.randomUUID().toString().substring(0, 8);
    RESET_TOKENS.put(token, username);

    // ❌ 漏洞点：Host 头由客户端完全控制
    String scheme = request.getScheme();
    String host = request.getHeader("Host");
    String resetLink = scheme + "://" + host
        + "/host-header-injection-reset.html?token=" + token;

    // 模拟发邮件：把邮件正文返回给前端
    return Result.success(buildMailPreview(username, resetLink));
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 从配置读固定 baseUrl
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * Host Header 注入 - 安全版
 * baseUrl 从 application.yml 读取，永远不信 Host 头
 */
@Value("${app.base-url:http://127.0.0.1}")
private String safeBaseUrl;

@PostMapping("/forgot-password/sec")
public Result forgotPasswordSec(
        @RequestBody Map&lt;String, String&gt; body) {
    String username = body.get("username");
    String token = UUID.randomUUID().toString().substring(0, 8);
    RESET_TOKENS.put(token, username);

    // ✅ baseUrl 来自配置，Host 头无效
    String resetLink = safeBaseUrl
        + "/host-header-injection-reset.html?token=" + token;

    return Result.success(buildMailPreview(username, resetLink));
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 漏洞版测试对话框 -->
    <el-dialog title="Host Header 注入漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog" width="860px" @close="resetVulnState">
      <div style="text-align: left; color: red; font-style: italic;">
        本测试模拟完整的"密码重置投毒"攻击链：合法基线 → curl 投毒 → 被害人点击 → 攻击者接管。
      </div>
      <div style="text-align: left; color: #909399; font-size: 12px; margin-top: 6px; line-height: 1.7;">
        💡 测试前提：<br>
        1. 当前已用 <strong>admin / Admin1234</strong> 登录靶场（被害人身份）<br>
        2. <strong>整个攻击链路只对 admin 起作用</strong>（演示简化，演示完用个人中心改回原密码）<br>
        3. 浏览器禁止 JS 修改 Host 头（forbidden header），所以"投毒"环节<strong>必须用 curl 在终端执行</strong><br>
        4. 完整闭环需 Docker Compose 部署（前端 Nginx 暴露端口 80/81），本地开发模式端口 81 不可用
      </div>

      <!-- Step 1：合法基线 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">1</span> 合法请求（建立基线）</div>
        <div class="step-desc">
          浏览器正常调用 <code>/hostHeaderInjection/forgot-password/vuln</code>，Host 头是后端的真实地址，生成的链接合法。
        </div>
        <el-input v-model="vulnForm.username" placeholder="目标用户名" style="width: 240px; margin-right: 10px;">
          <template #prepend>username</template>
        </el-input>
        <el-button type="primary" :loading="vulnForm.loading1" @click="step1Legit">发起合法请求</el-button>

        <div v-if="vulnForm.legitMail" class="mail-preview mail-ok">
          <div class="mail-header">📧 模拟邮件预览（合法基线 - 正常链接）</div>
          <div class="mail-row"><b>To:</b> {{ vulnForm.legitMail.to }}</div>
          <div class="mail-row"><b>From:</b> {{ vulnForm.legitMail.from }}</div>
          <div class="mail-row"><b>Subject:</b> {{ vulnForm.legitMail.subject }}</div>
          <div class="mail-row"><b>请求时 Host 头:</b> <code>{{ vulnForm.legitMail.hostHeader }}</code></div>
          <pre class="mail-body">{{ vulnForm.legitMail.body }}</pre>
          <div class="mail-link">
            <b>提取出的 reset link：</b>
            <a :href="vulnForm.legitMail.resetLink" target="_blank">{{ vulnForm.legitMail.resetLink }}</a>
            <div class="mail-tag mail-tag-ok">✅ 链接指向合法业务域名，无异常</div>
          </div>
        </div>
      </div>

      <!-- Step 2：curl 投毒 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">2</span> 攻击者用 curl 注入恶意 Host</div>
        <div class="step-desc">
          复制以下命令到终端执行，注意 <code>-H "Host: 127.0.0.1:81"</code> 把 Host 头指向攻击者站点（端口 81）。
          执行后把返回的 JSON 粘贴回下方"响应"框，前端会渲染成被毒化的邮件。
        </div>
        <div class="curl-box">
          <pre>{{ vulnCurlCommand }}</pre>
          <el-button type="primary" size="mini" @click="copyToClipboard(vulnCurlCommand)" style="margin-top: 8px;">📋 复制命令</el-button>
        </div>
        <div style="margin-top: 12px;">
          <label style="font-size: 13px; color: #606266;">把 curl 返回的 JSON 粘贴到这里：</label>
          <el-input v-model="vulnForm.curlResponse" type="textarea" :rows="3" placeholder='例：{"code":0,"msg":"success","data":{"resetLink":"http://127.0.0.1:81/host-header-injection-reset.html?token=xxx", ...}}' />
          <el-button type="danger" size="mini" @click="parseCurlResponse" style="margin-top: 6px;">解析响应 → 渲染投毒邮件</el-button>
        </div>

        <div v-if="vulnForm.poisonedMail" class="mail-preview mail-bad">
          <div class="mail-header">📧 模拟邮件预览（被毒化 - 链接已指向攻击者站点）</div>
          <div class="mail-row"><b>To:</b> {{ vulnForm.poisonedMail.to }}</div>
          <div class="mail-row"><b>From:</b> {{ vulnForm.poisonedMail.from }}</div>
          <div class="mail-row"><b>Subject:</b> {{ vulnForm.poisonedMail.subject }}</div>
          <div class="mail-row"><b>请求时 Host 头:</b> <code style="color:#c0392b;">{{ vulnForm.poisonedMail.hostHeader }}</code></div>
          <pre class="mail-body">{{ vulnForm.poisonedMail.body }}</pre>
          <div class="mail-link">
            <b>提取出的 reset link：</b>
            <a :href="vulnForm.poisonedMail.resetLink" target="_blank">{{ vulnForm.poisonedMail.resetLink }}</a>
            <div class="mail-tag mail-tag-bad">❌ 链接已被毒化，指向攻击者站点</div>
          </div>
        </div>
      </div>

      <!-- Step 3：被害人点击 + 攻击者接管 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">3</span> 被害人点击邮件链接（你切换为受害人视角）</div>
        <div class="step-desc">
          点击下方按钮，新标签页打开<strong>被毒化的链接</strong>（端口 81 的攻击者抓取页）。
          在抓取页点"接管账号"按钮，攻击者就拿到了 admin 的密码控制权。
        </div>
        <el-button
          type="warning"
          :disabled="!vulnForm.poisonedMail"
          @click="openPoisonedLink"
        >
          📨 点击邮件中的"重置密码"链接（新标签）
        </el-button>
        <div v-if="!vulnForm.poisonedMail" style="color:#909399; font-size:12px; margin-top:6px;">
          ⚠️ 请先在 Step 2 完成 curl 投毒并解析响应
        </div>
      </div>

      <!-- Step 4：验证接管 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">4</span> 验证账号已被接管</div>
        <div class="step-desc">
          回到靶场前端 → 退出登录 → 用 <code>admin / hacked_by_host_header</code> 登录 → 登录成功证明攻击闭环完成。
          <br><strong>恢复方法：</strong>登录后到"个人中心"将密码改回原值。
        </div>
      </div>
    </el-dialog>

    <!-- 安全版测试对话框 -->
    <el-dialog title="Host Header 注入安全版测试" :visible.sync="secDialogVisible" class="center-dialog" width="860px" @close="resetSecState">
      <div style="text-align: left; color: green; font-style: italic;">
        安全版 baseUrl 来自 <code>application.yml</code> 的 <code>app.base-url</code> 配置，无论 Host 头怎么传都不受影响。
      </div>
      <br />

      <div class="step-block">
        <div class="step-title"><span class="step-num">1</span> 合法请求（基线）</div>
        <el-input v-model="secForm.username" placeholder="目标用户名" style="width: 240px; margin-right: 10px;">
          <template #prepend>username</template>
        </el-input>
        <el-button type="primary" :loading="secForm.loading1" @click="secStep1">发起合法请求</el-button>

        <div v-if="secForm.legitMail" class="mail-preview mail-ok">
          <div class="mail-header">📧 模拟邮件预览（基线）</div>
          <div class="mail-row"><b>请求时 Host 头:</b> <code>{{ secForm.legitMail.hostHeader }}</code></div>
          <pre class="mail-body">{{ secForm.legitMail.body }}</pre>
          <div class="mail-link">
            <b>reset link：</b><a :href="secForm.legitMail.resetLink" target="_blank">{{ secForm.legitMail.resetLink }}</a>
          </div>
        </div>
      </div>

      <div class="step-block">
        <div class="step-title"><span class="step-num">2</span> curl 投毒尝试（应当失效）</div>
        <div class="step-desc">
          复制下面命令到终端执行，注入恶意 Host 头：
        </div>
        <div class="curl-box">
          <pre>{{ secCurlCommand }}</pre>
          <el-button type="primary" size="mini" @click="copyToClipboard(secCurlCommand)" style="margin-top: 8px;">📋 复制命令</el-button>
        </div>
        <div style="margin-top: 12px;">
          <label style="font-size: 13px; color: #606266;">把 curl 返回的 JSON 粘贴到这里：</label>
          <el-input v-model="secForm.curlResponse" type="textarea" :rows="3" placeholder='例：{"code":0,"msg":"success","data":{"resetLink":"http://127.0.0.1/...", ...}}' />
          <el-button type="success" size="mini" @click="parseSecCurlResponse" style="margin-top: 6px;">解析响应</el-button>
        </div>

        <div v-if="secForm.attackedMail" class="mail-preview mail-ok">
          <div class="mail-header">📧 模拟邮件预览（即便注入了恶意 Host，链接仍然合法）</div>
          <div class="mail-row"><b>注入的 Host 头:</b> <code style="color:#c0392b;">{{ secForm.attackedMail.hostHeader }}</code></div>
          <pre class="mail-body">{{ secForm.attackedMail.body }}</pre>
          <div class="mail-link">
            <b>reset link：</b><a :href="secForm.attackedMail.resetLink" target="_blank">{{ secForm.attackedMail.resetLink }}</a>
            <div class="mail-tag mail-tag-ok">✅ 链接永远指向 application.yml 中配置的 baseUrl，攻击失败</div>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { forgotPasswordVuln, forgotPasswordSec } from '@/api/hostHeaderInjection'
import { getBaseUrl } from '@/utils/request'

export default {
  name: 'HostHeaderInjection',
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false,
      vulnForm: {
        username: 'admin',
        loading1: false,
        legitMail: null,
        curlResponse: '',
        poisonedMail: null
      },
      secForm: {
        username: 'admin',
        loading1: false,
        legitMail: null,
        curlResponse: '',
        attackedMail: null
      }
    }
  },
  computed: {
    backendBaseUrl() {
      return getBaseUrl()
    },
    vulnCurlCommand() {
      return `curl -X POST ${this.backendBaseUrl}/hostHeaderInjection/forgot-password/vuln \\
     -H "Content-Type: application/json" \\
     -H "Host: 127.0.0.1:81" \\
     -d '{"username":"${this.vulnForm.username || 'admin'}"}'`
    },
    secCurlCommand() {
      return `curl -X POST ${this.backendBaseUrl}/hostHeaderInjection/forgot-password/sec \\
     -H "Content-Type: application/json" \\
     -H "Host: 127.0.0.1:81" \\
     -d '{"username":"${this.secForm.username || 'admin'}"}'`
    }
  },
  methods: {
    handleClick() {},

    showVulnDialog() {
      this.vulnDialogVisible = true
    },
    showSecDialog() {
      this.secDialogVisible = true
    },
    resetVulnState() {
      this.vulnForm.legitMail = null
      this.vulnForm.curlResponse = ''
      this.vulnForm.poisonedMail = null
    },
    resetSecState() {
      this.secForm.legitMail = null
      this.secForm.curlResponse = ''
      this.secForm.attackedMail = null
    },

    async step1Legit() {
      if (!this.vulnForm.username) {
        this.$message.warning('请填写用户名')
        return
      }
      this.vulnForm.loading1 = true
      try {
        const res = await forgotPasswordVuln(this.vulnForm.username)
        this.vulnForm.legitMail = res.data
      } catch (e) {
        this.$message.error('请求失败：' + e.message)
      } finally {
        this.vulnForm.loading1 = false
      }
    },

    parseCurlResponse() {
      const text = (this.vulnForm.curlResponse || '').trim()
      if (!text) {
        this.$message.warning('请粘贴 curl 返回的 JSON')
        return
      }
      try {
        const json = JSON.parse(text)
        if (json && json.code === 0 && json.data) {
          this.vulnForm.poisonedMail = json.data
          this.$message.success('解析成功')
        } else {
          this.$message.error('JSON 格式不正确（期望 code=0 且含 data 字段）')
        }
      } catch (e) {
        this.$message.error('JSON 解析失败：' + e.message)
      }
    },

    openPoisonedLink() {
      if (this.vulnForm.poisonedMail && this.vulnForm.poisonedMail.resetLink) {
        window.open(this.vulnForm.poisonedMail.resetLink, '_blank')
      }
    },

    async secStep1() {
      if (!this.secForm.username) {
        this.$message.warning('请填写用户名')
        return
      }
      this.secForm.loading1 = true
      try {
        const res = await forgotPasswordSec(this.secForm.username)
        this.secForm.legitMail = res.data
      } catch (e) {
        this.$message.error('请求失败：' + e.message)
      } finally {
        this.secForm.loading1 = false
      }
    },

    parseSecCurlResponse() {
      const text = (this.secForm.curlResponse || '').trim()
      if (!text) {
        this.$message.warning('请粘贴 curl 返回的 JSON')
        return
      }
      try {
        const json = JSON.parse(text)
        if (json && json.code === 0 && json.data) {
          this.secForm.attackedMail = json.data
          this.$message.success('解析成功')
        } else {
          this.$message.error('JSON 格式不正确（期望 code=0 且含 data 字段）')
        }
      } catch (e) {
        this.$message.error('JSON 解析失败：' + e.message)
      }
    },

    async copyToClipboard(text) {
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text)
        } else {
          const ta = document.createElement('textarea')
          ta.value = text
          ta.style.position = 'fixed'
          ta.style.opacity = '0'
          document.body.appendChild(ta)
          ta.focus()
          ta.select()
          document.execCommand('copy')
          document.body.removeChild(ta)
        }
        this.$message.success('已复制到剪贴板')
      } catch (e) {
        this.$message.error('复制失败：' + e.message)
      }
    }
  }
}
</script>

<style scoped>
.root-div { height: 100%; }

.vuln-info {
  border-radius: 10px;
  margin: 10px 20px 20px;
}

.header-div {
  font-size: 24px;
  color: #409EFF;
  font-weight: bold;
  padding: 10px;
  border-bottom: 1px solid #ccc;
}

.body-div {
  padding: 10px;
  font-family: Arial, sans-serif;
  font-size: 14px;
}

.vuln-detail {
  background-color: #dce9f8;
  padding: 10px;
  line-height: 1.7;
}

.code-demo {
  margin: 20px;
  border-top: 1px solid #ccc;
  padding-top: 20px;
}

pre code { font-size: 12px; }

.el-row { margin-bottom: 20px; }
.el-row:last-child { margin-bottom: 0; }
.el-col { border-radius: 4px; }
.bg-purple { background: #d3dce6; }

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

/* Step 块样式 */
.step-block {
  border: 1px solid #ebeef5;
  border-radius: 6px;
  padding: 14px 18px;
  margin-top: 18px;
  text-align: left;
  background: #fafafa;
}

.step-title {
  font-size: 15px;
  font-weight: bold;
  color: #303133;
  margin-bottom: 8px;
}

.step-num {
  display: inline-block;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: #409eff;
  color: #fff;
  text-align: center;
  line-height: 22px;
  font-size: 13px;
  margin-right: 8px;
}

.step-desc {
  font-size: 13px;
  color: #606266;
  line-height: 1.7;
  margin-bottom: 10px;
}

/* curl 命令显示框 */
.curl-box {
  background: #2b2b2b;
  color: #f8f8f2;
  padding: 12px 14px;
  border-radius: 4px;
  margin-top: 6px;
}

.curl-box pre {
  white-space: pre-wrap;
  word-break: break-all;
  font-family: Consolas, Monaco, monospace;
  font-size: 12px;
  line-height: 1.6;
  margin: 0;
  color: #f8f8f2;
}

/* 模拟邮件卡片 */
.mail-preview {
  border-radius: 6px;
  padding: 14px;
  margin-top: 12px;
  border: 2px solid;
  font-size: 13px;
}

.mail-ok {
  border-color: #67c23a;
  background: #f0f9eb;
}

.mail-bad {
  border-color: #f56c6c;
  background: #fef0f0;
}

.mail-header {
  font-weight: bold;
  color: #303133;
  margin-bottom: 8px;
  font-size: 14px;
}

.mail-row {
  margin: 4px 0;
  color: #606266;
}

.mail-body {
  background: #fff;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  padding: 10px;
  margin: 8px 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-family: Consolas, Monaco, monospace;
  font-size: 12px;
  color: #303133;
  line-height: 1.6;
}

.mail-link {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px dashed #c0c4cc;
}

.mail-link a {
  color: #409eff;
  word-break: break-all;
}

.mail-tag {
  display: inline-block;
  margin-top: 6px;
  padding: 3px 8px;
  border-radius: 3px;
  font-size: 12px;
  font-weight: bold;
}

.mail-tag-ok {
  background: #e1f3d8;
  color: #67c23a;
  border: 1px solid #c2e7b0;
}

.mail-tag-bad {
  background: #fde2e2;
  color: #f56c6c;
  border: 1px solid #fbc4c4;
}
</style>
