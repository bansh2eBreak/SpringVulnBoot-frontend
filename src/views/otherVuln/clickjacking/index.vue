<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">点击劫持漏洞（ClickJacking）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              <strong>ClickJacking（点击劫持，又称 UI 重定向攻击）</strong>是一种通过视觉欺骗手段，诱导用户在不知情的情况下点击隐藏页面元素的攻击方式。
              <br /><br />
              <span style="color: red;">攻击原理：</span>
              <br />
              攻击者将目标网站（受害者已登录的网站）通过 <code>&lt;iframe&gt;</code> 嵌入到自己控制的钓鱼页面中，
              再用 CSS 把 iframe 设置为<strong>完全透明（opacity:0）</strong>并精准覆盖在某个诱饵元素（如"立即领取大奖"按钮）上方。
              当受害者点击诱饵按钮时，实际点击穿透到 iframe 内的真实按钮上，触发敏感操作。
              <br /><br />
              <span style="color: red;">攻击成立的核心前提：</span>
              <br />
              1. 受害者已登录目标网站（浏览器持有 Cookie / JWT 等凭证）
              <br />
              2. 目标页面未设置 <code>X-Frame-Options</code> 或 <code>Content-Security-Policy: frame-ancestors</code>，允许被任意来源 iframe 嵌入
              <br />
              3. 攻击者诱导受害者访问钓鱼页面并完成"看似无害"的点击
              <br /><br />
              <span style="color: red;">本靶场攻击链路：</span>
              <br />
              受害者已登录靶场（端口 80）→ 访问攻击者钓鱼页（端口 81）→ 钓鱼页用透明 iframe 嵌入"修改密码"受害者页面（端口 80，与靶场同 Origin，能读到 localStorage 中的 JWT）→ 受害者点击"立即领奖"实际触发"确认修改密码" → 后端 <code>/changePassword</code> 接口将密码改为攻击者预设值。
              <br /><br />
              <span style="color: #e6a23c; font-weight: bold;">⚠️ 关于 iframe 加载目标的重要澄清（避免误解）：</span>
              <br />
              iframe 中加载的 <code>http://127.0.0.1/clickjacking-victim-vuln.html</code> 部署在<strong>靶场前端服务器（端口 80）</strong>，
              它<strong>不是攻击者放上去的</strong>，而是<strong>模拟业务系统本身的"修改密码"合法页面</strong>。
              <br /><br />
              <strong>真实场景对照：</strong>例如银行被点击劫持时，攻击者只控制自己的钓鱼站 <code>attacker.com</code>，
              在钓鱼页里写 <code>&lt;iframe src="http://bank.com/transfer"&gt;</code>，浏览器自动去 <code>bank.com</code>（业务方服务器）拉取合法转账页 —— 
              <strong>攻击者不需要也无法把页面放到 bank.com 上</strong>。漏洞的本质是：bank.com 的合法页面没有设置 <code>X-Frame-Options</code>，允许被任意网站 iframe 嵌入。
              <br /><br />
              本靶场用一个简化的静态 HTML（<code>clickjacking-victim-vuln.html</code>）等价模拟"靶场真实的修改密码业务页"，
              <strong>没有任何攻击者代码</strong>，全部是合法业务逻辑（读 JWT → 调 <code>/changePassword</code>）。
              之所以不直接 iframe 靶场 Vue 项目里的修改密码页，是因为 Vue 是 SPA，
              所有路由都返回同一个 <code>index.html</code>，Nginx 难以针对单个 SPA 子路由设置不同的 <code>X-Frame-Options</code> 来做漏洞/安全版对比。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              点击劫持配合不同的"目标操作"可造成多种危害：
              <br /><br />
              <span style="color: red;">典型攻击场景：</span>
              <br />
              • <strong>账户接管</strong>：诱导点击"修改密码 / 修改绑定邮箱 / 撤销 MFA"按钮
              <br />
              • <strong>资金损失</strong>：诱导点击"确认转账 / 同意支付"按钮
              <br />
              • <strong>权限授予</strong>：诱导点击 OAuth "授权"按钮，把账户权限给第三方应用
              <br />
              • <strong>关注/点赞劫持（Likejacking）</strong>：刷粉、刷点赞、传播恶意内容
              <br />
              • <strong>恶意权限授予</strong>：诱导用户授予浏览器摄像头/麦克风/位置权限
              <br /><br />
              <span style="color: red;">真实案例：</span>
              <br />
              • Twitter 早期存在 Tweet 按钮的 Likejacking 攻击
              <br />
              • Facebook 多次出现"一键关注"的点击劫持事件
              <br />
              • OAuth 授权流程曾被多个 OAuth 提供方爆出可被 iframe 嵌入实施授权劫持
              <br />
              • Adobe Flash 配置面板曾被点击劫持启用摄像头/麦克风
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】设置 X-Frame-Options 响应头</span>
              <br />
              在所有可能被嵌入的敏感页面响应中加入 <code>X-Frame-Options: DENY</code>（完全禁止）或 <code>SAMEORIGIN</code>（仅同源允许）。
              Spring Security 默认会对所有响应自动添加 <code>X-Frame-Options: DENY</code>。
              <br /><br />
              <span style="color: red;">【推荐】使用 CSP frame-ancestors（更现代）</span>
              <br />
              在响应头中加入 <code>Content-Security-Policy: frame-ancestors 'none'</code> 或 <code>'self'</code>，比 X-Frame-Options 更灵活，支持白名单多个允许嵌入的域名。
              CSP 是 X-Frame-Options 的升级版，浏览器优先级更高。
              <br /><br />
              <span style="color: red;">【建议】敏感操作二次确认</span>
              <br />
              对于修改密码、转账、删除账户等敏感操作，要求用户输入<strong>当前密码 / 短信验证码 / MFA</strong>等二次因子，
              即使点击穿透成功，仅靠"点击一个按钮"也无法完成攻击。
              <br /><br />
              <span style="color: red;">【建议】SameSite Cookie 属性</span>
              <br />
              将 Session Cookie 设置为 <code>SameSite=Strict</code> 或 <code>SameSite=Lax</code>，限制跨站请求时浏览器自动携带 Cookie，
              可以降低部分点击劫持衍生的请求伪造风险。
              <br /><br />
              <span style="color: #e6a23c; font-weight: bold;">⚠️ 关于本靶场的实现说明：</span>
              <br />
              Spring Security 默认会给所有后端响应加 <code>X-Frame-Options: DENY</code>，但<strong>前端 Nginx 服务的静态资源默认无此防护</strong>。
              本演示通过 Nginx 配置：对漏洞版静态页面不加防护头、对安全版静态页面主动加 <code>add_header X-Frame-Options "DENY"</code>，直观对比效果。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-community/attacks/Clickjacking" target="_blank" style="text-decoration: underline;">《OWASP - Clickjacking》</a>：OWASP 对点击劫持的官方说明。<br />
              <a href="https://portswigger.net/web-security/clickjacking" target="_blank" style="text-decoration: underline;">《PortSwigger - Clickjacking (UI redressing)》</a>：PortSwigger 学院的点击劫持教程。<br />
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP - Clickjacking Defense Cheat Sheet》</a>：点击劫持防护清单。<br />
              <a href="https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Frame-Options" target="_blank" style="text-decoration: underline;">《MDN - X-Frame-Options》</a>：响应头详细说明。<br />
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
              漏洞配置 - Nginx 无 X-Frame-Options
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="nginx">
# nginx.conf - 漏洞版：无任何防护
# 浏览器允许该页面被任意来源 iframe 嵌入
location = /clickjacking-victim-vuln.html {
    root /usr/share/nginx/html;
    # ❌ 未设置 X-Frame-Options
    # ❌ 未设置 Content-Security-Policy: frame-ancestors
}

&lt;!-- clickjacking-victim-vuln.html 关键片段 --&gt;
&lt;style&gt;
  /* 关键：按钮 fixed 锁在 iframe 视口 (0,0)
     这样攻击者 iframe 只需简单覆盖在诱饵按钮上方即可触发 */
  .clickjacking-trigger {
    position: fixed; top: 0; left: 0;
    width: 100%; height: 60px;
    z-index: 9999;
  }
&lt;/style&gt;

&lt;button class="clickjacking-trigger"
        onclick="doChangePassword()"&gt;确认修改密码&lt;/button&gt;

&lt;script&gt;
  // 同 origin，能读到靶场 localStorage 中的 JWT
  var jwt = localStorage.getItem('Authorization');
  async function doChangePassword() {
    var newPassword = document.getElementById('newPassword').value;
    await fetch('http://127.0.0.1:8080/changePassword', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': jwt
      },
      body: JSON.stringify({ newPassword: newPassword })
    });
  }
&lt;/script&gt;</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全配置 - Nginx 加 X-Frame-Options
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="nginx">
# nginx.conf - 安全版：响应头 X-Frame-Options: DENY
# 浏览器拒绝把该页面渲染到任何 iframe 中
location = /clickjacking-victim-sec.html {
    root /usr/share/nginx/html;
    add_header X-Frame-Options "DENY" always;  # ✅
    # 或使用 CSP（推荐，更现代）：
    # add_header Content-Security-Policy "frame-ancestors 'none'" always;
}

# Spring Boot 应用层防护（默认已开启）
# Spring Security 自动给所有响应加：
#   X-Frame-Options: DENY
# 如需放开特定页面：
#   http.headers().frameOptions().sameOrigin();</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 漏洞版测试对话框 -->
    <el-dialog title="点击劫持漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog" width="780px">
      <div style="text-align: left; color: red; font-style: italic;">
        本测试将模拟攻击者钓鱼页面对靶场受害者发起点击劫持攻击。
        <br>受害者页面无 X-Frame-Options 防护，可被透明 iframe 嵌入。
      </div>
      <div style="text-align: left; color: #909399; font-size: 12px; margin-top: 6px;">
        💡 测试前提：
        <br>1. 您当前已登录靶场（localStorage 中存有 JWT），浏览器同 origin 的页面均可读取
        <br>2. 攻击者站点运行在端口 81（独立 Origin），受害者页面运行在端口 80（与靶场同 Origin）
        <br>3. 本场景需通过 <strong>Docker Compose 部署</strong>后测试（前端 Nginx 暴露端口 80/81），本地开发模式不经过 Nginx
      </div>
      <div style="text-align: left; color: #e67e22; font-size: 12px; margin-top: 6px; background:#fff3e0; padding:8px 10px; border-radius:4px; border-left:3px solid #e67e22;">
        ⚠️ 注意：iframe 加载的 <code>clickjacking-victim-vuln.html</code> 是<strong>靶场业务系统提供的合法页面</strong>（部署在端口 80），
        不是攻击者放上去的。攻击者只是写 <code>&lt;iframe src="..."&gt;</code> 让浏览器去业务方服务器拉取这个未加防护的合法页面。
        详细说明见"漏洞描述"标签页。
      </div>
      <br />
      <div style="text-align: left;">
        <strong>攻击步骤：</strong>
        <ol style="margin-top: 6px; padding-left: 22px; line-height: 1.9; color: #606266;">
          <li>点击下方"打开攻击者钓鱼页"，新标签页打开 <code>http://127.0.0.1:81/clickjacking-attacker.html</code></li>
          <li>钓鱼页默认加载漏洞版受害者页面，建议先用<strong>"半透明（教学）"</strong>模式直观看到 iframe 错位</li>
          <li>切换回<strong>"透明（真实攻击）"</strong>模式，点击红色"立即领取大奖"按钮</li>
          <li>实际点击穿透到 iframe 内的"确认修改密码"按钮（fixed 锁定在视口顶部）→ 触发 <code>/changePassword</code> → 密码被改为 <code>hacked_by_clickjacking</code></li>
          <li>退出靶场重新登录，原密码已失效，需使用新密码登录</li>
        </ol>
      </div>
      <div style="margin-top: 16px; text-align: center;">
        <el-button type="danger" @click="openAttacker">打开攻击者钓鱼页（新标签）</el-button>
      </div>
      <div class="result-box result-warning" style="margin-top: 16px; text-align: left;">
        <strong>预期结果：</strong>密码修改请求成功，admin 密码被改为攻击者预设值。
        <br>F12 → Network 可看到 POST <code>/changePassword</code> 请求带着您真实的 JWT 头部成功发起。
        <br><br>
        <strong>恢复密码：</strong>测试结束后，可重新登录靶场，进入"个人中心"修改密码恢复原值。
      </div>
    </el-dialog>

    <!-- 安全版测试对话框 -->
    <el-dialog title="点击劫持安全版测试" :visible.sync="secDialogVisible" class="center-dialog" width="780px">
      <div style="text-align: left; color: green; font-style: italic;">
        安全版受害者页面通过 Nginx 配置加入 <code>X-Frame-Options: DENY</code>，浏览器拒绝将其渲染到 iframe 中。
      </div>
      <br />
      <div style="text-align: left;">
        <strong>测试步骤：</strong>
        <ol style="margin-top: 6px; padding-left: 22px; line-height: 1.9; color: #606266;">
          <li>点击下方"打开攻击者钓鱼页"，新标签页打开钓鱼页</li>
          <li>在控制面板"受害者页面"下拉中选择<strong>"安全版（X-Frame-Options: DENY）"</strong></li>
          <li>切换"完全可见"模式，观察 iframe 加载结果</li>
        </ol>
      </div>
      <div style="margin-top: 16px; text-align: center;">
        <el-button type="success" @click="openAttacker">打开攻击者钓鱼页（新标签）</el-button>
      </div>
      <div class="result-box result-success" style="margin-top: 16px; text-align: left;">
        <strong>预期结果：</strong>iframe 显示空白（或浏览器报错），无法加载受害者页面。
        <br>F12 → Console 会看到：<code>Refused to display 'http://127.0.0.1/clickjacking-victim-sec.html' in a frame because it set 'X-Frame-Options' to 'deny'</code>
        <br><br>
        即使攻击者构造了精美的钓鱼页，iframe 被浏览器拒绝加载，点击穿透攻击无法成立。
      </div>
    </el-dialog>
  </div>
</template>

<script>
export default {
  name: 'ClickJacking',
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false
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
    openAttacker() {
      // 攻击者钓鱼页运行在端口 81（独立 Origin）
      const origin = window.location.protocol + '//' + window.location.hostname
      const url = origin + ':81/clickjacking-attacker.html'
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

.result-box {
  padding: 12px 16px;
  border-radius: 4px;
  line-height: 1.7;
  font-size: 13px;
}

.result-success {
  background-color: #f0f9ff;
  color: #67c23a;
  border: 1px solid #c6e2ff;
}

.result-warning {
  background-color: #fdf6ec;
  color: #e6a23c;
  border: 1px solid #f5dab1;
}
</style>
