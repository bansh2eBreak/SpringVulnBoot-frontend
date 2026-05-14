<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">配置漏洞 -- CORS 配置错误（Cross-Origin Resource Sharing Misconfiguration）</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>一、浏览器同源策略（Same-Origin Policy）</strong><br />
                            同源策略是浏览器最核心的安全机制之一。"同源"指<strong>协议 + 域名 + 端口</strong>三者完全相同。
                            不同源的页面之间，浏览器默认禁止 JavaScript 读取对方的响应内容，防止恶意网站窃取用户数据。<br />
                            例如：前端（<code>http://127.0.0.1:80</code>）访问后端（<code>http://127.0.0.1:8080</code>），因端口不同，属于跨域请求。<br />
                            <br />
                            <strong>二、跨域（Cross-Origin）与 CORS</strong><br />
                            CORS（Cross-Origin Resource Sharing，跨域资源共享）是 W3C 标准，
                            允许服务器通过响应头主动声明"哪些来源可以访问我"，从而在保证安全的前提下放开跨域限制。<br />
                            核心响应头：<br />
                            &nbsp;&nbsp;• <code>Access-Control-Allow-Origin</code>：允许的来源（精确域名）<br />
                            &nbsp;&nbsp;• <code>Access-Control-Allow-Credentials</code>：是否允许携带 Cookie/Token 等凭证<br />
                            &nbsp;&nbsp;• <code>Access-Control-Allow-Methods</code>：允许的请求方法<br />
                            &nbsp;&nbsp;• <code>Access-Control-Allow-Headers</code>：允许的请求头<br />
                            <br />
                            <strong>三、简单请求与非简单请求</strong><br />
                            浏览器将跨域请求分为两类，处理方式不同：<br /><br />
                            <strong>简单请求（Simple Request）</strong>——<span style="color:#67C23A">直接发送，无预检</span><br />
                            满足以下全部条件才是简单请求：<br />
                            &nbsp;&nbsp;• 请求方法仅限：GET、HEAD、POST<br />
                            &nbsp;&nbsp;• Content-Type 仅限：<code>text/plain</code>、<code>multipart/form-data</code>、<code>application/x-www-form-urlencoded</code><br />
                            &nbsp;&nbsp;• 没有自定义请求头（如 Authorization）<br />
                            浏览器直接发出请求，但若响应头中无匹配的 <code>Access-Control-Allow-Origin</code>，JS 无法读取响应。<br /><br />
                            <strong>非简单请求（Non-Simple Request）</strong>——<span style="color:#E6A23C">先发预检，再发真实请求</span><br />
                            以下情况触发预检：<br />
                            &nbsp;&nbsp;• 请求方法为 PUT、DELETE、PATCH 等<br />
                            &nbsp;&nbsp;• Content-Type 为 <code>application/json</code>（现代前后端分离项目最常见）<br />
                            &nbsp;&nbsp;• 携带自定义 Header（如 <code>Authorization: Bearer xxx</code>）<br />
                            本靶场前端发出的所有请求均携带 <code>Authorization</code> Header，全部属于非简单请求，均会触发预检。<br />
                            <br />
                            <strong>四、预检请求（Preflight Request）</strong><br />
                            浏览器在发送非简单请求前，先自动发一个 <code>OPTIONS</code> 请求询问服务器是否允许。
                            服务器通过 CORS 响应头回答，浏览器再决定是否放行真实请求。
                            若服务器响应中无匹配的 <code>Access-Control-Allow-Origin</code>，浏览器直接拦截，真实请求不会发出。<br />
                            <br />
                            <strong>五、CORS 配置错误漏洞</strong><br />
                            当服务器 CORS 配置不当时，攻击者的恶意页面可携带受害者凭证（Cookie/Token）向目标服务器发起跨域请求，并读取响应数据。<br />
                            常见错误：<br />
                            &nbsp;&nbsp;• <strong>漏洞1</strong>：允许任意来源 + 允许携带凭证（<code>addAllowedOriginPattern("*")</code> + <code>allowCredentials(true)</code>）<br />
                            &nbsp;&nbsp;• <strong>漏洞2</strong>：Origin 校验逻辑有缺陷，可被绕过（如 <code>contains</code>、<code>endsWith</code> 模糊匹配）
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            1. <strong>敏感数据泄露</strong>：攻击者恶意页面可读取受害者的用户信息、Token、薪资、证件号、API 密钥等<br />
                            2. <strong>账户接管</strong>：结合读取 Token 的能力，可进一步发起账户劫持攻击<br />
                            3. <strong>危害大于 CSRF</strong>：CSRF 只能让受害者"发出请求"（无法读响应），CORS 配置错误可让攻击者直接读到响应内容<br />
                            4. <strong>攻击无感知</strong>：受害者只需访问攻击者的页面，无需任何操作，数据即被静默窃取<br />
                            5. <strong>影响范围广</strong>：所有已登录用户均为潜在受害者，一次配置错误影响全站
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【必须】使用精确的 Origin 白名单，禁止 addAllowedOriginPattern("*") + allowCredentials(true) 同时出现</strong><br />
                            <pre style="background:#f0f9ff;padding:8px;border-radius:4px;font-size:12px;margin:8px 0;">// ✅ 正确：精确白名单
corsConfiguration.addAllowedOrigin("https://app.secnotes.icu");
corsConfiguration.addAllowedOrigin("https://admin.secnotes.icu");
corsConfiguration.setAllowCredentials(true);</pre>
                            <strong>【必须】校验 Origin 时使用完整精确匹配，禁止 contains / endsWith 等模糊匹配</strong><br />
                            错误示范：<code>origin.contains("secnotes")</code> → <code>http://evilsecnotes.com</code> 可绕过<br />
                            错误示范：<code>origin.endsWith(".secnotes.icu")</code> → 攻击者注册子域名即可绕过<br />
                            正确做法：将 Origin 与精确白名单列表对比（<code>whitelist.contains(origin)</code>）<br /><br />
                            <strong>【必须】白名单中的 Origin 必须包含完整的协议 + 域名 + 端口</strong><br />
                            如 <code>https://app.secnotes.icu</code>，不能省略协议或端口<br /><br />
                            <strong>【建议】生产环境 CORS 白名单通过配置文件管理，禁止硬编码，便于各环境统一维护</strong><br /><br />
                            <strong>【建议】关键接口增加 CSRF Token 或 SameSite=Strict Cookie 作为第二道防线</strong>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://developer.mozilla.org/zh-CN/docs/Web/HTTP/CORS" target="_blank" style="text-decoration:underline;">《MDN - 跨域资源共享（CORS）》</a><br />
                            <a href="https://developer.mozilla.org/zh-CN/docs/Web/Security/Same-origin_policy" target="_blank" style="text-decoration:underline;">《MDN - 浏览器同源策略》</a><br />
                            <a href="https://portswigger.net/web-security/cors" target="_blank" style="text-decoration:underline;">《PortSwigger - CORS 漏洞详解与实验》</a><br />
                            <a href="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny" target="_blank" style="text-decoration:underline;">《OWASP - CORS Origin 头部安全分析》</a><br />
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing" target="_blank" style="text-decoration:underline;">《OWASP CORS 安全配置清单》</a>
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>

        <!-- 代码演示区域 -->
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <!-- 漏洞1 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - Origin 完全信任（任意来源可携带凭证访问）
                            <el-button type="danger" round size="mini" @click="vuln1DialogVisible = true">去测试</el-button>
                        </el-row>
                        <pre v-highlightjs><code class="java">// ===== CorsConfig.java =====
// ❌ 危险配置：addAllowedOriginPattern("*") + allowCredentials(true)
// 后端将请求中的 Origin 原样反射到响应头
// 任意来源的恶意页面均可携带受害者 Token 读取响应数据

CorsConfiguration config = new CorsConfiguration();
config.setAllowCredentials(true);
config.addAllowedOriginPattern("*"); // 反射任意 Origin
config.addAllowedMethod("*");
config.addAllowedHeader("*");
source.registerCorsConfiguration("/cors/vuln1/**", config);

// 攻击者恶意页面发起请求：
// Origin: http://evil.com
// 响应头：Access-Control-Allow-Origin: http://evil.com
//        Access-Control-Allow-Credentials: true
// 结果：浏览器允许 evil.com 的 JS 读取响应 → 数据泄露！

// ===== CorsController.java =====
// Controller 无需做任何 CORS 判断，CORS 过滤器已全部放行
@GetMapping("/vuln1/sensitiveData")
public Result vuln1SensitiveData(HttpServletRequest request) {
    return Result.success(buildSensitiveData(request));
}</code></pre>
                    </div>
                </el-col>

                <!-- 安全版 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - 严格白名单（非白名单来源一律拒绝）
                            <el-button type="success" round size="mini" @click="secureDialogVisible = true">去测试</el-button>
                        </el-row>
                        <pre v-highlightjs><code class="java">// ===== CorsConfig.java =====
// ✅ 安全配置：精确白名单，仅允许指定来源
// 非白名单来源在预检（OPTIONS）阶段即被拦截，真实请求不会发出

CorsConfiguration config = new CorsConfiguration();
config.setAllowCredentials(true);
// 精确指定允许的来源（协议 + 域名 + 端口缺一不可）
config.addAllowedOrigin("http://trusted.secnotes.icu");
config.addAllowedMethod("*");
config.addAllowedHeader("*");
source.registerCorsConfiguration("/cors/secure/**", config);

// 攻击者页面（127.0.0.1:81）不在白名单，浏览器报错：
// "No 'Access-Control-Allow-Origin' header is present
//  on the requested resource."

// ===== CorsController.java =====
// 不在白名单的来源在过滤器层已被拒绝，Controller 无需额外判断
@GetMapping("/secure/sensitiveData")
public Result secureSensitiveData(HttpServletRequest request) {
    return Result.success(buildSensitiveData(request));
}</code></pre>
                    </div>
                </el-col>
            </el-row>

            <el-row :gutter="20" class="grid-flex">
                <!-- 漏洞2 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - Origin 校验可绕过（模糊匹配被绕过）
                            <el-button type="danger" round size="mini" @click="vuln2DialogVisible = true">去测试</el-button>
                        </el-row>
                        <pre v-highlightjs><code class="java">// ===== CorsConfig.java =====
// ❌ 危险配置：使用模糊匹配，等价于 origin.contains("127.0.0.1")
// 开发者原意：只允许本机（127.0.0.1）访问
// 实际缺陷：端口 :80（合法前端）和 :81（攻击者页面）
//           都包含 "127.0.0.1"，攻击者照样绕过

CorsConfiguration config = new CorsConfiguration();
config.setAllowCredentials(true);
config.addAllowedOriginPattern("*127.0.0.1*"); // 模糊匹配，可被绕过
config.addAllowedMethod("*");
config.addAllowedHeader("*");
source.registerCorsConfiguration("/cors/vuln2/**", config);

// 绕过方式：攻击者页面（:81）的 Origin 同样包含 "127.0.0.1"
// http://127.0.0.1:81 → 匹配 *127.0.0.1* → 校验通过！

// ===== CorsController.java =====
// Controller 无需做任何 CORS 判断，CORS 过滤器已按模糊匹配放行
@GetMapping("/vuln2/sensitiveData")
public Result vuln2SensitiveData(HttpServletRequest request) {
    return Result.success(buildSensitiveData(request));
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12"></el-col>
            </el-row>
        </div>

        <!-- 漏洞1 测试对话框 -->
        <el-dialog title="⚠️ CORS 漏洞1 - Origin 完全信任" :visible.sync="vuln1DialogVisible" width="680px">
            <el-alert type="info" :closable="false" style="margin-bottom:20px;">
                <div style="line-height:2;font-size:13px;">
                    <strong>真实攻击演示：</strong>受害者登录靶场后，访问攻击者控制的恶意网站（端口 81，不同 Origin）。<br />
                    恶意网站的 JS 携带受害者 Token 向靶场 API（端口 8080）发起跨域请求，因 CORS 配置信任任意来源，成功读取敏感数据。
                </div>
            </el-alert>
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <el-button type="danger" @click="openAttackerPage">打开攻击者模拟页面（端口 81）</el-button>
                <span style="font-size:12px;color:#999;">在新标签打开，粘贴 Token 后点击"攻击漏洞1"按钮</span>
            </div>
        </el-dialog>

        <!-- 漏洞2 测试对话框 -->
        <el-dialog title="⚠️ CORS 漏洞2 - Origin 校验可绕过" :visible.sync="vuln2DialogVisible" width="680px">
            <el-alert type="info" :closable="false" style="margin-bottom:20px;">
                <div style="line-height:2;font-size:13px;">
                    <strong>漏洞说明：</strong>后端 CORS 配置使用 <code>contains("127.0.0.1")</code> 模糊匹配，本意只允许本机访问。<br />
                    缺陷在于：<code>http://127.0.0.1:80</code>（合法前端）和 <code>http://127.0.0.1:81</code>（攻击者页面）都包含 "127.0.0.1"，<br />
                    端口不同即为不同 Origin，攻击者页面（端口 81）照样绕过校验，成功读取敏感数据。
                </div>
            </el-alert>
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <el-button type="danger" @click="openAttackerPage">打开攻击者模拟页面（端口 81）</el-button>
                <span style="font-size:12px;color:#999;">在新标签打开，粘贴 Token 后点击"攻击漏洞2"按钮</span>
            </div>
        </el-dialog>

        <!-- 安全版 测试对话框 -->
        <el-dialog title="✅ CORS 安全版 - 严格白名单防御" :visible.sync="secureDialogVisible" width="680px">
            <el-alert title="防御原理" type="success" :closable="false" style="margin-bottom:20px;">
                <div style="line-height:2;">
                    后端仅允许 <code>http://trusted.secnotes.icu</code> 跨域访问。<br />
                    攻击者模拟页面（端口 81）不在白名单内，浏览器在预检（OPTIONS）阶段即拦截，真实请求不会发出，攻击者无法读取任何响应数据。
                </div>
            </el-alert>
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <el-button type="success" @click="openAttackerPage">打开攻击者模拟页面（端口 81）</el-button>
                <span style="font-size:12px;color:#999;">在新标签打开，点击"测试安全版"按钮，观察 CORS 拦截效果</span>
            </div>
        </el-dialog>
    </div>
</template>

<script>

export default {
    name: 'CorsVuln',
    data() {
        return {
            activeName: 'first',
            vuln1DialogVisible: false,
            vuln2DialogVisible: false,
            secureDialogVisible: false
        }
    },
    methods: {
        handleClick() {},
        openAttackerPage() {
            // 攻击者模拟页面通过端口 81 访问，与靶场前端（端口 80）属于不同 Origin
            const url = `${window.location.protocol}//${window.location.hostname}:81`
            window.open(url, '_blank')
        }
    }
}
</script>

<style scoped>
.vuln-info {
    border-radius: 10px;
    margin: 20px;
    margin-top: 10px;
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
    line-height: 1.8;
}
.vuln-detail code {
    background-color: #f0f0f0;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    color: #e74c3c;
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
.preview-content {
    margin-top: 10px;
}
.preview-text {
    text-align: left;
    background-color: #f5f7fa;
    padding: 10px;
    border-radius: 4px;
    max-height: 300px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 13px;
}
.result-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.result-table tr {
    border-bottom: 1px solid #ebeef5;
}
.result-table tr:last-child {
    border-bottom: none;
}
.result-table .sensitive-row {
    background-color: #fff5f5;
}
.result-table td {
    padding: 10px 14px;
    vertical-align: middle;
}
.result-label {
    width: 110px;
    background-color: #fafafa;
    color: #606266;
    font-weight: bold;
    border-right: 1px solid #ebeef5;
    white-space: nowrap;
}
.result-value {
    color: #303133;
}
.result-value.sensitive {
    color: #f56c6c;
    font-weight: bold;
}
</style>
