<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- 二次注入</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>二次注入（Second Order SQL Injection）</strong>是 SQL 注入中<span style="color: red;">最隐蔽、最难发现的类型</span>。
                            它的攻击代码分<span style="color: red;">两个阶段</span>执行：第一次输入时被安全存储，第二次使用时才触发注入。
                            <br /><br />
                            <strong>核心特点：</strong><br />
                            1. <strong>两阶段攻击</strong>：存储时安全，使用时触发<br />
                            2. <strong>隐蔽性强</strong>：第一次存储使用预编译，代码审计难以发现<br />
                            3. <strong>危害严重</strong>：可以修改任意用户数据，包括管理员密码<br />
                            <br />
                            <strong>与普通 SQL 注入的区别：</strong><br />
                            • <span style="color: #ff9800;">普通注入</span>：第一次输入时直接触发，容易被发现和防御（直接）<br />
                            • <span style="color: #f56c6c;">二次注入</span>：第一次安全存储，第二次使用时触发（隐蔽）
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            二次注入的危害往往比普通 SQL 注入更严重，因为它发生在业务逻辑深处，不易被发现：<br /><br />
                            <strong>1. 权限提升</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 普通用户可以修改管理员账号的密码<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 获取系统最高权限，控制整个应用<br /><br />
                            <strong>2. 批量数据篡改</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 同时修改多个用户的敏感数据（密码、邮箱、权限等）<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 修改订单金额、收货地址，造成经济损失<br /><br />
                            <strong>3. 数据泄露</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 通过注入条件读取其他用户的敏感信息<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 获取数据库结构、表名、列名<br /><br />
                            <strong>4. 真实案例</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 某社交平台：用户昵称二次注入，泄露百万用户密码<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 某电商网站：评论内容二次注入，修改订单金额
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【必须】全程使用参数化查询</strong><br />
                            无论是存储还是使用，都应使用预编译/参数化查询，绝不直接拼接 SQL。<br /><br />

                            <strong>【必须】MyBatis 使用 #{} 而非 ${}</strong><br />
                            MyBatis 的 <code>#{}</code> 底层使用 PreparedStatement 预编译，<code>${}</code> 是字符串替换，会导致注入。<br /><br />

                            <strong>【必须】输入验证</strong><br />
                            对用户输入进行严格的格式验证、类型检查和长度限制，禁止包含特殊字符。<br /><br />

                            <strong>【建议】输出转义</strong><br />
                            从数据库读取的数据，在二次使用前进行转义处理（虽然使用预编译已足够安全）。<br /><br />

                            <strong>【建议】代码审计</strong><br />
                            重点审查从数据库读取数据后，再次使用到 SQL 语句中的代码逻辑，这是二次注入的高危场景。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank"
                                style="text-decoration: underline;">《SQL Injection》</a> - OWASP 官方文档<br />
                            <a href="https://portswigger.net/web-security/sql-injection" target="_blank"
                                style="text-decoration: underline;">《SQL injection》</a> - PortSwigger 安全指南<br />
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank"
                                style="text-decoration: underline;">《SQL Injection Prevention Cheat Sheet》</a> - SQL 注入防御速查表<br />
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>

        <!-- 代码演示区域 -->
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <!-- 漏洞代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - MyBatis方式 - 使用 ${}
                            <div>
                                <el-button type="danger" round size="mini" @click="vulnDialogVisible = true">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * 二次注入 - 漏洞版本（MyBatis）
 * 场景：修改密码功能
 * 漏洞：使用 ${} 直接拼接 SQL
 */
// Mapper 接口
@Update("UPDATE admin SET password = #{newPassword} " +
        "WHERE username = '\${username}'")
int changePassword(@Param("username") String username, 
                   @Param("newPassword") String newPassword);

// Controller
@PostMapping("/changePassword")
public Result changePassword(@RequestBody Map&lt;String, String&gt; params,
                            HttpServletRequest httpRequest) {
    String token = httpRequest.getHeader("Authorization");
    // ❌ 从 Token 获取 username（从数据库读取，可能包含恶意SQL）
    String username = JwtUtils.parseJwt(token).get("username").toString();
    String newPassword = params.get("newPassword");
    
    // ⚠️ 危险：使用 ${} 拼接 username，触发二次注入
    int affectedRows = loginService.changePassword(username, newPassword);
    
    // 例如: username = "hacker' OR username='admin'#"
    // SQL: UPDATE admin SET password='888888' WHERE username='hacker' OR username='admin'#'
    //                                                注释掉后面的单引号 ↑
    return Result.success("密码修改成功");
}</code></pre>
                    </div>
                </el-col>

                <!-- 安全代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - MyBatis方式 - 使用 #{}
                            <div>
                                <el-button type="success" round size="mini" @click="secDialogVisible = true">
                                    查看说明
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * 二次注入 - 安全版本（MyBatis）
 * 防御：使用 MyBatis 的 #{} 进行参数绑定
 * 原理：#{} 底层使用 PreparedStatement 预编译
 */
// Mapper 接口
@Update("UPDATE admin SET password = #{newPassword} " +
        "WHERE username = #{username}")
int changePassword(@Param("username") String username, 
                   @Param("newPassword") String newPassword);

// Controller
@PostMapping("/changePassword")
public Result changePassword(@RequestBody Map&lt;String, String&gt; params,
                            HttpServletRequest httpRequest) {
    String token = httpRequest.getHeader("Authorization");
    // ✅ 从 Token 获取 username
    String username = JwtUtils.parseJwt(token).get("username").toString();
    String newPassword = params.get("newPassword");
    
    // ✅ 使用 #{} 的 Mapper 方法，自动转义特殊字符
    int affectedRows = loginService.changePassword(username, newPassword);
    
    // ✅ 即使 username = "hacker' OR username='admin'#"，也会被转义
    // SQL: UPDATE admin SET password='888888' WHERE username='hacker\' OR username=\'admin\'#'
    // 查询条件只能匹配字面量用户名，无法注入SQL逻辑
    return Result.success("密码修改成功");
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 漏洞测试对话框 -->
        <el-dialog title="💥 二次注入攻击演示（完整测试流程）" :visible.sync="vulnDialogVisible" width="800px">
            <el-alert
                title="💡 二次注入完整攻击流程"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>攻击步骤（依次执行）：</strong><br />
                    <strong>① 注册恶意用户：</strong>在登录页点击"注册账号"，使用以下信息：<br />
                    &nbsp;&nbsp;&nbsp;&nbsp;用户名：<el-tag type="danger" size="small">hacker' OR username='admin'#</el-tag>
                    <el-button size="mini" type="text" @click="copyMaliciousUsername" style="padding: 0;">📋 复制</el-button><br />
                    &nbsp;&nbsp;&nbsp;&nbsp;密码：<code>hacker123</code>（任意密码）<br />
                    <strong>② 登录恶意账号：</strong>退出当前账号，使用刚注册的恶意账号登录<br />
                    <strong>③ 修改密码（触发注入）：</strong>点击右上角用户名 → <code>ResetPass</code> → 输入新密码（如 <code>888888</code>）→ 点击"提交"<br />
                    <strong>④ 验证攻击成功：</strong>退出登录，使用 <code>admin</code> / <code>888888</code> 登录 → 🎯 登录成功 = 攻击成功！
                </div>
            </el-alert>

            <el-collapse>
                <el-collapse-item title="🔍 为什么会产生二次注入？（点击展开详情）" name="1">
                    <div style="padding: 10px;">
                        <el-alert type="info" :closable="false">
                            <div style="font-size: 13px; line-height: 1.8;">
                                <p style="margin: 5px 0;"><strong>第一次（注册）：</strong>恶意用户名被<span style="color: green;">正确转义</span>存入数据库</p>
                                <pre style="background-color: #f5f5f5; padding: 8px; border-radius: 4px; margin: 8px 0; font-size: 12px;">使用预编译：INSERT INTO admin(...) VALUES(?, ...)
存储结果：username = "hacker' OR username='admin'#"</pre>

                                <p style="margin: 15px 0 5px 0;"><strong>第二次（修改密码）：</strong>从数据库读取 username 后，<span style="color: red;">直接拼接</span>到 SQL 中</p>
                                <pre style="background-color: #fff0f0; padding: 8px; border-radius: 4px; color: #F56C6C; margin: 8px 0; font-size: 12px;">使用 MyBatis ${}：UPDATE admin SET password='888888' WHERE username='${username}'
执行的 SQL：UPDATE admin SET password='888888' WHERE username='hacker' OR username='admin'#'
                             注释掉后面 ↑</pre>

                                <p style="margin: 15px 0 5px 0;"><strong>触发注入：</strong><code>#</code> 注释掉后面的单引号，<code>OR username='admin'</code> 被解释为 SQL 条件</p>
                            </div>
                        </el-alert>
                    </div>
                </el-collapse-item>
            </el-collapse>
        </el-dialog>

        <!-- 安全说明对话框 -->
        <el-dialog title="✅ 二次注入防御说明" :visible.sync="secDialogVisible" width="700px">
            <el-alert
                title="🛡️ 防御原理 - 使用 #{} 参数化查询"
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 1.8;">
                    <p style="margin: 5px 0;">使用 <code>#{}</code> 参数化查询，MyBatis 会将其编译为 PreparedStatement 的 <code>?</code> 占位符，并自动转义特殊字符。</p>
                    
                    <br />
                    <strong>安全执行流程：</strong>
                    <ol style="padding-left: 20px; margin: 10px 0;">
                        <li>MyBatis 将 SQL 编译为：<code>UPDATE admin SET password = ? WHERE username = ?</code></li>
                        <li>参数 <code>hacker' OR username='admin'--</code> 被转义为 <code>hacker\' OR username=\'admin\'--</code></li>
                        <li>WHERE 条件只能匹配字面量用户名，无法注入 SQL 逻辑</li>
                        <li>只有真实存在用户名为 <code>hacker' OR username='admin'--</code> 的用户才会被修改（实际不存在）</li>
                    </ol>
                </div>
            </el-alert>

            <el-alert type="info" title="核心区别" :closable="false">
                <p style="margin: 5px 0;">• <code style="color: #F56C6C;">${}</code>：字符串替换，直接拼接，<strong style="color: #F56C6C;">危险</strong></p>
                <p style="margin: 5px 0;">• <code style="color: #67C23A;">#{}</code>：参数化查询，自动转义，<strong style="color: #67C23A;">安全</strong></p>
            </el-alert>
        </el-dialog>
    </div>
</template>

<script>
export default {
    name: 'SecondOrder',
    data() {
        return {
            activeName: 'first',
            vulnDialogVisible: false,
            secDialogVisible: false
        }
    },
    methods: {
        handleClick(tab, event) {
            console.log(tab, event)
        },
        copyMaliciousUsername() {
            const text = "hacker' OR username='admin'#"
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    this.$message.success('恶意用户名已复制到剪贴板')
                }).catch(() => {
                    this.fallbackCopy(text)
                })
            } else {
                this.fallbackCopy(text)
            }
        },
        fallbackCopy(text) {
            const textarea = document.createElement('textarea')
            textarea.value = text
            textarea.style.position = 'fixed'
            textarea.style.opacity = '0'
            document.body.appendChild(textarea)
            textarea.select()
            try {
                document.execCommand('copy')
                this.$message.success('恶意用户名已复制到剪贴板')
            } catch (err) {
                this.$message.error('复制失败，请手动复制：' + text)
            }
            document.body.removeChild(textarea)
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
</style>
