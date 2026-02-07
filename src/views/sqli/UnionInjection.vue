<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- UNION联合注入</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>UNION 联合注入（UNION-Based SQL Injection）</strong>是 SQL 注入中<span style="color: red;">最经典、最直接的类型</span>。
                            它利用 SQL 的 <code>UNION</code> 操作符来合并多个 <code>SELECT</code> 语句的结果集，从而<span style="color: red;">一次性获取大量敏感数据</span>。
                            <br /><br />
                            <strong>核心特点：</strong><br />
                            1. <strong>有数据回显</strong>：页面直接显示查询结果（如文章标题、内容）<br />
                            2. <strong>效率最高</strong>：一次请求即可获取完整数据，无需逐字符猜测<br />
                            3. <strong>应用广泛</strong>：新闻网站、博客系统、CMS 后台都是高危场景<br />
                            <br />
                            <strong>与布尔盲注的区别：</strong><br />
                            • <span style="color: #ff9800;">布尔盲注</span>：页面只返回"真/假"，需要发送数百次请求逐字符猜测（慢）<br />
                            • <span style="color: #4caf50;">UNION 注入</span>：页面直接显示数据，1次请求获取完整结果（快）
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            UNION 注入是危害最严重的 SQL 注入类型之一：<br /><br />
                            <strong>1. 数据库完全泄露</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 一次性获取所有表名、列名<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 批量导出用户账号、密码（通常是明文或弱加密）<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 窃取订单、交易、个人隐私等敏感数据<br /><br />
                            <strong>2. 绕过身份认证</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 直接获取管理员账号密码<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 登录后台，控制整个系统<br /><br />
                            <strong>3. 横向扩展攻击</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 通过泄露的密码撞库其他系统<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 利用数据库用户权限读写文件（如 LOAD_FILE、INTO OUTFILE）<br /><br />
                            <strong>4. 真实案例</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 2015年：某电商网站 UNION 注入，泄露 2000万用户数据<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 2018年：某政府网站被 UNION 注入，数据库完全泄露<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 大部分 SQL 注入漏洞赏金都是 UNION 注入类型
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【必须】使用预编译语句（PreparedStatement）</strong><br />
                            预编译可以确保 SQL 结构在编译时确定，用户输入的 <code>UNION</code>、<code>SELECT</code> 等关键字会被转义为普通字符串，无法改变 SQL 逻辑。<br /><br />

                            <strong>【必须】屏蔽详细错误信息</strong><br />
                            禁止将 SQL 语法错误、表名、列名等信息返回给前端，避免攻击者利用错误信息判断列数和数据库结构。<br /><br />

                            <strong>【建议】最小权限原则</strong><br />
                            数据库账号只授予必要的权限（如只读权限），禁止使用 root 账号连接应用，防止攻击者利用 <code>LOAD_FILE</code>、<code>INTO OUTFILE</code> 等高危函数。<br /><br />

                            <strong>【建议】输入校验</strong><br />
                            虽然预编译已经足够安全,但仍建议对输入进行白名单校验（如 ID 必须是数字），提供纵深防御。<br /><br />

                            <strong>【建议】Web应用防火墙（WAF）</strong><br />
                            部署 WAF 检测和拦截 SQL 注入攻击，但不能完全依赖 WAF（因为存在绕过可能）。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://portswigger.net/web-security/sql-injection/union-attacks" target="_blank"
                                style="text-decoration: underline;">《SQL injection UNION attacks》</a> - PortSwigger 官方教程<br />
                            <a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank"
                                style="text-decoration: underline;">《SQL Injection》</a> - OWASP 安全指南<br />
                            <a href="https://www.sqlinjection.net/union/" target="_blank"
                                style="text-decoration: underline;">《UNION Based SQL Injection》</a> - SQL注入技术详解<br />
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
                            漏洞代码 - JDBC方式 - 字符串拼接
                            <div>
                                <el-button type="danger" round size="mini" @click="openVulnDialog">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * UNION 注入 - 漏洞版本
 * 场景：查询文章详情
 * 漏洞：直接拼接 SQL，允许 UNION 注入
 */
@GetMapping("/getArticleVuln")
public Result getArticleVuln(String id) {
    // 1. 注册驱动
    Class.forName("com.mysql.cj.jdbc.Driver");
    // 2. 获取连接
    Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
    // 3. ❌ 拼接 SQL（漏洞点）
    String sql = "SELECT id, title, author, content, create_time " + 
                 "FROM articles WHERE id = " + id;
    
    log.warn("【UNION注入漏洞】执行SQL: {}", sql);
    
    // 4. 执行查询
    Statement statement = conn.createStatement();
    ResultSet resultSet = statement.executeQuery(sql);
    
    // 5. 返回结果
    // ⚠️ 攻击者可以使用 UNION SELECT 获取其他表数据
    // 例如: id=-1 UNION SELECT 1,username,password,avatar,5 FROM admin
    return Result.success(resultSet);
}</code></pre>
                    </div>
                </el-col>

                <!-- 安全代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - JDBC方式 - 预编译
                            <div>
                                <el-button type="success" round size="mini" @click="openSecDialog">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * UNION 注入 - 安全版本
 * 防御：使用 PreparedStatement 预编译 + 参数绑定
 */
@GetMapping("/getArticleSec")
public Result getArticleSec(String id) {
    // 1. 注册驱动
    Class.forName("com.mysql.cj.jdbc.Driver");
    // 2. 获取连接
    Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
    // 3. ✅ 使用预编译（安全点）
    String sql = "SELECT id, title, author, content, create_time " + 
                 "FROM articles WHERE id = ?";
    
    log.info("【安全】执行SQL: {}, 参数: {}", sql, id);
    
    // 4. 参数绑定
    PreparedStatement ps = conn.prepareStatement(sql);
    ps.setString(1, id);  // UNION 等关键字被转义为普通字符串
    
    // 5. 执行查询
    ResultSet resultSet = ps.executeQuery();
    
    // 6. 返回结果
    // ✅ 即使输入 "1 UNION SELECT..."，也会被当作普通字符串查询
    // 查询条件变成: WHERE id = '1 UNION SELECT...'（找不到结果）
    return Result.success(resultSet);
}</code></pre>
                    </div>
                </el-col>
            </el-row>

            <!-- MyBatis 版本 -->
            <el-row :gutter="20" class="grid-flex" style="margin-top: 30px;">
                <!-- 漏洞代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - MyBatis方式 - 使用 ${}
                            <div>
                                <el-button type="danger" round size="mini" @click="openVulnDialogMybatis">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * UNION 注入 - 漏洞版本（MyBatis）
 * 场景：查询文章详情
 * 漏洞：使用 ${} 直接拼接 SQL
 */
// Mapper 接口
@Select("SELECT id, title, author, content, create_time " +
        "FROM articles WHERE id = \${id}")
List&lt;Article&gt; getArticleByIdVuln(@Param("id") String id);

// Controller
@GetMapping("/getArticleVuln")
public Result getArticleVuln(String id) {
    // ❌ 调用使用 ${} 的 Mapper 方法
    List&lt;Article&gt; articles = unionInjectionService.getArticleByIdVuln(id);
    
    log.warn("【UNION注入漏洞-MyBatis】查询成功，返回 {} 条记录", articles.size());
    
    // ⚠️ 攻击者可以使用 UNION SELECT 获取其他表数据
    // 例如: id=-1 UNION SELECT 1,username,password,avatar,5 FROM admin
    return Result.success(articles);
}</code></pre>
                    </div>
                </el-col>

                <!-- 安全代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - MyBatis方式 - 使用 #{}
                            <div>
                                <el-button type="success" round size="mini" @click="openSecDialogMybatis">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * UNION 注入 - 安全版本（MyBatis）
 * 防御：使用 MyBatis 的 #{} 进行参数绑定
 * 原理：#{} 底层使用 PreparedStatement 预编译
 */
// Mapper 接口
@Select("SELECT id, title, author, content, create_time " +
        "FROM articles WHERE id = #{id}")
List&lt;Article&gt; getArticleByIdSec(@Param("id") String id);

// Controller
@GetMapping("/getArticleSec")
public Result getArticleSec(String id) {
    // ✅ 调用使用 #{} 的 Mapper 方法
    List&lt;Article&gt; articles = unionInjectionService.getArticleByIdSec(id);
    
    log.info("【安全-MyBatis】查询成功，返回 {} 条记录", articles.size());
    
    // ✅ 即使输入 "1 UNION SELECT..."，也会被当作普通字符串查询
    // 查询条件变成: WHERE id = '1 UNION SELECT...'（找不到结果）
    return Result.success(articles);
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 漏洞测试对话框 -->
        <el-dialog title="🔴 文章详情查询（漏洞版 - UNION注入）" :visible.sync="vulnDialogVisible" width="900px">
            <el-alert
                title="💡 UNION 联合注入完整攻击流程"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>攻击步骤（依次执行）：</strong><br />
                    <strong>① 测试注入点：</strong><code>1'</code> → 查看是否报错（有错误说明存在注入）<br />
                    <strong>② 判断列数：</strong><code>1 ORDER BY 5</code> → 正常则有5列，<code>1 ORDER BY 6</code> → 报错则只有5列<br />
                    <strong>③ 确定回显位置：</strong><code>-1 UNION SELECT 1,2,3,4,5</code> → 查看哪些数字显示在页面上<br />
                    <strong>④ 获取数据库信息：</strong><code>-1 UNION SELECT 1,database(),user(),version(),5</code><br />
                    <strong>⑤ 获取所有表名：</strong><code>-1 UNION SELECT 1,2,group_concat(table_name),4,5 FROM information_schema.tables WHERE table_schema=database()</code><br />
                    <strong>⑥ 获取admin表列名：</strong><code>-1 UNION SELECT 1,2,group_concat(column_name),4,5 FROM information_schema.columns WHERE table_name='admin'</code><br />
                    <strong>⑦ 获取敏感数据：</strong><code>-1 UNION SELECT 1,username,password,avatar,5 FROM admin</code> → 🎯 获取所有管理员密码！
                </div>
            </el-alert>

            <!-- 文章ID输入 -->
            <div class="query-form">
                <el-form label-width="100px">
                    <el-form-item label="文章ID">
                        <el-input 
                            v-model="vulnForm.id" 
                            placeholder="请输入文章ID（支持SQL注入测试）"
                            clearable
                            style="width: 600px;">
                            <el-button 
                                slot="append" 
                                type="primary" 
                                @click="queryVulnArticle"
                                :loading="vulnQuerying">
                                查询文章
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 查询结果显示 -->
                <div v-if="vulnResult.show" class="query-result">
                    <!-- SQL语句显示 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content">{{ vulnResult.sql }}</div>
                    </div>

                    <!-- 查询结果 -->
                    <div v-if="vulnResult.results && vulnResult.results.length > 0" class="article-list">
                        <el-divider content-position="left">📄 查询结果</el-divider>
                        <div v-for="(article, index) in vulnResult.results" :key="index" class="article-item">
                            <div class="article-row">
                                <span class="article-label">ID:</span>
                                <span class="article-value">{{ article.id }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">标题:</span>
                                <span class="article-value">{{ article.title }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">作者:</span>
                                <span class="article-value">{{ article.author }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">内容:</span>
                                <span class="article-value article-content">{{ article.content }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">发布时间:</span>
                                <span class="article-value">{{ article.create_time }}</span>
                            </div>
                            <el-divider v-if="index < vulnResult.results.length - 1"></el-divider>
                        </div>
                    </div>
                    <el-alert v-else title="未找到文章或查询失败" type="info" :closable="false"></el-alert>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试（完整攻击链）</el-divider>
                    <!-- 第一行：4个按钮 -->
                    <el-row :gutter="10" style="margin-bottom: 10px;">
                        <el-col :span="6">
                            <el-button size="small" style="width: 100%;" @click="quickTest('1')">
                                ① 正常查询: ID=1
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTest('1\'')">
                                ② 测试注入点: 1'
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTest('1 ORDER BY 5')">
                                ③ 判断列数: ORDER BY 5
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTest('-1 UNION SELECT 1,2,3,4,5')">
                                ④ 确定回显: UNION 1,2,3,4,5
                            </el-button>
                        </el-col>
                    </el-row>
                    <!-- 第二行：4个按钮 -->
                    <el-row :gutter="10">
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTest('-1 UNION SELECT 1,database(),user(),version(),5')">
                                ⑤ 获取数据库信息
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTest('-1 UNION SELECT 1,2,group_concat(table_name),4,5 FROM information_schema.tables WHERE table_schema=database()')">
                                ⑥ 获取所有表名
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTest('-1 UNION SELECT 1,2,group_concat(column_name),4,5 FROM information_schema.columns WHERE table_name=\'admin\'')">
                                ⑦ 获取admin表列名
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTest('-1 UNION SELECT 1,username,password,avatar,5 FROM admin')">
                                ⑧ 🎯 获取管理员密码
                            </el-button>
                        </el-col>
                    </el-row>
                </div>
            </div>
        </el-dialog>

        <!-- 安全版本测试对话框 -->
        <el-dialog title="✅ 文章详情查询（安全版 - 预编译防御）" :visible.sync="secDialogVisible" width="900px">
            <el-alert
                title=""
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>✅ 防御原理：</strong><br />
                    &nbsp;&nbsp;• PreparedStatement 在编译时就确定了 SQL 结构<br />
                    &nbsp;&nbsp;• 用户输入的 <code>UNION</code>、<code>SELECT</code> 等关键字会被转义为普通字符串<br />
                    &nbsp;&nbsp;• 查询条件变成 <code>WHERE id = '1 UNION SELECT...'</code>（当作普通字符串查询，找不到结果）<br />
                    &nbsp;&nbsp;• 无论输入什么恶意代码，都无法改变 SQL 逻辑
                </div>
            </el-alert>

            <!-- 文章ID输入 -->
            <div class="query-form">
                <el-form label-width="100px">
                    <el-form-item label="文章ID">
                        <el-input 
                            v-model="secForm.id" 
                            placeholder="请输入文章ID（尝试注入攻击）"
                            clearable
                            style="width: 600px;">
                            <el-button 
                                slot="append" 
                                type="success" 
                                @click="querySecArticle"
                                :loading="secQuerying">
                                查询文章
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 查询结果显示 -->
                <div v-if="secResult.show" class="query-result">
                    <!-- SQL语句显示 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content">{{ secResult.sql }}</div>
                    </div>

                    <!-- 查询结果 -->
                    <div v-if="secResult.results && secResult.results.length > 0" class="article-list">
                        <el-divider content-position="left">📄 查询结果</el-divider>
                        <div v-for="(article, index) in secResult.results" :key="index" class="article-item">
                            <div class="article-row">
                                <span class="article-label">ID:</span>
                                <span class="article-value">{{ article.id }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">标题:</span>
                                <span class="article-value">{{ article.title }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">作者:</span>
                                <span class="article-value">{{ article.author }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">内容:</span>
                                <span class="article-value article-content">{{ article.content }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">发布时间:</span>
                                <span class="article-value">{{ article.create_time }}</span>
                            </div>
                        </div>
                    </div>
                    <el-alert v-else title="未找到文章（注入攻击被成功防御）" type="info" :closable="false"></el-alert>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试（验证防御效果）</el-divider>
                    <el-row :gutter="10">
                        <el-col :span="8">
                            <el-button size="small" style="width: 100%;" @click="quickTestSec('1')">
                                正常查询: ID=1
                            </el-button>
                        </el-col>
                        <el-col :span="8">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTestSec('-1 UNION SELECT 1,2,3,4,5')">
                                尝试注入: UNION SELECT
                            </el-button>
                        </el-col>
                        <el-col :span="8">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTestSec('-1 UNION SELECT 1,username,password,avatar,5 FROM admin')">
                                尝试获取密码（被防御）
                            </el-button>
                        </el-col>
                    </el-row>
                </div>
            </div>
        </el-dialog>

        <!-- MyBatis 漏洞测试对话框 -->
        <el-dialog title="🔴 文章详情查询（MyBatis 漏洞版 - UNION注入）" :visible.sync="vulnDialogVisibleMybatis" width="900px">
            <el-alert
                title="💡 UNION 联合注入完整攻击流程 - MyBatis 版本"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>攻击步骤（依次执行）：</strong><br />
                    <strong>① 测试注入点：</strong><code>1'</code> → 查看是否报错（有错误说明存在注入）<br />
                    <strong>② 判断列数：</strong><code>1 ORDER BY 5</code> → 正常则有5列，<code>1 ORDER BY 6</code> → 报错则只有5列<br />
                    <strong>③ 确定回显位置：</strong><code>-1 UNION SELECT 1,2,3,4,5</code> → 查看哪些数字显示在页面上<br />
                    <strong>④ 获取数据库信息：</strong><code>-1 UNION SELECT 1,database(),user(),version(),5</code><br />
                    <strong>⑤ 获取所有表名：</strong><code>-1 UNION SELECT 1,2,group_concat(table_name),4,5 FROM information_schema.tables WHERE table_schema=database()</code><br />
                    <strong>⑥ 获取admin表列名：</strong><code>-1 UNION SELECT 1,2,group_concat(column_name),4,5 FROM information_schema.columns WHERE table_name='admin'</code><br />
                    <strong>⑦ 获取敏感数据：</strong><code>-1 UNION SELECT 1,username,password,avatar,5 FROM admin</code> → 🎯 获取所有管理员密码！
                </div>
            </el-alert>

            <!-- 文章ID输入 -->
            <div class="query-form">
                <el-form label-width="100px">
                    <el-form-item label="文章ID">
                        <el-input 
                            v-model="vulnFormMybatis.id" 
                            placeholder="请输入文章ID（支持SQL注入测试）"
                            clearable
                            style="width: 600px;">
                            <el-button 
                                slot="append" 
                                type="primary" 
                                @click="queryVulnArticleMybatis"
                                :loading="vulnQueryingMybatis">
                                查询文章
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 查询结果显示 -->
                <div v-if="vulnResultMybatis.show" class="query-result">
                    <!-- SQL语句显示 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content">{{ vulnResultMybatis.sql }}</div>
                    </div>

                    <!-- 查询结果 -->
                    <div v-if="vulnResultMybatis.results && vulnResultMybatis.results.length > 0" class="article-list">
                        <el-divider content-position="left">📄 查询结果</el-divider>
                        <div v-for="(article, index) in vulnResultMybatis.results" :key="index" class="article-item">
                            <div class="article-row">
                                <span class="article-label">ID:</span>
                                <span class="article-value">{{ article.id }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">标题:</span>
                                <span class="article-value">{{ article.title }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">作者:</span>
                                <span class="article-value">{{ article.author }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">内容:</span>
                                <span class="article-value article-content">{{ article.content }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">发布时间:</span>
                                <span class="article-value">{{ article.create_time }}</span>
                            </div>
                            <el-divider v-if="index < vulnResultMybatis.results.length - 1"></el-divider>
                        </div>
                    </div>
                    <el-alert v-else title="未找到文章或查询失败" type="info" :closable="false"></el-alert>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试（完整攻击链）</el-divider>
                    <!-- 第一行：4个按钮 -->
                    <el-row :gutter="10" style="margin-bottom: 10px;">
                        <el-col :span="6">
                            <el-button size="small" style="width: 100%;" @click="quickTestMybatis('1')">
                                ① 正常查询: ID=1
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTestMybatis('1\'')">
                                ② 测试注入点: 1'
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTestMybatis('1 ORDER BY 5')">
                                ③ 判断列数: ORDER BY 5
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTestMybatis('-1 UNION SELECT 1,2,3,4,5')">
                                ④ 确定回显: UNION 1,2,3,4,5
                            </el-button>
                        </el-col>
                    </el-row>
                    <!-- 第二行：4个按钮 -->
                    <el-row :gutter="10">
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTestMybatis('-1 UNION SELECT 1,database(),user(),version(),5')">
                                ⑤ 获取数据库信息
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTestMybatis('-1 UNION SELECT 1,2,group_concat(table_name),4,5 FROM information_schema.tables WHERE table_schema=database()')">
                                ⑥ 获取所有表名
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTestMybatis('-1 UNION SELECT 1,2,group_concat(column_name),4,5 FROM information_schema.columns WHERE table_name=\'admin\'')">
                                ⑦ 获取admin表列名
                            </el-button>
                        </el-col>
                        <el-col :span="6">
                            <el-button size="small" type="danger" style="width: 100%;" @click="quickTestMybatis('-1 UNION SELECT 1,username,password,avatar,5 FROM admin')">
                                ⑧ 🎯 获取管理员密码
                            </el-button>
                        </el-col>
                    </el-row>
                </div>
            </div>
        </el-dialog>

        <!-- MyBatis 安全版本测试对话框 -->
        <el-dialog title="✅ 文章详情查询（MyBatis 安全版 - 预编译防御）" :visible.sync="secDialogVisibleMybatis" width="900px">
            <el-alert
                title=""
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>✅ 防御原理：</strong><br />
                    &nbsp;&nbsp;• MyBatis 的 <code>#{}</code> 底层使用 PreparedStatement<br />
                    &nbsp;&nbsp;• SQL 在编译时就确定了结构，用户输入仅作为参数值<br />
                    &nbsp;&nbsp;• 用户输入的 <code>UNION</code>、<code>SELECT</code> 等关键字会被转义为普通字符串<br />
                    &nbsp;&nbsp;• 查询条件变成 <code>WHERE id = '1 UNION SELECT...'</code>（当作普通字符串查询，找不到结果）<br />
                    &nbsp;&nbsp;• 无论输入什么恶意代码，都无法改变 SQL 逻辑
                </div>
            </el-alert>

            <!-- 文章ID输入 -->
            <div class="query-form">
                <el-form label-width="100px">
                    <el-form-item label="文章ID">
                        <el-input 
                            v-model="secFormMybatis.id" 
                            placeholder="请输入文章ID（尝试注入攻击）"
                            clearable
                            style="width: 600px;">
                            <el-button 
                                slot="append" 
                                type="success" 
                                @click="querySecArticleMybatis"
                                :loading="secQueryingMybatis">
                                查询文章
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 查询结果显示 -->
                <div v-if="secResultMybatis.show" class="query-result">
                    <!-- SQL语句显示 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content">{{ secResultMybatis.sql }}</div>
                    </div>

                    <!-- 查询结果 -->
                    <div v-if="secResultMybatis.results && secResultMybatis.results.length > 0" class="article-list">
                        <el-divider content-position="left">📄 查询结果</el-divider>
                        <div v-for="(article, index) in secResultMybatis.results" :key="index" class="article-item">
                            <div class="article-row">
                                <span class="article-label">ID:</span>
                                <span class="article-value">{{ article.id }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">标题:</span>
                                <span class="article-value">{{ article.title }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">作者:</span>
                                <span class="article-value">{{ article.author }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">内容:</span>
                                <span class="article-value article-content">{{ article.content }}</span>
                            </div>
                            <div class="article-row">
                                <span class="article-label">发布时间:</span>
                                <span class="article-value">{{ article.create_time }}</span>
                            </div>
                        </div>
                    </div>
                    <el-alert v-else title="未找到文章（注入攻击被成功防御）" type="info" :closable="false"></el-alert>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试（验证防御效果）</el-divider>
                    <el-row :gutter="10">
                        <el-col :span="8">
                            <el-button size="small" style="width: 100%;" @click="quickTestSecMybatis('1')">
                                正常查询: ID=1
                            </el-button>
                        </el-col>
                        <el-col :span="8">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTestSecMybatis('-1 UNION SELECT 1,2,3,4,5')">
                                尝试注入: UNION SELECT
                            </el-button>
                        </el-col>
                        <el-col :span="8">
                            <el-button size="small" type="warning" style="width: 100%;" @click="quickTestSecMybatis('-1 UNION SELECT 1,username,password,avatar,5 FROM admin')">
                                尝试获取密码（被防御）
                            </el-button>
                        </el-col>
                    </el-row>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { 
  getArticleVulnJdbc, 
  getArticleSecJdbc,
  getArticleVulnMybatis,
  getArticleSecMybatis
} from '@/api/sqli';

export default {
    data() {
        return {
            activeName: 'first',
            vulnDialogVisible: false,
            secDialogVisible: false,
            vulnDialogVisibleMybatis: false,
            secDialogVisibleMybatis: false,
            vulnForm: {
                id: ''
            },
            secForm: {
                id: ''
            },
            vulnFormMybatis: {
                id: ''
            },
            secFormMybatis: {
                id: ''
            },
            vulnResult: {
                show: false,
                sql: '',
                results: []
            },
            secResult: {
                show: false,
                sql: '',
                results: []
            },
            vulnResultMybatis: {
                show: false,
                sql: '',
                results: []
            },
            secResultMybatis: {
                show: false,
                sql: '',
                results: []
            },
            vulnQuerying: false,
            secQuerying: false,
            vulnQueryingMybatis: false,
            secQueryingMybatis: false
        };
    },
    methods: {
        handleClick(tab, event) {
            // Tab 切换事件
        },
        openVulnDialog() {
            this.vulnDialogVisible = true;
            this.vulnForm.id = '';
            this.vulnResult.show = false;
        },
        openSecDialog() {
            this.secDialogVisible = true;
            this.secForm.id = '';
            this.secResult.show = false;
        },
        // 查询文章（漏洞版）
        async queryVulnArticle() {
            if (!this.vulnForm.id) {
                this.$message.warning('请输入文章ID');
                return;
            }

            this.vulnQuerying = true;
            try {
                const res = await getArticleVulnJdbc({ id: this.vulnForm.id });

                if (res.code === 0) {
                    this.vulnResult = {
                        show: true,
                        sql: res.data.sql,
                        results: res.data.results || []
                    };
                } else {
                    // 理论上不会到这里，因为后端总是返回 success
                    this.vulnResult = {
                        show: true,
                        sql: `SELECT id, title, author, content, create_time FROM articles WHERE id = ${this.vulnForm.id}`,
                        results: []
                    };
                }
            } catch (error) {
                // axios 拦截器已经弹出错误提示了，这里不需要再弹出
                // 只需要确保 loading 状态被重置即可
                console.error('查询失败:', error);
            } finally {
                this.vulnQuerying = false;
            }
        },
        // 查询文章（安全版）
        async querySecArticle() {
            if (!this.secForm.id) {
                this.$message.warning('请输入文章ID');
                return;
            }

            this.secQuerying = true;
            try {
                const res = await getArticleSecJdbc({ id: this.secForm.id });

                if (res.code === 0) {
                    this.secResult = {
                        show: true,
                        sql: res.data.sql,
                        results: res.data.results || []
                    };
                } else {
                    // 理论上不会到这里，因为后端总是返回 success
                    this.secResult = {
                        show: true,
                        sql: `SELECT id, title, author, content, create_time FROM articles WHERE id = ? (参数: ${this.secForm.id})`,
                        results: []
                    };
                }
            } catch (error) {
                // axios 拦截器已经弹出错误提示了，这里不需要再弹出
                // 只需要确保 loading 状态被重置即可
                console.error('查询失败:', error);
            } finally {
                this.secQuerying = false;
            }
        },
        // 快速测试（漏洞版）
        quickTest(id) {
            this.vulnForm.id = id;
            this.queryVulnArticle();
        },
        // 快速测试（安全版）
        quickTestSec(id) {
            this.secForm.id = id;
            this.querySecArticle();
        },
        // MyBatis - 打开漏洞对话框
        openVulnDialogMybatis() {
            this.vulnDialogVisibleMybatis = true;
            this.vulnFormMybatis.id = '';
            this.vulnResultMybatis.show = false;
        },
        // MyBatis - 打开安全对话框
        openSecDialogMybatis() {
            this.secDialogVisibleMybatis = true;
            this.secFormMybatis.id = '';
            this.secResultMybatis.show = false;
        },
        // MyBatis - 查询文章（漏洞版）
        async queryVulnArticleMybatis() {
            if (!this.vulnFormMybatis.id) {
                this.$message.warning('请输入文章ID');
                return;
            }

            this.vulnQueryingMybatis = true;
            try {
                const res = await getArticleVulnMybatis({ id: this.vulnFormMybatis.id });

                if (res.code === 0) {
                    this.vulnResultMybatis = {
                        show: true,
                        sql: res.data.sql,
                        results: res.data.results || []
                    };
                } else {
                    this.vulnResultMybatis = {
                        show: true,
                        sql: `SELECT id, title, author, content, create_time FROM articles WHERE id = ${this.vulnFormMybatis.id}`,
                        results: []
                    };
                }
            } catch (error) {
                console.error('查询失败:', error);
            } finally {
                this.vulnQueryingMybatis = false;
            }
        },
        // MyBatis - 查询文章（安全版）
        async querySecArticleMybatis() {
            if (!this.secFormMybatis.id) {
                this.$message.warning('请输入文章ID');
                return;
            }

            this.secQueryingMybatis = true;
            try {
                const res = await getArticleSecMybatis({ id: this.secFormMybatis.id });

                if (res.code === 0) {
                    this.secResultMybatis = {
                        show: true,
                        sql: res.data.sql,
                        results: res.data.results || []
                    };
                } else {
                    this.secResultMybatis = {
                        show: true,
                        sql: `SELECT id, title, author, content, create_time FROM articles WHERE id = ? (参数: ${this.secFormMybatis.id})`,
                        results: []
                    };
                }
            } catch (error) {
                console.error('查询失败:', error);
            } finally {
                this.secQueryingMybatis = false;
            }
        },
        // MyBatis - 快速测试（漏洞版）
        quickTestMybatis(id) {
            this.vulnFormMybatis.id = id;
            this.queryVulnArticleMybatis();
        },
        // MyBatis - 快速测试（安全版）
        quickTestSecMybatis(id) {
            this.secFormMybatis.id = id;
            this.querySecArticleMybatis();
        }
    }
};
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

/* 对话框样式 */
.query-form {
    padding: 10px;
}

.query-result {
    margin-top: 20px;
}

.sql-display {
    margin-bottom: 15px;
    padding: 15px;
    background-color: #f9f9f9;
    border-left: 4px solid #409EFF;
    border-radius: 4px;
}

.sql-label {
    font-weight: bold;
    color: #409EFF;
    margin-bottom: 8px;
}

.sql-content {
    font-family: 'Courier New', monospace;
    background-color: #fff;
    padding: 10px;
    border-radius: 4px;
    word-break: break-all;
    color: #333;
}

.article-list {
    margin-top: 15px;
}

.article-item {
    padding: 15px;
    background-color: #f9f9f9;
    border-radius: 4px;
    margin-bottom: 10px;
}

.article-row {
    margin-bottom: 10px;
    display: flex;
    align-items: flex-start;
}

.article-row:last-child {
    margin-bottom: 0;
}

.article-label {
    font-weight: bold;
    color: #606266;
    min-width: 80px;
    flex-shrink: 0;
}

.article-value {
    color: #303133;
    flex: 1;
}

.article-content {
    line-height: 1.8;
}

.quick-test {
    margin-top: 20px;
}
</style>
