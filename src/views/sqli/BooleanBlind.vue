<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- 布尔盲注</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>布尔盲注（Boolean-Based Blind SQL Injection）</strong>是一种特殊的 SQL 注入类型。与普通 SQL
                            注入不同，布尔盲注的应用程序<span style="color: red;">不会直接返回数据库数据</span>，而是只返回<span
                                style="color: red;">"真"或"假"</span>两种状态（例如："用户名已存在" / "用户名可用"）。
                            <br /><br />
                            <strong>攻击原理：</strong><br />
                            1. 攻击者构造特殊的 SQL 条件判断语句（如 <code>AND 1=1</code>、<code>AND
                                SUBSTRING(password,1,1)='a'</code>）<br />
                            2. 根据应用程序返回的布尔值（真/假）推断数据库信息<br />
                            3. 通过大量条件测试，逐字符猜测敏感数据（如密码、表名等）<br />
                            <br />
                            <strong>经典场景：</strong>用户注册时检查用户名是否已存在<br />
                            <strong>与时间盲注区别：</strong>布尔盲注根据<span style="color: green;">页面返回内容差异</span>判断（快速），时间盲注根据<span
                                style="color: green;">响应时间</span>判断（慢速）
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            布尔盲注虽然无法直接获取数据，但通过自动化工具（如 sqlmap）可以实现：<br /><br />
                            <strong>1. 数据库信息泄露</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 猜测数据库版本、表名、列名<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 逐字符爆破用户密码、敏感信息<br /><br />
                            <strong>2. 用户身份泄露</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 通过"用户名是否存在"接口枚举系统所有用户名<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 为后续撞库攻击、社会工程学攻击提供目标<br /><br />
                            <strong>3. 数据完整性验证</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 猜测数据库记录总数<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 验证特定数据是否存在<br /><br />
                            <strong>4. 自动化爆破</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 使用工具（sqlmap、自定义脚本）可在数小时内完成爆破<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 示例：爆破 32 位 MD5 密码通常需要 32×16=512 次请求
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【必须】使用预编译语句（PreparedStatement）</strong><br />
                            预编译可以确保 SQL 语句结构在编译时就已确定，用户输入仅作为数据值，无法改变 SQL 逻辑。<br /><br />

                            <strong>【必须】屏蔽详细错误信息</strong><br />
                            禁止将数据库错误、SQL 语句等敏感信息返回给前端，避免攻击者获取数据库结构信息。<br /><br />

                            <strong>【建议】限制查询频率</strong><br />
                            对同一 IP 或用户的查询请求进行频率限制（如 1 秒内最多 5 次），防止自动化爆破工具攻击。<br /><br />

                            <strong>【建议】使用验证码</strong><br />
                            在敏感接口（如用户名检查）添加验证码或滑动验证，增加自动化攻击难度。<br /><br />

                            <strong>【建议】避免明确的布尔响应</strong><br />
                            不要返回"用户名已存在"/"用户名可用"等明确信息，可以统一返回"提交成功，请等待审核"。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://portswigger.net/web-security/sql-injection/blind" target="_blank"
                                style="text-decoration: underline;">《Blind SQL injection》</a> - PortSwigger 官方文档<br />
                            <a href="https://owasp.org/www-community/attacks/Blind_SQL_Injection" target="_blank"
                                style="text-decoration: underline;">《Blind SQL Injection》</a> - OWASP 安全指南<br />
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
 * 布尔盲注 - 漏洞版本
 * 场景：用户注册时检查用户名是否已被占用
 * 漏洞：直接拼接 SQL，允许注入条件判断语句
 */
@GetMapping("/checkUserExistsVuln")
public Result checkUserExistsVuln(String username) {
    // 1. 注册驱动
    Class.forName("com.mysql.cj.jdbc.Driver");
    // 2. 获取连接
    Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
    // 3. ❌ 拼接 SQL（漏洞点）
    String sql = "SELECT COUNT(*) as count FROM admin " + 
                 "WHERE username = '" + username + "'";
    
    log.warn("【布尔盲注漏洞】执行SQL: {}", sql);
    
    // 4. 执行查询
    Statement statement = conn.createStatement();
    ResultSet resultSet = statement.executeQuery(sql);
    
    // 5. 判断用户是否存在
    if (resultSet.next()) {
        int count = resultSet.getInt("count");
        boolean exists = count &gt; 0;
        return exists ? "❌ 用户名已存在" : "✅ 用户名可用";
    }
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
 * 布尔盲注 - 安全版本
 * 防御方法：使用 PreparedStatement 预编译 + 参数绑定
 * 原理：SQL 结构编译时确定，用户输入仅作为数据值
 */
@GetMapping("/checkUserExistsSec")
public Result checkUserExistsSec(String username) {
    // 1. 注册驱动
    Class.forName("com.mysql.cj.jdbc.Driver");
    // 2. 获取连接
    Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
    // 3. ✅ 使用预编译（安全点）
    String sql = "SELECT COUNT(*) as count FROM admin " + 
                 "WHERE username = ?";
    
    log.info("【安全】执行SQL: {}, 参数: {}", sql, username);
    
    // 4. 参数绑定
    PreparedStatement ps = conn.prepareStatement(sql);
    ps.setString(1, username);  // 自动转义特殊字符
    
    // 5. 执行查询
    ResultSet resultSet = ps.executeQuery();
    
    // 6. 判断用户是否存在
    if (resultSet.next()) {
        int count = resultSet.getInt("count");
        boolean exists = count &gt; 0;
        return exists ? "❌ 用户名已存在" : "✅ 用户名可用";
    }
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
 * 布尔盲注 - 漏洞版本（MyBatis）
 * 场景：用户注册时检查用户名是否已被占用
 * 漏洞：使用 ${} 直接拼接 SQL
 */
// Mapper 接口
@Select("SELECT COUNT(*) FROM admin WHERE username = '\${username}'")
int checkUserExistsByDollar(@Param("username") String username);

// Controller
@GetMapping("/checkUserExistsVuln")
public Result checkUserExistsVuln(String username) {
    // ❌ 调用使用 ${} 的 Mapper 方法
    int count = booleanBlindService.checkUserExistsByDollar(username);
    
    boolean exists = count &gt; 0;
    
    log.warn("【布尔盲注漏洞-MyBatis】查询结果: {}", exists);
    
    return exists ? "❌ 用户名已存在" : "✅ 用户名可用";
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
 * 布尔盲注 - 安全版本（MyBatis）
 * 防御方法：使用 MyBatis 的 #{} 进行参数绑定
 * 原理：#{} 底层使用 PreparedStatement 预编译
 */
// Mapper 接口
@Select("SELECT COUNT(*) FROM admin WHERE username = #{username}")
int checkUserExistsBySharp(@Param("username") String username);

// Controller
@GetMapping("/checkUserExistsSec")
public Result checkUserExistsSec(String username) {
    // ✅ 调用使用 #{} 的 Mapper 方法
    int count = booleanBlindService.checkUserExistsBySharp(username);
    
    boolean exists = count &gt; 0;
    
    log.info("【安全-MyBatis】查询结果: {}", exists);
    
    return exists ? "❌ 用户名已存在" : "✅ 用户名可用";
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 漏洞测试对话框 - JDBC版本 -->
        <el-dialog title="🔴 用户注册 - 检查用户名（漏洞版）" :visible.sync="vulnDialogVisible" width="700px">
            <el-alert
                title="💡 布尔盲注攻击演示"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>攻击分析：</strong><br />
                    1. 注入的条件语句成功执行，说明存在 SQL 注入漏洞<br />
                    2. 根据用户名是否已注册，可以判断注入条件的真假<br />
                    3. 攻击者可以通过编写脚本，自动化猜测数据库中的敏感信息<br />
                    <br />
                    <strong>正常测试：</strong>输入 <code>admin</code>，查看是否返回"用户名已存在"<br />
                    <strong>布尔盲注攻击：</strong>利用条件判断逐字符猜测数据<br />
                    &nbsp;&nbsp;• <code>admin' AND SUBSTRING(password,1,1)='1' -- </code> 猜测密码第1位是否为'1'<br />
                    &nbsp;&nbsp;• <code>admin' AND LENGTH(password)>=30 -- </code> 猜测密码长度<br />
                    &nbsp;&nbsp;• <code>admin' AND SUBSTRING(VERSION(),1,1)='8' -- </code> 猜测数据库版本<br />
                </div>
            </el-alert>

            <!-- 模拟注册表单 -->
            <div class="register-form">
                <el-form :model="vulnForm" label-width="100px">
                    <el-form-item label="用户名">
                        <el-input 
                            v-model="vulnForm.username" 
                            placeholder="请输入要注册的用户名"
                            clearable
                            style="width: 400px;">
                            <el-button 
                                slot="append" 
                                type="primary" 
                                @click="checkVulnUsername"
                                :loading="vulnChecking">
                                检查是否已注册
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 检查结果显示 -->
                <div v-if="vulnResult.show" class="check-result">
                    <el-alert
                        :title="vulnResult.message"
                        :type="vulnResult.exists ? 'error' : 'success'"
                        :closable="false"
                        show-icon>
                    </el-alert>
                    
                    <!-- 执行的 SQL 语句 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content" v-html="formatSql(vulnResult.sql)"></div>
                    </div>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试</el-divider>
                    <el-button size="small" @click="quickTest('admin')">
                        正常：admin
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTest('admin\' AND SUBSTRING(password,1,1)=\'1\' -- ')">
                        攻击：猜测密码第1位='1'
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTest('admin\' AND LENGTH(password)>=30 -- ')">
                        攻击：猜测密码长度>=30
                    </el-button>
                </div>
            </div>
        </el-dialog>

        <!-- 安全版本测试对话框 -->
        <el-dialog title="✅ 用户注册 - 检查用户名（安全版）" :visible.sync="secDialogVisible" width="700px">
            <el-alert
                title=""
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>✅ 防御原理：</strong><br />
                    &nbsp;&nbsp;• PreparedStatement 在编译时就确定了 SQL 结构<br />
                    &nbsp;&nbsp;• 用户输入通过参数绑定传递，仅作为数据值<br />
                    &nbsp;&nbsp;• 单引号、注释符等特殊字符被转义为普通字符
                </div>
            </el-alert>

            <!-- 模拟注册表单 -->
            <div class="register-form">
                <el-form :model="secForm" label-width="100px">
                    <el-form-item label="用户名">
                        <el-input 
                            v-model="secForm.username" 
                            placeholder="请输入要注册的用户名"
                            clearable
                            style="width: 400px;">
                            <el-button 
                                slot="append" 
                                type="success" 
                                @click="checkSecUsername"
                                :loading="secChecking">
                                检查是否已注册
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 检查结果显示 -->
                <div v-if="secResult.show" class="check-result">
                    <el-alert
                        :title="secResult.message"
                        :type="secResult.exists ? 'error' : 'success'"
                        :closable="false"
                        show-icon>
                    </el-alert>
                    
                    <!-- 执行的 SQL 语句 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content">{{ secResult.sql }}</div>
                    </div>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试</el-divider>
                    <el-button size="small" @click="quickTestSec('admin')">
                        正常：admin
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTestSec('admin\' AND SUBSTRING(password,1,1)=\'1\' -- ')">
                        攻击：猜测密码第1位='1'
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTestSec('admin\' AND LENGTH(password)>=30 -- ')">
                        攻击：猜测密码长度>=30
                    </el-button>
                </div>
            </div>
        </el-dialog>

        <!-- MyBatis 漏洞测试对话框 -->
        <el-dialog title="🔴 用户注册 - 检查用户名（MyBatis 漏洞版）" :visible.sync="vulnDialogVisibleMybatis" width="700px">
            <el-alert
                title="💡 布尔盲注攻击演示 - MyBatis 版本"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>攻击分析：</strong><br />
                    1. MyBatis 使用 <code>${'$'}{}</code> 进行字符串替换，直接拼接到 SQL 中<br />
                    2. 根据用户名是否已注册，可以判断注入条件的真假<br />
                    3. 攻击者可以通过编写脚本，自动化猜测数据库中的敏感信息<br />
                    <br />
                    <strong>正常测试：</strong>输入 <code>admin</code>，查看是否返回"用户名已存在"<br />
                    <strong>布尔盲注攻击：</strong>利用条件判断逐字符猜测数据<br />
                    &nbsp;&nbsp;• <code>admin' AND SUBSTRING(password,1,1)='1' -- </code> 猜测密码第1位是否为'1'<br />
                    &nbsp;&nbsp;• <code>admin' AND LENGTH(password)>=30 -- </code> 猜测密码长度<br />
                    &nbsp;&nbsp;• <code>admin' AND SUBSTRING(VERSION(),1,1)='8' -- </code> 猜测数据库版本<br />
                </div>
            </el-alert>

            <!-- 模拟注册表单 -->
            <div class="register-form">
                <el-form :model="vulnFormMybatis" label-width="100px">
                    <el-form-item label="用户名">
                        <el-input 
                            v-model="vulnFormMybatis.username" 
                            placeholder="请输入要注册的用户名"
                            clearable
                            style="width: 400px;">
                            <el-button 
                                slot="append" 
                                type="primary" 
                                @click="checkVulnUsernameMybatis"
                                :loading="vulnCheckingMybatis">
                                检查是否已注册
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 检查结果显示 -->
                <div v-if="vulnResultMybatis.show" class="check-result">
                    <el-alert
                        :title="vulnResultMybatis.message"
                        :type="vulnResultMybatis.exists ? 'error' : 'success'"
                        :closable="false"
                        show-icon>
                    </el-alert>
                    
                    <!-- 执行的 SQL 语句 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content" v-html="formatSql(vulnResultMybatis.sql)"></div>
                    </div>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试</el-divider>
                    <el-button size="small" @click="quickTestMybatis('admin')">
                        正常：admin
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTestMybatis('admin\' AND SUBSTRING(password,1,1)=\'1\' -- ')">
                        攻击：猜测密码第1位='1'
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTestMybatis('admin\' AND LENGTH(password)>=30 -- ')">
                        攻击：猜测密码长度>=30
                    </el-button>
                </div>
            </div>
        </el-dialog>

        <!-- MyBatis 安全版本测试对话框 -->
        <el-dialog title="✅ 用户注册 - 检查用户名（MyBatis 安全版）" :visible.sync="secDialogVisibleMybatis" width="700px">
            <el-alert
                title=""
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>✅ 防御原理：</strong><br />
                    &nbsp;&nbsp;• MyBatis 的 <code>#{}</code> 底层使用 PreparedStatement<br />
                    &nbsp;&nbsp;• SQL 在编译时就确定了结构，用户输入仅作为参数值<br />
                    &nbsp;&nbsp;• 单引号、注释符等特殊字符被自动转义
                </div>
            </el-alert>

            <!-- 模拟注册表单 -->
            <div class="register-form">
                <el-form :model="secFormMybatis" label-width="100px">
                    <el-form-item label="用户名">
                        <el-input 
                            v-model="secFormMybatis.username" 
                            placeholder="请输入要注册的用户名"
                            clearable
                            style="width: 400px;">
                            <el-button 
                                slot="append" 
                                type="success" 
                                @click="checkSecUsernameMybatis"
                                :loading="secCheckingMybatis">
                                检查是否已注册
                            </el-button>
                        </el-input>
                    </el-form-item>
                </el-form>

                <!-- 检查结果显示 -->
                <div v-if="secResultMybatis.show" class="check-result">
                    <el-alert
                        :title="secResultMybatis.message"
                        :type="secResultMybatis.exists ? 'error' : 'success'"
                        :closable="false"
                        show-icon>
                    </el-alert>
                    
                    <!-- 执行的 SQL 语句 -->
                    <div class="sql-display">
                        <div class="sql-label">📝 执行的 SQL 语句：</div>
                        <div class="sql-content">{{ secResultMybatis.sql }}</div>
                    </div>
                </div>

                <!-- 快速测试按钮 -->
                <div class="quick-test">
                    <el-divider content-position="left">⚡ 快速测试</el-divider>
                    <el-button size="small" @click="quickTestSecMybatis('admin')">
                        正常：admin
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTestSecMybatis('admin\' AND SUBSTRING(password,1,1)=\'1\' -- ')">
                        攻击：猜测密码第1位='1'
                    </el-button>
                    <el-button size="small" type="warning" @click="quickTestSecMybatis('admin\' AND LENGTH(password)>=30 -- ')">
                        攻击：猜测密码长度>=30
                    </el-button>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { 
  checkUserExistsVulnJdbc, 
  checkUserExistsSecJdbc,
  checkUserExistsVulnMybatis,
  checkUserExistsSecMybatis
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
                username: ''
            },
            secForm: {
                username: ''
            },
            vulnFormMybatis: {
                username: ''
            },
            secFormMybatis: {
                username: ''
            },
            vulnResult: {
                show: false,
                exists: false,
                message: '',
                sql: ''
            },
            secResult: {
                show: false,
                exists: false,
                message: '',
                sql: ''
            },
            vulnResultMybatis: {
                show: false,
                exists: false,
                message: '',
                sql: ''
            },
            secResultMybatis: {
                show: false,
                exists: false,
                message: '',
                sql: ''
            },
            vulnChecking: false,
            secChecking: false,
            vulnCheckingMybatis: false,
            secCheckingMybatis: false
        };
    },
    methods: {
        handleClick(tab, event) {
            // Tab 切换事件
        },
        openVulnDialog() {
            this.vulnDialogVisible = true;
            this.vulnForm.username = '';
            this.vulnResult.show = false;
        },
        openSecDialog() {
            this.secDialogVisible = true;
            this.secForm.username = '';
            this.secResult.show = false;
        },
        // 检查用户名（漏洞版）
        async checkVulnUsername() {
            if (!this.vulnForm.username) {
                this.$message.warning('请输入用户名');
                return;
            }

            this.vulnChecking = true;
            try {
                const res = await checkUserExistsVulnJdbc({ username: this.vulnForm.username });

                if (res.code === 0) {
                    this.vulnResult = {
                        show: true,
                        exists: res.data.exists,
                        message: res.data.message,
                        sql: res.data.sql
                    };
                } else {
                    this.$message.error(res.msg || '查询失败');
                }
            } catch (error) {
                this.$message.error('请求失败：' + error.message);
            } finally {
                this.vulnChecking = false;
            }
        },
        // 检查用户名（安全版）
        async checkSecUsername() {
            if (!this.secForm.username) {
                this.$message.warning('请输入用户名');
                return;
            }

            this.secChecking = true;
            try {
                const res = await checkUserExistsSecJdbc({ username: this.secForm.username });

                if (res.code === 0) {
                    this.secResult = {
                        show: true,
                        exists: res.data.exists,
                        message: res.data.message,
                        sql: res.data.sql
                    };
                } else {
                    this.$message.error(res.msg || '查询失败');
                }
            } catch (error) {
                this.$message.error('请求失败：' + error.message);
            } finally {
                this.secChecking = false;
            }
        },
        // 快速测试（漏洞版）
        quickTest(username) {
            this.vulnForm.username = username;
            this.checkVulnUsername();
        },
        // 快速测试（安全版）
        quickTestSec(username) {
            this.secForm.username = username;
            this.checkSecUsername();
        },
        // 格式化 SQL 显示（高亮参数）
        formatSql(sql) {
            if (!sql) return '';
            // 高亮显示用户输入的部分
            const match = sql.match(/WHERE username = '(.+?)'/);
            if (match && match[1]) {
                const userInput = match[1];
                return sql.replace(
                    userInput,
                    '<span class="sql-highlight">' + userInput + '</span>'
                );
            }
            return sql;
        },
        // MyBatis - 打开漏洞对话框
        openVulnDialogMybatis() {
            this.vulnDialogVisibleMybatis = true;
            this.vulnFormMybatis.username = '';
            this.vulnResultMybatis.show = false;
        },
        // MyBatis - 打开安全对话框
        openSecDialogMybatis() {
            this.secDialogVisibleMybatis = true;
            this.secFormMybatis.username = '';
            this.secResultMybatis.show = false;
        },
        // MyBatis - 检查用户名（漏洞版）
        async checkVulnUsernameMybatis() {
            if (!this.vulnFormMybatis.username) {
                this.$message.warning('请输入用户名');
                return;
            }

            this.vulnCheckingMybatis = true;
            try {
                const res = await checkUserExistsVulnMybatis({ username: this.vulnFormMybatis.username });

                if (res.code === 0) {
                    this.vulnResultMybatis = {
                        show: true,
                        exists: res.data.exists,
                        message: res.data.message,
                        sql: res.data.sql
                    };
                } else {
                    this.$message.error(res.msg || '查询失败');
                }
            } catch (error) {
                this.$message.error('请求失败：' + error.message);
            } finally {
                this.vulnCheckingMybatis = false;
            }
        },
        // MyBatis - 检查用户名（安全版）
        async checkSecUsernameMybatis() {
            if (!this.secFormMybatis.username) {
                this.$message.warning('请输入用户名');
                return;
            }

            this.secCheckingMybatis = true;
            try {
                const res = await checkUserExistsSecMybatis({ username: this.secFormMybatis.username });

                if (res.code === 0) {
                    this.secResultMybatis = {
                        show: true,
                        exists: res.data.exists,
                        message: res.data.message,
                        sql: res.data.sql
                    };
                } else {
                    this.$message.error(res.msg || '查询失败');
                }
            } catch (error) {
                this.$message.error('请求失败：' + error.message);
            } finally {
                this.secCheckingMybatis = false;
            }
        },
        // MyBatis - 快速测试（漏洞版）
        quickTestMybatis(username) {
            this.vulnFormMybatis.username = username;
            this.checkVulnUsernameMybatis();
        },
        // MyBatis - 快速测试（安全版）
        quickTestSecMybatis(username) {
            this.secFormMybatis.username = username;
            this.checkSecUsernameMybatis();
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
.register-form {
    padding: 10px;
}

.check-result {
    margin-top: 20px;
}

.sql-display {
    margin-top: 15px;
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

.sql-highlight {
    color: #e74c3c;
    font-weight: bold;
    background-color: #ffe6e6;
    padding: 2px 4px;
    border-radius: 3px;
}

.attack-demo {
    margin-top: 20px;
    padding: 15px;
    background-color: #fff3e0;
    border-left: 4px solid #ff9800;
    border-radius: 4px;
}

.attack-explanation {
    line-height: 1.8;
    color: #666;
}

.defense-demo {
    margin-top: 20px;
    padding: 15px;
    background-color: #e8f5e9;
    border-left: 4px solid #4caf50;
    border-radius: 4px;
}

.defense-explanation {
    line-height: 1.8;
    color: #666;
}

.quick-test {
    margin-top: 20px;
}

.quick-test .el-button {
    margin-right: 10px;
    margin-bottom: 10px;
}
</style>
