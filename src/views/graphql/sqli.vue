<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">GraphQL -- SQL注入漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>GraphQL SQL 注入</strong>是指通过 GraphQL 查询参数将恶意 SQL 语句注入到后端数据库查询中，原理与传统 SQL 注入完全一致，只是<span style="color: red;">攻击入口由 REST 接口换成了 GraphQL 查询</span>。
                            <br /><br />
                            <strong>很多人对 GraphQL 有误解：</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• GraphQL 有类型校验，参数类型是 <code>String!</code>，传入的只能是字符串<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 但类型校验只保证"是字符串"，<strong>不能阻止字符串中包含 SQL 注入 payload</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 危险在于后端 Resolver 如何处理这个字符串——若拼接 SQL，注入照样成功<br /><br />
                            <strong>本演示场景：</strong><br />
                            系统提供按用户名搜索的 GraphQL 接口 <code>searchUsers(keyword)</code>，漏洞版后端使用 MyBatis 的 <code>${'$'}{keyword}</code> 直接拼接 SQL，
                            攻击者传入 <code>' OR 1=1 -- </code> 即可绕过搜索条件，获取所有用户的薪资、社保号等敏感数据。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            GraphQL SQL 注入的危害与传统 SQL 注入相同，但更具隐蔽性：<br /><br />
                            <strong>1. 数据泄露</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 绕过搜索条件，获取全部用户的敏感数据（薪资、社保号）<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 结合 Introspection 泄露的字段名，精准提取目标数据<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• <code>' OR 1=1 -- </code> 让 WHERE 条件永远为真，返回所有记录<br /><br />
                            <strong>2. 隐蔽性更强</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 传统 WAF 规则针对 REST 参数，可能忽略 GraphQL 请求体中的注入<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• GraphQL 请求统一发往单一端点（<code>/api/graphql</code>），不易区分正常查询和攻击<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 安全人员容易误认为 GraphQL 类型系统已提供足够的防护<br /><br />
                            <strong>3. 真实案例</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 多个使用 GraphQL 的企业 API 存在注入漏洞，通过 keyword 参数即可拖取数据库
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【根本原因】后端 SQL 拼接，而非参数化</strong><br />
                            GraphQL 的类型系统只负责校验参数类型，不负责 SQL 安全，防护必须在后端 SQL 层实现。<br /><br />
                            <strong>【修复方案】MyBatis 使用 #{} 参数化查询（推荐）</strong><br />
                            <pre style="background-color: #f0f9ff; padding: 8px; border-radius: 4px; font-size: 12px; margin: 8px 0;">// ❌ 漏洞：${keyword} 直接拼接，可注入
"WHERE a.username LIKE '%${'{'}keyword{'}'}%'"

// ✅ 安全：#{keyword} 参数化，SQL 与数据分离
"WHERE a.username LIKE CONCAT('%', #{'{'}keyword{'}'}, '%')"</pre>
                            <strong>【原理】参数化查询为何安全？</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• <code>#{'{'}{'}'}}</code> 会将参数作为预编译占位符传递，数据库驱动自动转义特殊字符<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 注入 payload 中的单引号、<code>--</code> 等会被转义为普通字符，无法改变 SQL 结构<br /><br />
                            <strong>【建议】GraphQL 层额外防护</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 对输入参数进行长度限制和格式校验<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 避免在 GraphQL 参数中直接拼接到 SQL，使用 ORM 或参数化方式
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html" target="_blank"
                                style="text-decoration: underline;">《OWASP GraphQL Cheat Sheet》</a> - GraphQL 安全速查表<br />
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank"
                                style="text-decoration: underline;">《OWASP SQL Injection Prevention》</a> - SQL 注入防御速查表<br />
                            <a href="https://portswigger.net/web-security/sql-injection" target="_blank"
                                style="text-decoration: underline;">《PortSwigger: SQL Injection》</a> - SQL 注入详解<br />
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
                            漏洞代码 - ${'{'}keyword{'}'} 直接拼接 SQL
                            <div>
                                <el-button type="danger" round size="mini" @click="vulnDialogVisible = true">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * schema.graphqls
 */
# SQL注入-漏洞版：keyword 参数直接拼接到后端 SQL
searchUsers(keyword: String!): [User!]!

/**
 * GraphQLEmployeeMapper.java
 */
// ❌ 漏洞：${keyword} 直接拼接，存在 SQL 注入风险
@Select("SELECT a.id, a.username, a.role, " +
        "e.email, e.salary, e.ssn, e.internal_notes " +
        "FROM Admin a JOIN graphql_employee e ON a.id = e.id " +
        "WHERE a.username LIKE '%${keyword}%'")
List&lt;GraphQLUser&gt; searchByKeyword(@Param("keyword") String keyword);

/**
 * 攻击示例：
 */
query {
    searchUsers(keyword: "' OR 1=1 -- ") {
        username
        salary      // ⚠️ 泄露所有用户薪资
        ssn         // ⚠️ 泄露所有用户社保号
        internalNotes
    }
}
// 实际执行的 SQL：
// WHERE a.username LIKE '%' OR 1=1 -- %'
// OR 1=1 使条件永远为真，返回全表数据</code></pre>
                    </div>
                </el-col>

                <!-- 安全代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - #{'{'}{keyword}{'}'} 参数化查询
                            <div>
                                <el-button type="success" round size="mini" @click="secDialogVisible = true">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * schema.graphqls
 */
# SQL注入-安全版：同样的参数，但后端使用参数化查询
secureSearchUsers(keyword: String!): [User!]!

/**
 * GraphQLEmployeeMapper.java
 */
// ✅ 安全：#{keyword} 参数化，数据库驱动自动转义特殊字符
@Select("SELECT a.id, a.username, a.role, " +
        "e.email, e.salary, e.ssn, e.internal_notes " +
        "FROM Admin a JOIN graphql_employee e ON a.id = e.id " +
        "WHERE a.username LIKE CONCAT('%', #{keyword}, '%')")
List&lt;GraphQLUser&gt; secureSearchByKeyword(@Param("keyword") String keyword);

/**
 * 相同的注入 payload，安全版返回空结果：
 */
query SearchUsers($keyword: String!) {
    secureSearchUsers(keyword: $keyword) {
        username salary ssn
    }
}
// variables: { "keyword": "' OR 1=1 -- " }
// 实际执行：WHERE a.username LIKE "%' OR 1=1 -- %"
// 单引号被转义，OR 1=1 作为普通字符串匹配，返回 []</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 漏洞测试对话框 -->
        <el-dialog title="💥 GraphQL SQL注入漏洞演示" :visible.sync="vulnDialogVisible" width="800px" @close="onVulnDialogClose">
            <el-alert
                title="💡 攻击流程"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    漏洞版接口 <code>searchUsers(keyword)</code> 后端使用 <code>${'$'}{keyword}</code> 直接拼接 SQL。<br />
                    正常输入用户名关键词可搜索用户，但注入 <code>' OR 1=1 -- </code> 可绕过条件返回所有用户数据。
                </div>
            </el-alert>

            <el-form inline style="margin-bottom: 10px;">
                <el-form-item label="搜索关键词">
                    <el-input v-model="vulnKeyword" placeholder="输入用户名或注入 payload" style="width: 300px;" />
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" :loading="vulnLoading" @click="doVulnSearch">搜索</el-button>
                </el-form-item>
            </el-form>

            <div style="margin-bottom: 10px;">
                <span style="font-size: 12px; color: #909399;">快速填入注入 payload：</span>
                <el-button size="mini" type="warning" plain @click="vulnKeyword = `' OR 1=1 -- `">
                    ' OR 1=1 -- （获取全部数据）
                </el-button>
                <el-button size="mini" plain @click="vulnKeyword = 'admin'">
                    admin（正常搜索）
                </el-button>
            </div>

            <div v-if="vulnResult !== null">
                <el-alert
                    v-if="vulnResult.length > 1"
                    type="error"
                    :closable="false"
                    style="margin-bottom: 12px;">
                    <strong>⚠️ SQL 注入成功！</strong>
                    绕过搜索条件，返回了 <strong>{{ vulnResult.length }}</strong> 条记录，敏感数据全部泄露！
                </el-alert>
                <el-alert
                    v-else-if="vulnResult.length === 0"
                    type="info"
                    title="未搜索到匹配用户"
                    :closable="false"
                    style="margin-bottom: 12px;">
                </el-alert>
                <el-alert
                    v-else
                    type="success"
                    title="正常搜索，仅返回匹配用户"
                    :closable="false"
                    style="margin-bottom: 12px;">
                </el-alert>

                <table v-if="vulnResult.length" class="user-info-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>用户名</th>
                            <th>邮箱</th>
                            <th>角色</th>
                            <th class="sensitive-col">💰 薪资</th>
                            <th class="sensitive-col">🔒 社保号</th>
                            <th class="sensitive-col">📝 内部备注</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="user in vulnResult" :key="user.id">
                            <td>{{ user.id }}</td>
                            <td>{{ user.username }}</td>
                            <td>{{ user.email }}</td>
                            <td>
                                <el-tag :type="user.role === 'admin' ? 'danger' : 'info'" size="small">{{ user.role }}</el-tag>
                            </td>
                            <td class="sensitive">${{ user.salary }}</td>
                            <td class="sensitive">{{ user.ssn }}</td>
                            <td class="sensitive">{{ user.internalNotes }}</td>
                        </tr>
                    </tbody>
                </table>

                <el-alert
                    v-if="vulnErrors.length"
                    type="error"
                    title="接口返回错误"
                    :closable="false"
                    style="margin-top: 10px;">
                    <ul style="margin: 6px 0; padding-left: 20px; font-size: 13px;">
                        <li v-for="(err, idx) in vulnErrors" :key="idx">{{ err.message }}</li>
                    </ul>
                </el-alert>
            </div>
        </el-dialog>

        <!-- 安全演示对话框 -->
        <el-dialog title="✅ GraphQL SQL注入安全演示" :visible.sync="secDialogVisible" width="800px" @close="onSecDialogClose">
            <el-alert
                title="🛡️ 防御原理"
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 1.8; font-size: 13px;">
                    安全版 <code>secureSearchUsers(keyword)</code> 后端使用 <code>#{'#'}{keyword}</code> 参数化查询。<br />
                    数据库驱动会将 keyword 作为纯数据处理，自动转义其中的特殊字符（单引号、注释符等），<strong>无论传入什么 payload 都只会作为字符串匹配</strong>。
                </div>
            </el-alert>

            <el-form inline style="margin-bottom: 10px;">
                <el-form-item label="搜索关键词">
                    <el-input v-model="secKeyword" placeholder="输入用户名或注入 payload" style="width: 300px;" />
                </el-form-item>
                <el-form-item>
                    <el-button type="success" :loading="secLoading" @click="doSecureSearch">搜索（注入无效）</el-button>
                </el-form-item>
            </el-form>

            <div style="margin-bottom: 10px;">
                <span style="font-size: 12px; color: #909399;">快速填入注入 payload：</span>
                <el-button size="mini" type="warning" plain @click="secKeyword = `' OR 1=1 -- `">
                    ' OR 1=1 -- （注入无效）
                </el-button>
                <el-button size="mini" plain @click="secKeyword = 'admin'">
                    admin（正常搜索）
                </el-button>
            </div>

            <div v-if="secResult !== null">
                <el-alert
                    v-if="secResult.length === 0 && secKeyword.includes('OR')"
                    type="success"
                    :closable="false"
                    style="margin-bottom: 12px;">
                    <strong>🚫 注入被防御！</strong>
                    payload 被当作普通字符串匹配，数据库中不存在包含 <code>' OR 1=1 -- </code> 的用户名，返回空结果。
                </el-alert>
                <el-alert
                    v-else-if="secResult.length === 0"
                    type="info"
                    title="未搜索到匹配用户"
                    :closable="false"
                    style="margin-bottom: 12px;">
                </el-alert>
                <el-alert
                    v-else
                    type="success"
                    title="正常搜索，仅返回匹配用户"
                    :closable="false"
                    style="margin-bottom: 12px;">
                </el-alert>

                <table v-if="secResult.length" class="user-info-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>用户名</th>
                            <th>邮箱</th>
                            <th>角色</th>
                            <th>薪资</th>
                            <th>社保号</th>
                            <th>内部备注</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="user in secResult" :key="user.id">
                            <td>{{ user.id }}</td>
                            <td>{{ user.username }}</td>
                            <td>{{ user.email }}</td>
                            <td>
                                <el-tag :type="user.role === 'admin' ? 'danger' : 'info'" size="small">{{ user.role }}</el-tag>
                            </td>
                            <td>${{ user.salary }}</td>
                            <td>{{ user.ssn }}</td>
                            <td>{{ user.internalNotes }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { searchUsers, secureSearchUsers } from '@/api/graphql'

export default {
    name: 'GraphQLSqli',
    data() {
        return {
            activeName: 'first',

            vulnDialogVisible: false,
            vulnKeyword: '',
            vulnLoading: false,
            vulnResult: null,
            vulnErrors: [],

            secDialogVisible: false,
            secKeyword: '',
            secLoading: false,
            secResult: null
        }
    },
    methods: {
        handleClick() {},

        async doVulnSearch() {
            if (!this.vulnKeyword.trim()) {
                this.$message.warning('请输入搜索关键词')
                return
            }
            this.vulnLoading = true
            this.vulnResult = null
            this.vulnErrors = []
            try {
                const res = await searchUsers(this.vulnKeyword)
                this.vulnResult = res.data?.searchUsers || []
                this.vulnErrors = res.errors || []
                if (this.vulnResult.length > 1) {
                    this.$message({ type: 'error', message: '⚠️ SQL 注入成功！获取到所有用户数据', duration: 3000 })
                }
            } catch (error) {
                this.$message.error('请求失败：' + (error.message || '未知错误'))
            } finally {
                this.vulnLoading = false
            }
        },

        async doSecureSearch() {
            if (!this.secKeyword.trim()) {
                this.$message.warning('请输入搜索关键词')
                return
            }
            this.secLoading = true
            this.secResult = null
            try {
                const res = await secureSearchUsers(this.secKeyword)
                this.secResult = res.data?.secureSearchUsers || []
            } catch (error) {
                this.$message.error('请求失败：' + (error.message || '未知错误'))
            } finally {
                this.secLoading = false
            }
        },

        onVulnDialogClose() {
            this.vulnResult = null
            this.vulnErrors = []
            this.vulnKeyword = ''
        },

        onSecDialogClose() {
            this.secResult = null
            this.secKeyword = ''
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

.user-info-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}

.user-info-table th {
    background-color: #f5f7fa;
    color: #606266;
    font-weight: bold;
    padding: 10px 12px;
    border-bottom: 2px solid #ebeef5;
    text-align: left;
    white-space: nowrap;
}

.user-info-table th.sensitive-col {
    color: #f56c6c;
}

.user-info-table tr {
    border-bottom: 1px solid #ebeef5;
}

.user-info-table tr:last-child {
    border-bottom: none;
}

.user-info-table td {
    padding: 10px 12px;
    vertical-align: middle;
    color: #303133;
}

.user-info-table td.sensitive {
    color: #f56c6c;
    font-weight: bold;
}
</style>
