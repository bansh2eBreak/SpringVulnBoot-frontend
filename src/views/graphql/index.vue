<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">GraphQL -- 字段建议泄露漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>GraphQL 字段建议泄露（Introspection Leak）</strong>是 GraphQL API 中的一个<span style="color: red;">信息泄露漏洞</span>。
                            GraphQL 的 Introspection 功能允许客户端查询 API 的完整 Schema 结构，虽然方便开发，但在生产环境如果不禁用，会<span style="color: red;">暴露敏感字段信息</span>。
                            <br /><br />
                            <strong>什么是 GraphQL？</strong><br />
                            GraphQL 是一种 API 查询语言，允许客户端精确指定需要什么数据。与 REST API 不同，GraphQL 只需<strong>一次请求</strong>即可获取多个资源的数据。
                            <br /><br />
                            <strong>什么是 Introspection？</strong><br />
                            Introspection（自省）是 GraphQL 的内置功能，通过特殊查询（<code>__schema</code>、<code>__type</code>）可以获取：<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 所有类型（Type）的定义<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 所有字段（Field）的名称和类型<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 所有查询（Query）和变更（Mutation）的定义<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 参数、返回值等完整信息
                            <br /><br />
                            <strong>攻击原理：</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 攻击者发送 Introspection 查询到 GraphQL 端点<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 获取完整的 Schema 结构<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 发现敏感字段名（如 <code>salary</code>、<code>ssn</code>、<code>password</code>）<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 为后续越权查询、数据泄露攻击提供目标
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            GraphQL Introspection 泄露看似只是信息泄露，但实际危害严重：<br /><br />
                            <strong>1. 暴露敏感字段结构</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 泄露薪资（<code>salary</code>）、社保号（<code>ssn</code>）等敏感字段名<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 攻击者知道有哪些敏感数据可以查询<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 为越权查询提供精确目标<br /><br />
                            <strong>2. 泄露 API 内部结构</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 暴露数据模型和业务逻辑<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 泄露表关系、字段命名规范<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 降低后续攻击难度<br /><br />
                            <strong>3. 辅助其他攻击</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 为 SQL 注入攻击提供字段名信息<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 为越权攻击提供敏感字段目标<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 为爬虫和自动化攻击提供 API 地图<br /><br />
                            <strong>4. 真实案例</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 某社交平台：通过 Introspection 发现 <code>privatePhotos</code> 字段，绕过权限查询私密照片<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 某金融 API：暴露 <code>accountBalance</code>、<code>creditScore</code> 等字段，攻击者批量查询用户财务数据
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【必须】生产环境禁用 Introspection</strong><br />
                            在 <code>application.yml</code> 中禁用 Schema 自省功能：<br />
                            <code>spring.graphql.schema.introspection.enabled=false</code>
                            <br /><br />
                            <strong>【必须】字段级权限控制</strong><br />
                            使用 <code>@PreAuthorize</code> 注解对敏感字段进行权限控制，确保只有授权用户可以访问。<br /><br />
                            <strong>【建议】查询深度和复杂度限制</strong><br />
                            防止深度嵌套查询和批量查询 DoS 攻击，限制查询深度（如最多5层）和复杂度。<br /><br />
                            <strong>【建议】查询白名单</strong><br />
                            对于高安全性要求的场景，可以使用查询白名单机制，只允许预定义的查询模式。<br /><br />
                            <strong>【建议】审计和监控</strong><br />
                            记录所有 GraphQL 查询日志，特别关注 Introspection 查询和敏感字段访问。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://graphql.org/learn/" target="_blank"
                                style="text-decoration: underline;">《GraphQL 官方文档》</a> - GraphQL 学习指南<br />
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html" target="_blank"
                                style="text-decoration: underline;">《OWASP GraphQL Cheat Sheet》</a> - GraphQL 安全速查表<br />
                            <a href="https://spring.io/projects/spring-graphql" target="_blank"
                                style="text-decoration: underline;">《Spring for GraphQL》</a> - Spring GraphQL 官方文档<br />
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>

        <!-- 代码演示区域 -->
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <!-- 漏洞配置 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - 开启 Introspection
                            <div>
                                <el-button type="danger" round size="mini" @click="vulnDialogVisible = true">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * application.yml
 */
spring:
  graphql:
    path: /api/graphql
    schema:
      introspection:
        enabled: true   // ❌ 漏洞：开启 Introspection，攻击者可查询完整 Schema

/**
 * schema.graphqls
 */
type Query {
    user(id: ID!): User          // 漏洞版查询入口
    users(limit: Int): [User!]!
}

type User {
    id: ID!
    username: String!
    email: String!
    role: String!
    salary: Float         // ⚠️ 敏感字段，无权限保护
    ssn: String           // ⚠️ 敏感字段，无权限保护
    internalNotes: String // ⚠️ 敏感字段，无权限保护
}

/**
 * GraphQLEmployeeMapper.java
 */
// 数据来源：JOIN Admin 表（username/role）+ graphql_employee 表（敏感字段）
@Select("SELECT a.id, a.username, a.role, e.email, " +
        "e.salary, e.ssn, e.internal_notes AS internalNotes " +
        "FROM Admin a JOIN graphql_employee e ON a.id = e.id " +
        "WHERE a.id = #{id}")
GraphQLUser findById(@Param("id") Long id);

/**
 * UserQueryController.java
 */
// ❌ 漏洞：敏感字段 Resolver 无任何权限校验，任何登录用户均可获取
@SchemaMapping(typeName = "User", field = "salary")
public Double userSalary(GraphQLUser user) {
    return user.getSalary();
}

@SchemaMapping(typeName = "User", field = "ssn")
public String userSsn(GraphQLUser user) {
    return user.getSsn();
}

@SchemaMapping(typeName = "User", field = "internalNotes")
public String userInternalNotes(GraphQLUser user) {
    return user.getInternalNotes();
}</code></pre>
                    </div>
                </el-col>

                <!-- 安全配置 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - 敏感字段权限控制
                            <div>
                                <el-button type="success" round size="mini" @click="secDialogVisible = true">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * SecurityConfig.java
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity // ✅ 开启方法级安全，使 @PreAuthorize 生效
public class SecurityConfig { ... }

/**
 * schema.graphqls
 */
type Query {
    secureUser(id: ID!): SecureUser  // ✅ 安全版查询入口
}

// ✅ 独立的安全类型，敏感字段 Resolver 单独鉴权
type SecureUser {
    id: ID!
    username: String!
    email: String!
    role: String!
    salary: Float         // 受字段级权限保护
    ssn: String           // 受字段级权限保护
    internalNotes: String // 受字段级权限保护
}

/**
 * GraphQLEmployeeMapper.java
 */
// ✅ 数据同样来自数据库，与漏洞版使用相同数据源
// 安全性由 Resolver 层的 @PreAuthorize 控制，而非数据层
@Select("SELECT a.id, a.username, a.role, e.email, " +
        "e.salary, e.ssn, e.internal_notes AS internalNotes " +
        "FROM Admin a JOIN graphql_employee e ON a.id = e.id " +
        "WHERE a.id = #{id}")
GraphQLUser findById(@Param("id") Long id);

/**
 * UserQueryController.java
 */
// ✅ 安全：每个敏感字段 Resolver 单独加 @PreAuthorize
@SchemaMapping(typeName = "SecureUser", field = "salary")
@PreAuthorize("hasRole('ADMIN')")
public Double secureUserSalary(GraphQLUser user) {
    return user.getSalary();
}

@SchemaMapping(typeName = "SecureUser", field = "ssn")
@PreAuthorize("hasRole('ADMIN')")
public String secureUserSsn(GraphQLUser user) {
    return user.getSsn();
}

@SchemaMapping(typeName = "SecureUser", field = "internalNotes")
@PreAuthorize("hasRole('ADMIN')")
public String secureUserInternalNotes(GraphQLUser user) {
    return user.getInternalNotes();
}
// ✅ 无 ADMIN 角色时，字段返回 null + errors: Forbidden</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 漏洞测试对话框 -->
        <el-dialog title="💥 GraphQL Introspection 漏洞演示" :visible.sync="vulnDialogVisible" width="900px" @close="onVulnDialogClose">
            <el-alert
                title="💡 Introspection 攻击流程"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    <strong>测试步骤（依次执行）：</strong><br />
                    <strong>步骤1：</strong>执行 Introspection 查询，获取 Schema 结构<br />
                    <strong>步骤2：</strong>查看返回的 Schema，发现敏感字段名（salary、ssn）<br />
                    <strong>步骤3：</strong>利用发现的字段名，查询敏感数据<br />
                </div>
            </el-alert>

            <!-- 测试区域1：Introspection 查询 -->
            <el-card style="margin-bottom: 20px;">
                <div slot="header">
                    <span>步骤1：执行 Introspection 查询</span>
                </div>
                
                <el-button type="danger" :loading="introspectionLoading" @click="executeIntrospection">
                    执行 __schema 查询
                </el-button>
                
                
                <div v-if="introspectionResult" style="margin-top: 15px;">
                    <el-alert
                        type="error"
                        title="⚠️ Schema 信息泄露！"
                        :closable="false"
                    >
                        <p>成功获取 GraphQL Schema，发现以下字段（含敏感字段）：</p>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <template v-if="leakedUserFields.length">
                                <li v-for="f in leakedUserFields" :key="f.name">
                                    <strong :style="f.sensitive ? 'color: #f56c6c;' : ''">{{ f.name }}</strong>
                                    <span v-if="f.sensitive"> - {{ f.name === 'salary' ? '薪资' : f.name === 'ssn' ? '社保号' : '内部备注' }}（敏感）</span>
                                </li>
                            </template>
                            <template v-else>
                                <li><strong style="color: #f56c6c;">salary</strong> - 薪资（敏感）</li>
                                <li><strong style="color: #f56c6c;">ssn</strong> - 社保号（敏感）</li>
                                <li><strong style="color: #f56c6c;">internalNotes</strong> - 内部备注（敏感）</li>
                            </template>
                        </ul>
                    </el-alert>
                    
                    <el-collapse style="margin-top: 10px;">
                        <el-collapse-item title="📋 查看完整 Schema 结果（点击展开）" name="1">
                            <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; max-height: 300px; overflow-y: auto; font-size: 12px;">{{ JSON.stringify(introspectionResult, null, 2) }}</pre>
                        </el-collapse-item>
                    </el-collapse>
                </div>
            </el-card>

            <!-- 测试区域2：查询敏感字段 -->
            <el-card>
                <div slot="header">
                    <span>步骤3：利用泄露的字段名查询敏感数据</span>
                </div>
                
                <el-form inline>
                    <el-form-item label="选择用户">
                        <el-select v-model="selectedUserId" placeholder="选择用户">
                            <el-option label="admin (ID: 1)" :value="1"></el-option>
                            <el-option label="zhangsan (ID: 2)" :value="2"></el-option>
                            <el-option label="guest (ID: 3)" :value="3"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item>
                        <el-button type="danger" @click="querySensitiveFields">
                            查询敏感字段
                        </el-button>
                    </el-form-item>
                </el-form>
                
                <div v-if="userInfo" style="margin-top: 15px;">
                    <el-alert
                        type="error"
                        title="⚠️ 敏感信息查询成功！"
                        :closable="false"
                        style="margin-bottom: 15px;"
                    >
                        任何人都可以查询其他用户的薪资、社保号等敏感信息！
                    </el-alert>
                    
                    <table class="user-info-table">
                        <tbody>
                            <tr>
                                <td class="info-label">用户ID</td>
                                <td class="info-value">{{ userInfo.id }}</td>
                                <td class="info-label">用户名</td>
                                <td class="info-value">{{ userInfo.username }}</td>
                            </tr>
                            <tr>
                                <td class="info-label">邮箱</td>
                                <td class="info-value" colspan="3">{{ userInfo.email }}</td>
                            </tr>
                            <tr>
                                <td class="info-label">角色</td>
                                <td class="info-value" colspan="3">
                                    <el-tag :type="userInfo.role === 'admin' ? 'danger' : 'info'" size="small">
                                        {{ userInfo.role }}
                                    </el-tag>
                                </td>
                            </tr>
                            <tr class="sensitive-row">
                                <td class="info-label">💰 薪资</td>
                                <td class="info-value sensitive" colspan="3">
                                    ${{ userInfo.salary }}
                                </td>
                            </tr>
                            <tr class="sensitive-row">
                                <td class="info-label">🔒 社保号</td>
                                <td class="info-value sensitive" colspan="3">
                                    {{ userInfo.ssn }}
                                </td>
                            </tr>
                            <tr class="sensitive-row">
                                <td class="info-label">📝 内部备注</td>
                                <td class="info-value sensitive" colspan="3">
                                    {{ userInfo.internalNotes }}
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </el-card>
        </el-dialog>

        <!-- 安全说明对话框 -->
        <el-dialog title="✅ GraphQL Introspection 安全演示" :visible.sync="secDialogVisible" width="700px" @close="onSecDialogClose">
            <el-alert
                title="🛡️ 防御原理"
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 1.8;">
                    <p style="margin: 5px 0;"><strong>1. 禁用 Introspection</strong></p>
                    <p style="margin: 5px 0;">生产环境禁用 Schema 自省功能，攻击者无法获取 API 结构。</p>
                    
                    <br />
                    <p style="margin: 5px 0;"><strong>2. 字段级权限控制</strong></p>
                    <p style="margin: 5px 0;">即使攻击者知道敏感字段名，也会因为权限不足被拒绝访问：</p>
                    <pre style="background-color: #f0f9ff; padding: 8px; border-radius: 4px; margin: 8px 0; font-size: 12px;">@SchemaMapping(typeName = "SecureUser", field = "salary")
@PreAuthorize("hasRole('ADMIN')")  // 只有管理员可访问
public Double secureUserSalary(GraphQLUser user) {
    return user.getSalary();
}</pre>
                    
                    <br />
                    <p style="margin: 5px 0;"><strong>3. 多层防御</strong></p>
                    <ul style="padding-left: 20px; margin: 10px 0;">
                        <li>禁用 Introspection（第一道防线）</li>
                        <li>字段级权限控制（第二道防线）</li>
                        <li>查询深度和复杂度限制（第三道防线）</li>
                        <li>审计和监控（检测异常查询）</li>
                    </ul>
                </div>
            </el-alert>

            <el-alert type="info" title="配置对比" :closable="false">
                <p style="margin: 5px 0;">• <code style="color: #F56C6C;">enabled: true</code>：开启 Introspection，<strong style="color: #F56C6C;">危险</strong></p>
                <p style="margin: 5px 0;">• <code style="color: #67C23A;">enabled: false</code>：禁用 Introspection，<strong style="color: #67C23A;">安全</strong></p>
            </el-alert>

            <!-- 实战测试：字段级权限控制（第二道防线） -->
            <el-divider></el-divider>
            <el-alert
                title="🔒 实战测试：字段级权限控制（第二道防线）"
                type="success"
                :closable="false"
                style="margin-bottom: 15px;">
                <div style="line-height: 1.8; font-size: 13px;">
                    后端对 <code>secureUser</code> 查询的敏感字段 Resolver 均添加了
                    <code>@PreAuthorize("hasRole('ADMIN')")</code>。<br />
                    即使攻击者已通过 Introspection 知道了 <code>salary</code>、<code>ssn</code>、<code>internalNotes</code> 字段名，
                    普通用户仍无法获取数据——服务端在字段解析阶段直接拦截，返回 <code>null</code> + <code>Forbidden</code> 错误。
                </div>
            </el-alert>

            <el-form inline style="margin-bottom: 10px;">
                <el-form-item label="选择用户">
                    <el-select v-model="secureSelectedUserId" placeholder="选择用户">
                        <el-option label="admin (ID: 1)" :value="1"></el-option>
                        <el-option label="zhangsan (ID: 2)" :value="2"></el-option>
                        <el-option label="guest (ID: 3)" :value="3"></el-option>
                    </el-select>
                </el-form-item>
                <el-form-item>
                    <el-button
                        type="success"
                        :loading="secureLoading"
                        @click="querySecureFields">
                        尝试查询敏感字段（字段级权限已启用）
                    </el-button>
                </el-form-item>
            </el-form>

            <div v-if="secureUserResult">
                <!-- 用户不存在时的提示 -->
                <el-alert
                    v-if="!secureUserResult.user && !secureUserResult.errors.length"
                    type="warning"
                    title="⚠️ 用户不存在"
                    :closable="false"
                    style="margin-bottom: 10px;">
                </el-alert>

                <!-- 基本字段：可正常访问 -->
                <el-alert
                    v-if="secureUserResult.user"
                    type="success"
                    title="✅ 基本字段可正常访问（id / username / email / role 无需权限）"
                    :closable="false"
                    style="margin-bottom: 10px;">
                </el-alert>
                <table v-if="secureUserResult.user" class="user-info-table" style="margin-bottom: 15px;">
                    <tbody>
                        <tr>
                            <td class="info-label">用户ID</td>
                            <td class="info-value">{{ secureUserResult.user.id }}</td>
                            <td class="info-label">用户名</td>
                            <td class="info-value">{{ secureUserResult.user.username }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">邮箱</td>
                            <td class="info-value" colspan="3">{{ secureUserResult.user.email }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">角色</td>
                            <td class="info-value" colspan="3">
                                <el-tag :type="secureUserResult.user.role === 'admin' ? 'danger' : 'info'" size="small">
                                    {{ secureUserResult.user.role }}
                                </el-tag>
                            </td>
                        </tr>
                        <tr class="sensitive-row">
                            <td class="info-label">💰 薪资</td>
                            <td class="info-value" colspan="3">
                                <el-tag v-if="secureUserResult.user.salary == null" type="info" size="small">🔒 无权访问</el-tag>
                                <span v-else class="sensitive">{{ secureUserResult.user.salary }}</span>
                            </td>
                        </tr>
                        <tr class="sensitive-row">
                            <td class="info-label">🔒 社保号</td>
                            <td class="info-value" colspan="3">
                                <el-tag v-if="secureUserResult.user.ssn == null" type="info" size="small">🔒 无权访问</el-tag>
                                <span v-else class="sensitive">{{ secureUserResult.user.ssn }}</span>
                            </td>
                        </tr>
                        <tr class="sensitive-row">
                            <td class="info-label">📝 内部备注</td>
                            <td class="info-value" colspan="3">
                                <el-tag v-if="secureUserResult.user.internalNotes == null" type="info" size="small">🔒 无权访问</el-tag>
                                <span v-else class="sensitive">{{ secureUserResult.user.internalNotes }}</span>
                            </td>
                        </tr>
                    </tbody>
                </table>

                <!-- 服务端拦截的错误详情 -->
                <el-alert
                    v-if="secureUserResult.errors && secureUserResult.errors.length"
                    type="warning"
                    title="⚠️ 服务端字段级权限拦截详情（GraphQL errors）"
                    :closable="false">
                    <ul style="margin: 8px 0; padding-left: 20px; font-size: 13px;">
                        <li v-for="(err, idx) in secureUserResult.errors" :key="idx">
                            <strong>{{ err.path ? err.path.join(' → ') : '字段' }}</strong>：{{ err.message }}
                        </li>
                    </ul>
                    <p style="margin: 5px 0; color: #666; font-size: 12px;">
                        <code>@PreAuthorize("hasRole('ADMIN')")</code> 在字段解析阶段拦截了请求，敏感数据不会被读取或返回。
                    </p>
                </el-alert>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { introspectionQuery, getUserWithSensitiveFields, getSecureUser } from '@/api/graphql'

const SENSITIVE_FIELD_NAMES = new Set(['salary', 'ssn', 'internalNotes'])

export default {
    name: 'GraphQLIntrospection',
    data() {
        return {
            activeName: 'first',
            vulnDialogVisible: false,
            secDialogVisible: false,
            introspectionLoading: false,
            introspectionResult: null,
            selectedUserId: 1,
            userInfo: null,
            secureSelectedUserId: 1,
            secureUserResult: null,
            secureLoading: false
        }
    },
    computed: {
        /** 从 Introspection 结果中解析 User 类型的字段（用于动态展示泄露的字段名） */
        leakedUserFields() {
            if (!this.introspectionResult?.__schema?.types) return []
            const userType = this.introspectionResult.__schema.types.find(t => t.name === 'User')
            if (!userType?.fields) return []
            return userType.fields.map(f => ({
                name: f.name,
                sensitive: SENSITIVE_FIELD_NAMES.has(f.name)
            }))
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event)
        },
        
        /**
         * 执行 Introspection 查询
         */
        async executeIntrospection() {
            this.introspectionLoading = true
            try {
                const res = await introspectionQuery()
                this.introspectionResult = res.data
                
                this.$message({
                    type: 'error',
                    message: '⚠️ Introspection 查询成功！敏感字段已暴露',
                    duration: 3000
                })
            } catch (error) {
                this.$message.error('查询失败：' + (error.response?.data?.message || error.message))
            } finally {
                this.introspectionLoading = false
            }
        },
        
        /**
         * 查询敏感字段
         */
        async querySensitiveFields() {
            this.userInfo = null
            try {
                const res = await getUserWithSensitiveFields(this.selectedUserId)
                // request 拦截器返回 response.data，即 GraphQL 响应体 { data: { user: {...} } } 或 { errors: [...] }
                const user = res.data?.user
                const errors = res.errors

                if (user) {
                    this.userInfo = user
                    this.$message({
                        type: 'error',
                        message: '⚠️ 敏感信息查询成功！',
                        duration: 3000
                    })
                } else if (errors && errors.length) {
                    this.$message.error('查询失败：' + errors[0].message)
                } else {
                    this.$message.warning('用户不存在或查询失败')
                }
            } catch (error) {
                this.$message.error('查询失败：' + (error.response?.data?.message || error.message))
            }
        },
        
        /**
         * 安全版：尝试查询敏感字段（字段级权限控制演示）
         * 普通用户（无 ADMIN 角色）发起请求，
         * 敏感字段 Resolver 被 @PreAuthorize 拦截 → 返回 null + errors: Forbidden
         */
        async querySecureFields() {
            this.secureLoading = true
            this.secureUserResult = null
            try {
                const res = await getSecureUser(this.secureSelectedUserId)
                this.secureUserResult = {
                    user: res.data?.secureUser || null,
                    errors: res.errors || []
                }
            } catch (error) {
                this.$message.error('请求失败：' + (error.message || '未知错误'))
            } finally {
                this.secureLoading = false
            }
        },

        onVulnDialogClose() {
            this.introspectionLoading = false
            this.introspectionResult = null
            this.userInfo = null
            this.selectedUserId = 1
        },

        onSecDialogClose() {
            this.secureUserResult = null
            this.secureSelectedUserId = 1
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

.user-info-table tr {
    border-bottom: 1px solid #ebeef5;
}

.user-info-table tr:last-child {
    border-bottom: none;
}

.user-info-table .sensitive-row {
    background-color: #fff5f5;
}

.user-info-table td {
    padding: 10px 14px;
    vertical-align: middle;
}

.user-info-table .info-label {
    width: 110px;
    background-color: #fafafa;
    color: #606266;
    font-weight: bold;
    border-right: 1px solid #ebeef5;
    white-space: nowrap;
}

.user-info-table .info-value {
    color: #303133;
}

.user-info-table .info-value.sensitive {
    color: #f56c6c;
    font-weight: bold;
}
</style>
