<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">GraphQL -- 越权查询（IDOR）漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>GraphQL IDOR（Insecure Direct Object Reference，不安全的直接对象引用）</strong>是一种<span style="color: red;">越权访问漏洞</span>。
                            当服务端直接信任客户端传入的资源 ID，而没有验证「当前登录用户是否有权限访问该 ID 所对应的资源」时，攻击者只需修改请求中的 ID 参数，即可获取其他用户的数据。
                            <br /><br />
                            <strong>什么是 IDOR？</strong><br />
                            IDOR 是指程序直接将用户可控的参数（如 <code>id=1</code>）用于数据库查询或资源定位，
                            却没有做「所有权校验」（ownership check）。本质上是<strong>授权校验缺失</strong>。
                            <br /><br />
                            <strong>GraphQL 场景下的 IDOR：</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• GraphQL 允许客户端在查询中自由传入参数（如 <code>myProfile(id: 1)</code>）<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 若 Resolver 只根据 id 查数据库，不验证该 id 是否属于当前登录用户<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 攻击者只需把 id 改成别人的，就能获取他人的敏感信息<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 结合 Introspection 泄露的字段名，IDOR 危害倍增
                            <br /><br />
                            <strong>本演示场景：</strong><br />
                            系统有三个账户：<code>admin（id=1）</code>、<code>zhangsan（id=2）</code>、<code>guest（id=3）</code>。
                            正常情况下用户只能查询自己的个人信息，但漏洞版本的 <code>myProfile</code> 接口完全信任客户端传入的 id，
                            任何已登录用户都可以通过修改 id 来获取他人的薪资、社保号等敏感数据。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            GraphQL IDOR 危害严重，攻击成本极低：<br /><br />
                            <strong>1. 敏感信息泄露</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 薪资、社保号、内部备注等员工隐私数据被任意读取<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 其他用户的账号信息、角色权限可被枚举<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 攻击者只需遍历 id 参数（1, 2, 3...）即可批量窃取数据<br /><br />
                            <strong>2. 横向越权（水平越权）</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 普通用户（guest）可访问管理员（admin）的专属数据<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 不需要知道目标账户的密码，只需知道其 ID<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• GraphQL 的 Introspection 或字段建议功能可进一步辅助攻击<br /><br />
                            <strong>3. 真实案例</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 某电商平台 GraphQL API：通过修改 <code>order(id: X)</code> 可查询任意用户的订单详情<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• 某社交平台：通过 <code>user(id: X)</code> 可访问私信内容、私人相册<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;• HackerOne 平台上 GraphQL IDOR 是高频漏洞类型之一
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【核心原则】永远不要信任客户端传入的资源标识符</strong><br />
                            资源所有权（ownership）必须由服务端从可信来源（JWT、Session）中自行获取并校验。<br /><br />
                            <strong>【方案1】服务端强制使用 JWT 中的用户 ID（推荐）</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;不接受客户端传入的 id 参数，直接从 JWT 解析当前用户身份：<br />
                            <code>secureMyProfile</code>（无 id 参数）→ 在 Resolver 内解析 JWT 取当前 id，无法伪造。<br /><br />
                            <strong>【方案2】接受 id 参数，但做所有权校验（本演示方案）</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;接受 id 参数，同时从 JWT 取当前用户 id，两者必须一致才能放行：<br />
                            <pre style="background-color: #f0f9ff; padding: 8px; border-radius: 4px; font-size: 12px; margin: 8px 0;">Long jwtUserId = JwtUtils.parseJwt(token).get("id");
if (!jwtUserId.equals(requestedId)) {
    throw new RuntimeException("无权访问：只能查询自己的数据");
}</pre>
                            <strong>【建议】结合 @PreAuthorize 做角色级粗粒度控制</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;在所有权校验之上，还可加上角色校验，实现纵深防御。<br /><br />
                            <strong>【建议】避免使用自增 ID 作为资源标识符</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;使用 UUID 替代自增 ID，可大幅增加 ID 枚举攻击的难度。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://owasp.org/www-chapter-ghana/assets/slides/IDOR.pdf" target="_blank"
                                style="text-decoration: underline;">《OWASP IDOR》</a> - IDOR 漏洞详解<br />
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html" target="_blank"
                                style="text-decoration: underline;">《OWASP GraphQL Cheat Sheet》</a> - GraphQL 安全速查表<br />
                            <a href="https://portswigger.net/web-security/access-control/idor" target="_blank"
                                style="text-decoration: underline;">《PortSwigger: IDOR》</a> - PortSwigger Web Security Academy<br />
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
                            漏洞代码 - 未校验资源所有权（IDOR）
                            <div>
                                <el-button type="danger" round size="mini" @click="vulnDialogVisible = true">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * schema.graphqls
 */
# IDOR 漏洞版：接受任意 id，无身份校验
myProfile(id: ID!): User

/**
 * UserQueryController.java
 */
// ❌ 漏洞：直接信任客户端传入的 id，不验证
// 是否是当前登录用户，任何人可查任何人的数据
@QueryMapping
public GraphQLUser myProfile(@Argument Long id) {
    // 直接查数据库，从不问"你是谁、你有权吗"
    return userService.findById(id);
}

/**
 * 攻击示例（guest 用户越权查询 admin 数据）：
 */
query {
    myProfile(id: 1) {   // ⚠️ 把 id 改成别人的
        username
        salary           // ⚠️ 获取 admin 的薪资
        ssn              // ⚠️ 获取 admin 的社保号
        internalNotes
    }
}</code></pre>
                    </div>
                </el-col>

                <!-- 安全代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - 服务端校验资源所有权
                            <div>
                                <el-button type="success" round size="mini" @click="secDialogVisible = true">
                                    去测试
                                </el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * schema.graphqls
 */
# IDOR 安全版：接受 id，但服务端强制校验
secureMyProfile(id: ID!): User

/**
 * UserQueryController.java
 */
// ✅ 安全：从 JWT 取当前用户 id，与请求 id 比对
@QueryMapping
public GraphQLUser secureMyProfile(@Argument Long id) {
    HttpServletRequest request = ((ServletRequestAttributes)
        RequestContextHolder.getRequestAttributes()).getRequest();
    String token = request.getHeader("Authorization");

    // 从服务端可信来源（JWT）取当前登录用户 id
    Long currentUserId = Long.parseLong(
        JwtUtils.parseJwt(token).get("id").toString()
    );

    // ✅ 所有权校验：请求 id 必须等于当前登录用户 id
    if (!currentUserId.equals(id)) {
        throw new RuntimeException("无权访问：只能查询自己的数据");
    }
    return userService.findById(id);
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 漏洞测试对话框 -->
        <el-dialog title="💥 GraphQL IDOR 越权漏洞演示" :visible.sync="vulnDialogVisible" width="800px" @close="onVulnDialogClose">
            <el-alert
                title="💡 攻击流程"
                type="warning"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 2;">
                    当前以 <strong>{{ currentUsername }}</strong>（JWT id = <strong>{{ currentUserId }}</strong>）身份登录。
                    <br />
                    漏洞版接口 <code>myProfile(id)</code> 会直接使用你传入的 id 查询数据库，<strong>不验证该 id 是否属于你</strong>。
                    <br />
                    请尝试将目标用户 ID 设置为其他用户，看是否能拿到他人的敏感数据。
                </div>
            </el-alert>

            <el-form inline style="margin-bottom: 10px;">
                <el-form-item label="目标用户 ID">
                    <el-select v-model="vulnTargetId" placeholder="选择目标用户">
                        <el-option label="1 - admin（系统管理员）" :value="1"></el-option>
                        <el-option label="2 - zhangsan（审计员）" :value="2"></el-option>
                        <el-option label="3 - guest（访客）" :value="3"></el-option>
                    </el-select>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" :loading="vulnLoading" @click="doVulnAttack">
                        发起越权查询
                    </el-button>
                </el-form-item>
            </el-form>

            <div v-if="vulnResult">
                <!-- 越权成功提示 -->
                <el-alert
                    v-if="vulnResult.user && Number(vulnResult.user.id) !== currentUserId"
                    type="error"
                    :closable="false"
                    style="margin-bottom: 12px;">
                    <strong>⚠️ IDOR 越权成功！</strong>
                    当前用户 <strong>{{ currentUsername }}（id={{ currentUserId }}）</strong>
                    成功获取了 <strong>{{ vulnResult.user.username }}（id={{ vulnResult.user.id }}）</strong> 的敏感数据！
                </el-alert>

                <!-- 查询到自己时的提示 -->
                <el-alert
                    v-else-if="vulnResult.user && Number(vulnResult.user.id) === currentUserId"
                    type="info"
                    title="这是你自己的数据（尝试选择其他用户来演示越权）"
                    :closable="false"
                    style="margin-bottom: 12px;">
                </el-alert>

                <!-- 用户不存在 -->
                <el-alert
                    v-else-if="!vulnResult.user && !vulnResult.errors.length"
                    type="warning"
                    title="⚠️ 用户不存在"
                    :closable="false"
                    style="margin-bottom: 12px;">
                </el-alert>

                <table v-if="vulnResult.user" class="user-info-table">
                    <tbody>
                        <tr>
                            <td class="info-label">用户ID</td>
                            <td class="info-value">{{ vulnResult.user.id }}</td>
                            <td class="info-label">用户名</td>
                            <td class="info-value">{{ vulnResult.user.username }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">邮箱</td>
                            <td class="info-value" colspan="3">{{ vulnResult.user.email }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">角色</td>
                            <td class="info-value" colspan="3">
                                <el-tag :type="vulnResult.user.role === 'admin' ? 'danger' : 'info'" size="small">
                                    {{ vulnResult.user.role }}
                                </el-tag>
                            </td>
                        </tr>
                        <tr class="sensitive-row">
                            <td class="info-label">💰 薪资</td>
                            <td class="info-value sensitive" colspan="3">${{ vulnResult.user.salary }}</td>
                        </tr>
                        <tr class="sensitive-row">
                            <td class="info-label">🔒 社保号</td>
                            <td class="info-value sensitive" colspan="3">{{ vulnResult.user.ssn }}</td>
                        </tr>
                        <tr class="sensitive-row">
                            <td class="info-label">📝 内部备注</td>
                            <td class="info-value sensitive" colspan="3">{{ vulnResult.user.internalNotes }}</td>
                        </tr>
                    </tbody>
                </table>

                <el-alert
                    v-if="vulnResult.errors && vulnResult.errors.length"
                    type="error"
                    title="接口返回错误"
                    :closable="false"
                    style="margin-top: 10px;">
                    <ul style="margin: 6px 0; padding-left: 20px; font-size: 13px;">
                        <li v-for="(err, idx) in vulnResult.errors" :key="idx">{{ err.message }}</li>
                    </ul>
                </el-alert>
            </div>
        </el-dialog>

        <!-- 安全演示对话框 -->
        <el-dialog title="✅ GraphQL IDOR 安全演示" :visible.sync="secDialogVisible" width="800px" @close="onSecDialogClose">
            <el-alert
                title="🛡️ 防御原理"
                type="success"
                :closable="false"
                style="margin-bottom: 20px;">
                <div style="line-height: 1.8; font-size: 13px;">
                    安全版 <code>secureMyProfile(id)</code> 在查询数据库<strong>之前</strong>，先从 JWT 中解析出当前登录用户的 id，
                    然后与请求参数中的 id 进行比对——<strong>只有两者相同才允许查询</strong>，否则直接拒绝。
                    <br />
                    客户端传入的 id 无法改变服务端对"你是谁"的判断，因为身份依据来自服务端签发的 JWT，不受客户端控制。
                </div>
            </el-alert>

            <el-alert
                type="info"
                :closable="false"
                style="margin-bottom: 15px;">
                当前以 <strong>{{ currentUsername }}</strong>（JWT id = <strong>{{ currentUserId }}</strong>）身份登录。
                请尝试查询不同的用户 ID，观察安全版的拦截效果。
            </el-alert>

            <el-form inline style="margin-bottom: 10px;">
                <el-form-item label="目标用户 ID">
                    <el-select v-model="secTargetId" placeholder="选择目标用户">
                        <el-option label="1 - admin（系统管理员）" :value="1"></el-option>
                        <el-option label="2 - zhangsan（审计员）" :value="2"></el-option>
                        <el-option label="3 - guest（访客）" :value="3"></el-option>
                    </el-select>
                </el-form-item>
                <el-form-item>
                    <el-button type="success" :loading="secLoading" @click="doSecureQuery">
                        尝试查询（所有权校验已启用）
                    </el-button>
                </el-form-item>
            </el-form>

            <div v-if="secResult">
                <!-- 被拦截 -->
                <el-alert
                    v-if="secResult.blocked"
                    type="warning"
                    :closable="false"
                    style="margin-bottom: 12px;">
                    <strong>🚫 越权查询被拦截！</strong>
                    服务端检测到 JWT 中的 id（{{ currentUserId }}）与请求 id（{{ secTargetId }}）不一致，拒绝访问。
                    <br /><br />
                    <strong>服务端返回错误：</strong>
                    <ul style="margin: 6px 0; padding-left: 20px; font-size: 13px;">
                        <li v-for="(err, idx) in secResult.errors" :key="idx">{{ err.message }}</li>
                    </ul>
                </el-alert>

                <!-- 查询成功（自己的数据） -->
                <el-alert
                    v-else-if="secResult.user"
                    type="success"
                    title="✅ 查询成功！只能访问自己的数据"
                    :closable="false"
                    style="margin-bottom: 12px;">
                </el-alert>

                <table v-if="secResult.user" class="user-info-table">
                    <tbody>
                        <tr>
                            <td class="info-label">用户ID</td>
                            <td class="info-value">{{ secResult.user.id }}</td>
                            <td class="info-label">用户名</td>
                            <td class="info-value">{{ secResult.user.username }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">邮箱</td>
                            <td class="info-value" colspan="3">{{ secResult.user.email }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">角色</td>
                            <td class="info-value" colspan="3">
                                <el-tag :type="secResult.user.role === 'admin' ? 'danger' : 'info'" size="small">
                                    {{ secResult.user.role }}
                                </el-tag>
                            </td>
                        </tr>
                        <tr>
                            <td class="info-label">💰 薪资</td>
                            <td class="info-value" colspan="3">${{ secResult.user.salary }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">🔒 社保号</td>
                            <td class="info-value" colspan="3">{{ secResult.user.ssn }}</td>
                        </tr>
                        <tr>
                            <td class="info-label">📝 内部备注</td>
                            <td class="info-value" colspan="3">{{ secResult.user.internalNotes }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { myProfile, secureMyProfile } from '@/api/graphql'

/**
 * 从 localStorage 中解析 JWT Payload，提取当前登录用户的 id 和 username。
 *
 * JWT 使用 Base64URL 编码（将标准 Base64 的 + 换成 -，/ 换成 _，并去掉末尾 = 填充）。
 * 浏览器原生 atob() 只支持标准 Base64，需要先做字符替换和补齐填充再解码。
 */
function parseCurrentUser() {
    try {
        const token = localStorage.getItem('Authorization')
        if (!token) return { id: null, username: '未登录' }

        // Base64URL → 标准 Base64：替换特殊字符并补齐 '=' 填充
        let base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
        while (base64.length % 4 !== 0) base64 += '='

        const payload = JSON.parse(atob(base64))
        return { id: Number(payload.id), username: payload.username || '未知' }
    } catch {
        return { id: null, username: '解析失败' }
    }
}

export default {
    name: 'GraphQLIdor',
    data() {
        const currentUser = parseCurrentUser()
        return {
            activeName: 'first',
            currentUserId: currentUser.id,
            currentUsername: currentUser.username,

            vulnDialogVisible: false,
            vulnTargetId: 1,
            vulnLoading: false,
            vulnResult: null,

            secDialogVisible: false,
            secTargetId: 1,
            secLoading: false,
            secResult: null
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event)
        },

        /** 漏洞版：发起越权查询 */
        async doVulnAttack() {
            this.vulnLoading = true
            this.vulnResult = null
            try {
                const res = await myProfile(this.vulnTargetId)
                this.vulnResult = {
                    user: res.data?.myProfile || null,
                    errors: res.errors || []
                }
            } catch (error) {
                this.$message.error('请求失败：' + (error.message || '未知错误'))
            } finally {
                this.vulnLoading = false
            }
        },

        /** 安全版：尝试越权查询（会被服务端拦截） */
        async doSecureQuery() {
            this.secLoading = true
            this.secResult = null
            try {
                const res = await secureMyProfile(this.secTargetId)
                const user = res.data?.secureMyProfile || null
                const errors = res.errors || []
                // 有 errors 且 user 为 null，说明被拦截（IDOR 防御生效）
                const blocked = !user && errors.length > 0
                this.secResult = { user, errors, blocked }
            } catch (error) {
                this.$message.error('请求失败：' + (error.message || '未知错误'))
            } finally {
                this.secLoading = false
            }
        },

        onVulnDialogClose() {
            this.vulnResult = null
            this.vulnTargetId = 1
        },

        onSecDialogClose() {
            this.secResult = null
            this.secTargetId = 1
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
