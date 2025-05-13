<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">未授权访问漏洞 -- Unauthorized Access</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            未授权访问漏洞是指系统没有对用户访问权限进行严格校验，导致攻击者可以访问未授权的功能或数据。<br>
                            这种漏洞通常发生在系统没有正确实现访问控制机制，或者访问控制机制存在缺陷的情况下。攻击者可以通过直接访问URL、修改请求参数等方式绕过权限验证。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            <p>未授权访问漏洞可能导致的危害：</p>
                            <ul>
                                <li>敏感信息泄露</li>
                                <li>未授权操作执行</li>
                                <li>系统功能被滥用</li>
                                <li>数据被非法访问或修改</li>
                                <li>系统安全机制被绕过</li>
                            </ul>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】访问控制安全实现<br />
                            1. 所有接口必须进行权限校验<br />
                            2. 实现基于角色的访问控制(RBAC)<br />
                            3. 使用统一的权限验证机制<br />
                            4. 对敏感操作进行二次验证<br />
                            5. 记录所有敏感操作的审计日志<br />
                            6. 定期检查权限配置<br />
                            7. 实现最小权限原则
                            <br /><br />
                            【建议】其他安全措施<br />
                            1. 使用Spring Security等安全框架<br />
                            2. 实现细粒度的权限控制<br />
                            3. 定期进行权限审计
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <!-- 给超链接配置下划线 -->
                            暂无
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 未授权访问
                            <el-button type="danger" round size="mini"
                                @click="testUnauthorizedAccess">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
* 未授权访问漏洞，不需要认证登录就可以获取其他人的MFA密钥
* @param userId
* @return
*/

@GetMapping("/vuln2/{userId}")
public Result getMfaSecretByUnAuth(@PathVariable Integer userId) {
    MfaSecret mfaSecret = mfaSecretService.getSecretByUserId(userId);
    if (mfaSecret != null) {
        return Result.success(mfaSecret.getSecret());
    } else {
        return Result.error("用户不存在或者用户未绑定MFA");
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 权限校验
                            <el-button type="success" round size="mini"
                                @click="testAuthorizedAccess">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
* 安全获取MFA密钥接口
* 使用JWT验证用户身份，防止未越权及非法越权访问
* @param userId 用户ID
* @param request HTTP请求对象，用于获取JWT token
* @return MFA密钥信息
*/

@GetMapping("/sec1/{userId}")
public Result getSecureMfaSecret(@PathVariable Integer userId, HttpServletRequest request) {
    // 获取JWT token
    String jwttoken = request.getHeader("Authorization");

    try {
        // 解析获取JWT中用户ID
        String tokenUserId = JwtUtils.parseJwt(jwttoken).get("id").toString();
        
        // 验证用户只能访问自己的MFA密钥
        if (!userId.toString().equals(tokenUserId)) {
            log.warn("用户 {} 尝试越权访问用户 {} 的MFA密钥", tokenUserId, userId);
            return Result.error("无权访问其他用户的MFA密钥");
        }

        // 获取MFA密钥
        MfaSecret mfaSecret = mfaSecretService.getSecretByUserId(userId);
        if (mfaSecret != null) {
            return Result.success(mfaSecret.getSecret());
        } else {
            return Result.error("用户不存在或者用户未绑定MFA");
        }
    } catch (Exception e) {
        log.error("JWT验证失败", e);
        return Result.error("身份验证失败");
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
    </div>
</template>

<script>
export default {
    data() {
        return {
            activeName: 'first',
            // 当前用户ID
            currentUserId: null,
            // 目标用户ID
            targetUserId: null,
        };
    },
    created() {
        // 获取当前登录用户ID
        this.currentUserId = localStorage.getItem('userId');
        // 设置目标用户ID（如果当前是1，则目标是2，反之亦然）
        this.targetUserId = this.currentUserId === '1' ? 2 : 1;
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        // 测试未授权访问
        testUnauthorizedAccess() {
            const url = `http://127.0.0.1:8080/accessControl/UnauthorizedPri/vuln1/${this.targetUserId}`;
            window.open(url, '_blank');
        },
        // 测试权限校验
        testAuthorizedAccess() {
            const url = `http://127.0.0.1:8080/accessControl/UnauthorizedPri/sec1/${this.targetUserId}`;
            window.open(url, '_blank');
        },
    }
};
</script>

<style>
.vuln-info {
    /* 设置边框 */
    /* border: 1px solid #ccc; */
    /* 设置边框圆角 */
    border-radius: 10px;
    /* 设置外边距 */
    margin-left: 20px;
    margin-right: 20px;
    margin-bottom: 20px;
    margin-top: 10px;
}

.header-div {
    font-size: 24px;
    color: #409EFF;
    /* 设置字体加粗 */
    font-weight: bold;
    /* 设置内边距 */
    padding: 10px;
    /* 水平居中 */
    justify-content: center;
    /* 垂直居中 */
    align-items: center;
    /* 添加底部边框线条，颜色为灰色 */
    border-bottom: 1px solid #ccc;

}

.body-div {
    /* 设置内边距 */
    padding: 10px;
    justify-content: center;
    /* 水平居中 */
    align-items: center;
    /* 垂直居中 */
    font-family: Arial, sans-serif;
    /* 设置字体为 Arial，并指定备用字体 */
    font-size: 14px;
    /* 设置字体大小为 16像素 */
}

.vuln-detail {
    background-color: #dce9f8;
    padding: 10px;

}

.code-demo {
    /* 设置外边距 */
    margin: 20px;
    border-top: 1px solid #ccc;
    padding-top: 20px;
}

pre code {
    /* 设置字体大小为 14px */
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

.bg-purple-dark {
    background: #99a9bf;
}

.bg-purple {
    background: #d3dce6;
}

.bg-purple-light {
    background: #e5e9f2;
}

.grid-content {
    border-radius: 4px;
    /* min-height: 36px; */
    height: 100%;
    padding: 10px;

}

.grid-flex {
    display: flex;
    align-items: stretch;
    /* 让子元素在交叉轴方向（垂直方向）拉伸以匹配高度 */
}

.row-bg {
    padding: 10px 0;
    background-color: #f9fafc;
}

.center-dialog {
    text-align: center;
    margin: 0 auto;
}

.center-dialog-table {
    text-align: center;
}
</style>