<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">水平越权漏洞 -- Horizontal Privilege Escalation</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            水平越权漏洞是指用户可以访问或修改与自己权限级别相同但并不属于自己的数据或资源。<br>
                            例如，用户A可以访问或修改用户B的个人信息，尽管两者拥有相同的权限级别。这种漏洞通常由于应用程序未正确验证请求者是否拥有对所请求资源的访问权限而导致。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            <p>水平越权漏洞可能导致的危害：</p>
                            <ul>
                                <li>用户敏感信息泄露</li>
                                <li>用户数据被非授权修改</li>
                                <li>账户身份冒用</li>
                                <li>业务逻辑混乱</li>
                                <li>系统信誉受损</li>
                            </ul>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】访问控制安全实现<br />
                            1. 所有敏感资源访问必须进行授权校验<br />
                            2. 校验用户对资源的所有权，确保用户只能访问属于自己的资源<br />
                            3. 使用间接引用方式访问资源，避免直接暴露资源标识符<br />
                            4. 不要仅依赖前端隐藏功能按钮来实现访问控制<br />
                            5. 不要仅依赖URL参数来判断访问权限<br />
                            6. 在服务端进行所有权校验，不要信任客户端数据<br />
                            7. 设置会话超时机制
                            <br /><br />
                            【建议】其他安全措施<br />
                            1. 实现基于角色的访问控制(RBAC)或基于属性的访问控制(ABAC)<br />
                            2. 记录所有敏感操作的审计日志<br />
                            3. 对敏感操作增加额外的身份验证步骤
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 水平越权查询他人MFA
                            <el-button type="danger" round size="mini"
                                @click="openDialog('mfaLeakDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
* 越权漏洞，可越权查询其他用户的MFA密钥
* @param userId
* @return
*/

@GetMapping("/vuln1/{userId}")
public Result getMfaSecret(@PathVariable Integer userId) {
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
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 禁止越权查询他人MFA
                            <el-button type="success" round size="mini"
                                @click="openDialog('mfaSafeDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
* 安全获取MFA密钥接口
* 使用JWT验证用户身份，防止越权访问
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

        <!-- 水平越权查询MFA测试对话框 -->
        <el-dialog title="水平越权查询MFA测试" :visible.sync="mfaLeakDialog" class="center-dialog">
            <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
                说明：该接口未做权限校验，可以查询任意用户的MFA信息！<br />
                越权拿到MFA后就可以非法绑定MFA进而进行后续攻击！
            </div>
            <div style="margin-bottom: 20px;">
                <el-button type="danger" @click="testMfaLeak">测试越权查询</el-button>
            </div>
            <div>
                <p v-if="mfaMessage" style="color: red;">{{ mfaMessage }}</p>
            </div>
        </el-dialog>

        <!-- 防水平越权查询MFA测试对话框 -->
        <el-dialog title="防水平越权查询MFA测试" :visible.sync="mfaSafeDialog" class="center-dialog">
            <div style="text-align: center; color: black; font-style: italic; margin-bottom: 20px;">
                说明：该接口增加了权限校验，无法查询其他用户的MFA信息！
            </div>
            <div style="margin-bottom: 20px;">
                <el-button type="success" @click="testMfaSafe">测试安全查询</el-button>
            </div>
            <div>
                <p v-if="mfaMessage" style="color: red;">{{ mfaMessage }}</p>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { getMfaVuln, getMfaSafe, getCurrentUserId } from '@/api/accessControl';

export default {
    data() {
        return {
            activeName: 'first',
            // 对话框显示控制
            mfaLeakDialog: false,
            mfaSafeDialog: false,
            // 提示消息
            mfaMessage: '',
            // 当前用户ID
            currentUserId: null,
            // 目标用户ID
            targetUserId: null,
        };
    },
    created() {
        // 获取当前登录用户ID
        this.currentUserId = getCurrentUserId();
        // 设置目标用户ID（如果当前是1，则目标是2，反之亦然）
        this.targetUserId = this.currentUserId === 1 ? 2 : 1;
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        // 打开对话框
        openDialog(dialogName) {
            this[dialogName] = true;
            this.clearMessages();
        },
        // 清除所有提示消息
        clearMessages() {
            this.mfaMessage = '';
        },
        // 测试水平越权查询MFA
        testMfaLeak() {
            if (!this.currentUserId) {
                this.mfaMessage = '未获取到当前用户信息，请先登录';
                return;
            }
            this.mfaMessage = `当前用户ID: ${this.currentUserId}, 尝试越权查询用户ID: ${this.targetUserId} 的MFA信息...`;
            getMfaVuln(this.targetUserId)
                .then(response => {
                    this.mfaMessage = '查询结果：' + JSON.stringify(response.data);
                })
                .catch(error => {
                    console.error('Error:', error);
                    this.mfaMessage = '查询失败：' + error.message;
                });
        },

        // 测试防水平越权查询MFA
        testMfaSafe() {
            if (!this.currentUserId) {
                this.mfaMessage = '未获取到当前用户信息，请先登录';
                return;
            }
            this.mfaMessage = `当前用户ID: ${this.currentUserId}, 尝试查询用户ID: ${this.targetUserId} 的MFA信息...`;
            getMfaSafe(this.targetUserId)
                .then(response => {
                    this.mfaMessage = '查询结果：' + JSON.stringify(response.data);
                })
                .catch(error => {
                    console.error('Error:', error);
                    this.mfaMessage = '查询失败：' + error.message;
                });
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