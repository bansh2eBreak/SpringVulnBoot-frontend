<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">MFA认证漏洞 -- MFA-Based authentication</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            MFA（基于时间的一次性密码）可显著提升账户安全，但如果实现不当，反而会引入新风险。常见漏洞包括：仅在前端校验MFA验证码，后端未强制校验，导致攻击者可直接绕过MFA保护；或MFA密钥管理不当，导致密钥泄露，被他人非法绑定和登录。
                            <br /><br />
                            <span style="color: #e67e22; font-weight: bold;">
                                提示：如需测试“MFA权限控制-越权漏洞（水平越权查询他人MFA）”，请前往“权限漏洞-水平越权漏洞”页面体验相关场景。
                            </span>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            MFA漏洞会导致账户认证形同虚设，攻击者可绕过二次验证，直接重置密码、登录账户，造成敏感信息泄露、账户被盗、资金损失等严重后果，甚至影响企业整体安全。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】所有涉及MFA的敏感操作，必须在后端校验MFA验证码，绝不能只依赖前端校验。<br />
                            【必须】MFA密钥仅存储于后端，严禁通过接口或日志泄露。<br />
                            【建议】限制验证码有效窗口，防止旧码被利用。<br />
                            【建议】对敏感操作增加日志审计，便于追溯异常行为。<br />
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP Authentication Cheat Sheet</a><br />
                            <a href="https://datatracker.ietf.org/doc/html/rfc6238" target="_blank" style="text-decoration: underline;">Google Authenticator安全原理（RFC 6238）</a><br />
                            <a href="https://www.freebuf.com/articles/web/332066.html" target="_blank" style="text-decoration: underline;">MFA安全实践与常见误区</a>
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="vuln-info">
            <div class="header-div">MFA绑定与解绑</div>
            <div class="body-div">
                <el-form :inline="true" class="demo-form-inline">
                    <el-form-item>
                        <el-button type="primary" @click="bindMfa">绑定MFA</el-button>
                    </el-form-item>
                    <el-form-item>
                        <el-button type="danger" @click="resetMfa">解绑MFA</el-button>
                    </el-form-item>
                </el-form>
                <div v-if="mfaInfo" class="vuln-detail">
                    <p>MFA Secret: {{ mfaInfo.secret }}</p>
                    <p>请使用Google Authenticator扫描以下二维码：</p>
                    <img :src="mfaInfo.qrCodeUrl" alt="MFA QR Code" style="max-width: 200px;">
                    <div style="margin-top: 10px; padding: 8px; background-color: #FDF6EC; border: 1px solid #E6A23C; border-radius: 4px; font-size: 12px; color: #E6A23C;">
                        <i class="el-icon-warning"></i>
                        提示：如二维码无法加载（需要科学上网），请直接使用上方的"MFA Secret"手动绑定双因素认证
                    </div>
                </div>
            </div>
        </div>

        <!-- MFA验证绕过漏洞演示 -->
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞场景 - 前端验证绕过
                            <el-button type="danger" round size="mini" @click="openDialog('mfaBypassDialog')">去测试</el-button>
                        </el-row>
                        <pre v-highlightjs><code class="java">
/**
 * 漏洞场景：管理员修改用户密码 - 仅前端验证MFA，后端不校验
 * 攻击者可以通过直接调用API绕过MFA验证
 */
@PostMapping("/changePasswordVuln")
public Result changePasswordVuln(@RequestBody Map&lt;String, Object&gt; requestData, HttpServletRequest request) {
    // 获取请求参数
    Integer targetUserId = (Integer) requestData.get("targetUserId");
    String newPassword = (String) requestData.get("newPassword");
    Integer mfaCode = (Integer) requestData.get("mfaCode");

    // 漏洞：这里没有验证MFA代码，直接执行密码修改
    // 攻击者可以通过直接调用此API绕过MFA验证
    log.warn("漏洞场景：MFA验证被绕过，直接修改用户密码");
    
    // 执行密码修改
    User user = new User();
    user.setId(targetUserId);
    user.setPassword(newPassword);
    
    int result = userService.updateUserPassword(user);
    if (result > 0) {
        return Result.success("密码修改成功");
    } else {
        return Result.error("密码修改失败");
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全场景 - 后端严格校验
                            <el-button type="success" round size="mini" @click="openDialog('mfaSecureDialog')">去测试</el-button>
                        </el-row>
                        <pre v-highlightjs><code class="java">
/**
 * 安全场景：管理员修改用户密码 - 后端严格校验MFA
 */
@PostMapping("/changePasswordSec")
public Result changePasswordSec(@RequestBody Map&lt;String, Object&gt; requestData, HttpServletRequest request) {
    // 获取请求参数
    Integer targetUserId = (Integer) requestData.get("targetUserId");
    String newPassword = (String) requestData.get("newPassword");
    Integer mfaCode = (Integer) requestData.get("mfaCode");

    // 安全：严格验证MFA代码
    // 获取当前用户的MFA密钥
    var mfaSecret = mfaSecretService.getSecretByUserId(tokenUserId);
    if (mfaSecret == null) {
        return Result.error("用户未绑定MFA，无法执行敏感操作");
    }

    // 验证MFA代码
    boolean isValidMfa = GoogleAuthenticatorUtil.verifyCode(mfaSecret.getSecret(), mfaCode);
    if (!isValidMfa) {
        log.warn("用户提供的MFA验证码错误: {}", mfaCode);
        return Result.error("MFA验证码错误");
    }

    log.info("MFA验证通过，执行密码修改操作");
    
    // 执行密码修改
    User user = new User();
    user.setId(targetUserId);
    user.setPassword(newPassword);
    
    int result = userService.updateUserPassword(user);
    if (result > 0) {
        return Result.success("密码修改成功");
    } else {
        return Result.error("密码修改失败");
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>




        <!-- MFA验证绕过漏洞对话框 -->
        <el-dialog title="MFA验证绕过测试" :visible.sync="mfaBypassDialog" class="center-dialog">
            <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
                该接口后端不校验MFA验证码，可被恶意利用绕过MFA验证！
            </div>
            <div style="margin-bottom: 20px;">
                <el-form :inline="true" class="demo-form-inline">
                    <el-form-item label="目标用户ID" label-width="100px">
                        <el-select v-model="mfaBypassForm.targetUserId" placeholder="选择要修改密码的用户" style="width: 200px;">
                            <el-option
                                v-for="user in userList"
                                :key="user.id"
                                :label="`${user.username} (ID: ${user.id})`"
                                :value="user.id">
                            </el-option>
                        </el-select>
                    </el-form-item>
                    <br />
                    <el-form-item label="新密码" label-width="100px">
                        <el-input v-model="mfaBypassForm.newPassword" placeholder="输入新密码" style="width: 200px;" type="password"></el-input>
                    </el-form-item>
                    <br />
                    <el-form-item label="MFA验证码" label-width="100px">
                        <el-input v-model="mfaBypassForm.mfaCode" placeholder="输入MFA验证码（漏洞场景下后端不校验）" style="width: 200px;"></el-input>
                    </el-form-item>
                    <br />
                    <el-form-item>
                        <el-button type="danger" @click="testMfaBypass">测试漏洞（绕过MFA）</el-button>
                    </el-form-item>
                </el-form>
            </div>
            <div>
                <p v-if="mfaBypassResult" style="color: red;">{{ mfaBypassResult }}</p>
            </div>
        </el-dialog>

        <!-- MFA安全验证对话框 -->
        <el-dialog title="MFA安全验证测试" :visible.sync="mfaSecureDialog" class="center-dialog">
            <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
                该接口后端严格校验MFA验证码，只有验证通过才执行敏感操作。<br />请使用Google Authenticator生成正确的验证码，否则无法通过安全验证
            </div>
            <div style="margin-bottom: 20px;">
                <el-form :inline="true" class="demo-form-inline">
                    <el-form-item label="目标用户ID" label-width="100px">
                        <el-select v-model="mfaSecureForm.targetUserId" placeholder="选择要修改密码的用户" style="width: 200px;">
                            <el-option
                                v-for="user in userList"
                                :key="user.id"
                                :label="`${user.username} (ID: ${user.id})`"
                                :value="user.id">
                            </el-option>
                        </el-select>
                    </el-form-item>
                    <br />
                    <el-form-item label="新密码" label-width="100px">
                        <el-input v-model="mfaSecureForm.newPassword" placeholder="输入新密码" style="width: 200px;" type="password"></el-input>
                    </el-form-item>
                    <br />
                    <el-form-item label="MFA验证码" label-width="100px">
                        <el-input v-model="mfaSecureForm.mfaCode" placeholder="输入正确的MFA验证码" style="width: 200px;"></el-input>
                    </el-form-item>
                    <br />
                    <el-form-item>
                        <el-button type="success" @click="testMfaSecure">测试安全验证</el-button>
                    </el-form-item>
                </el-form>
            </div>
            <div>
                <p v-if="mfaSecureResult" style="color: red;">{{ mfaSecureResult }}</p>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { bindMfa, resetMfa, changePasswordVuln, changePasswordSec, getUsers } from '@/api/mfaAuth.js';

export default {
    data() {
        return {
            activeName: 'first',
            mfaInfo: null,
            // MFA验证绕过相关数据
            mfaBypassDialog: false,
            mfaSecureDialog: false,
            userList: [],
            mfaBypassForm: {
                targetUserId: null,
                newPassword: '',
                mfaCode: ''
            },
            mfaSecureForm: {
                targetUserId: null,
                newPassword: '',
                mfaCode: ''
            },
            mfaBypassResult: '',
            mfaSecureResult: ''
        };
    },
    created() {
        this.loadUsers();
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        // 从JWT中获取用户ID
        getUserIdFromJwt() {
            try {
                // 1. 获取Authorization
                const token = localStorage.getItem('Authorization');
                if (!token) {
                    throw new Error('未找到Authorization token');
                }

                // 2. 获取JWT的payload部分
                const payload = token.split('.')[1];
                if (!payload) {
                    throw new Error('JWT格式错误');
                }

                // 3. Base64解码
                const decodedPayload = JSON.parse(atob(payload));
                if (!decodedPayload.id) {
                    throw new Error('JWT中未找到用户ID');
                }

                return decodedPayload.id;
            } catch (error) {
                console.error('获取用户ID失败:', error);
                this.$message.error('获取用户ID失败，请确保已登录');
                return null;
            }
        },
        async bindMfa() {
            const userId = this.getUserIdFromJwt();
            if (!userId) return;

            try {
                const response = await bindMfa({ userId: userId.toString() });
                if (response.code === 0) {
                    this.mfaInfo = {
                        secret: response.data.secret,
                        qrCodeUrl: response.data.qrCodeUrl
                    };
                } else {
                    this.$message.error(response.message || 'MFA绑定失败');
                }
               
            } catch (error) {
                // this.$message.error('MFA绑定请求失败');
                console.error('MFA绑定失败:', error);
            }
        },
        async resetMfa() {
            const userId = this.getUserIdFromJwt();
            if (!userId) return;

            try {
                const response = await resetMfa({ userId: userId.toString() });
                if (response.code === 0) {
                    this.mfaInfo = null;
                    this.$message.success('MFA解绑成功');
                } else {
                    this.$message.error(response.message || 'MFA解绑失败');
                }
            } catch (error) {
                // this.$message.error('MFA解绑请求失败');
                console.error('MFA解绑失败:', error);
            }
        },

        // MFA验证绕过相关方法
        async loadUsers() {
            try {
                const response = await getUsers();
                if (response.code === 0) {
                    this.userList = response.data;
                } else {
                    console.error('获取用户列表失败:', response.message);
                }
            } catch (error) {
                console.error('获取用户列表失败:', error);
            }
        },

        // 打开对话框
        openDialog(dialogName) {
            this[dialogName] = true;
            this.clearMessages();
        },
        
        // 清除所有提示消息
        clearMessages() {
            this.mfaBypassResult = '';
            this.mfaSecureResult = '';
            this.mfaBypassForm = {
                targetUserId: null,
                newPassword: '',
                mfaCode: ''
            };
            this.mfaSecureForm = {
                targetUserId: null,
                newPassword: '',
                mfaCode: ''
            };
        },

        async testMfaBypass() {
            if (!this.mfaBypassForm.targetUserId || !this.mfaBypassForm.newPassword) {
                this.$message.error('请填写完整信息');
                return;
            }

            try {
                const response = await changePasswordVuln({
                    targetUserId: this.mfaBypassForm.targetUserId,
                    newPassword: this.mfaBypassForm.newPassword,
                    mfaCode: this.mfaBypassForm.mfaCode // 漏洞场景：即使不提供MFA验证码也能成功
                });

                if (response.code === 0) {
                    this.mfaBypassResult = `✅ ${response.data}，后端没有验证MFA验证码，直接执行了密码修改操作，成功绕过了MFA验证。`;
                } else {
                    this.mfaBypassResult = `❌ 操作失败：${response.data}`;
                }
            } catch (error) {
                this.mfaBypassResult = `❌ 请求失败：${error.message}`;
            }
        },

        async testMfaSecure() {
            if (!this.mfaSecureForm.targetUserId || !this.mfaSecureForm.newPassword || !this.mfaSecureForm.mfaCode) {
                this.$message.error('请填写完整信息，包括正确的MFA验证码');
                return;
            }

            try {
                const response = await changePasswordSec({
                    targetUserId: this.mfaSecureForm.targetUserId,
                    newPassword: this.mfaSecureForm.newPassword,
                    mfaCode: this.mfaSecureForm.mfaCode
                });

                console.log("sec:" + response.code);

                if (response.code === 0) {
                    this.mfaSecureResult = `✅ ${response.data}，MFA验证码正确！`;
                } else {
                    this.mfaSecureResult = `❌ ${response.data}，安全机制生效：MFA验证码错误，后端拒绝执行敏感操作！`;
                }
            } catch (error) {
                this.mfaSecureResult = `❌ 请求失败：${error.message}`;
            }
        }
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