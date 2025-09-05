<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">JWT安全漏洞 -- JWT接受任意签名</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            JWT接受任意签名漏洞是指JWT验证过程中没有正确验证签名，或者接受任意签名算法。<span style="color: red;">攻击者可以修改JWT的payload部分并使用任意密钥重新签名</span>，从而伪造JWT令牌。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            JWT接受任意签名的危害包括：<br /><br />
                            身份伪造：攻击者可以伪造任意用户的JWT令牌；<br />
                            权限提升：攻击者可以修改JWT中的权限信息；<br />
                            会话劫持：攻击者可以劫持用户的会话；<br />
                            数据篡改：攻击者可以修改JWT中的敏感数据。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】严格验证JWT签名
                            验证JWT时必须使用正确的签名密钥和算法。<br /><br />
                            【必须】指定签名算法
                            在JWT验证时明确指定允许的签名算法。<br /><br />
                            【建议】使用非对称加密
                            考虑使用RS256等非对称加密算法。<br /><br />
                            【建议】密钥轮换
                            定期更换签名密钥，降低密钥泄露风险。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/" target="_blank" style="text-decoration: underline;">《JWT库中的关键漏洞》</a>：了解JWT库中的常见安全漏洞。<br />
                            <a href="https://jwt.io/introduction" target="_blank" style="text-decoration: underline;">《JWT安全最佳实践》</a>：JWT安全配置的详细指南。
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - JWT接受任意签名
                            <div>
                                <el-button type="danger" round size="mini" @click="handleArbitraryTest">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT接受任意签名漏洞 - 不验证签名或接受任意签名
public class JwtArbitraryUtils {
    private static String signKey = "password";
    private static Long expire = 3600000L; // 1小时

    public static String generateJwt(Map&lt;String, Object&gt; claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();
        return jwttoken;
    }

    public static Claims parseJwt(String jwttoken) {
        // 漏洞：不验证签名或接受任意签名
        try {
            // 尝试使用原始密钥解析
            Claims claims = Jwts.parser()
                    .setSigningKey(signKey)
                    .parseClaimsJws(jwttoken)
                    .getBody();
            return claims;
        } catch (Exception e) {
            // 漏洞：如果原始密钥解析失败，尝试使用空密钥或默认密钥
            try {
                Claims claims = Jwts.parser()
                        .setSigningKey("") // 使用空密钥
                        .parseClaimsJws(jwttoken)
                        .getBody();
                return claims;
            } catch (Exception e2) {
                // 漏洞：如果还是失败，尝试不验证签名
                String[] parts = jwttoken.split("\\\\.");
                if (parts.length == 3) {
                    // 直接解码payload部分，不验证签名
                    String payload = new String(Base64.getDecoder().decode(parts[1]));
                    return new DefaultClaims(payload);
                }
            }
        }
        return null;
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - JWT安全签名
                            <div>
                                <el-button type="success" round size="mini" @click="handleSecureTest">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT安全实现 - 严格验证签名
public class JwtSecureUtils {
    private static String signKey = "password";
    private static Long expire = 3600000L; // 1小时

    public static String generateJwt(Map&lt;String, Object&gt; claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();
        return jwttoken;
    }

    public static Claims parseJwt(String jwttoken) {
        // 安全：严格验证签名
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(signKey)
                    .requireIssuer("secure-app") // 验证发行者
                    .requireAudience("secure-users") // 验证受众
                    .parseClaimsJws(jwttoken)
                    .getBody();
            
            // 验证过期时间
            if (claims.getExpiration().before(new Date())) {
                throw new RuntimeException("Token已过期");
            }
            
            return claims;
        } catch (Exception e) {
            // 安全：验证失败时抛出异常，不尝试其他方式
            throw new RuntimeException("JWT验证失败: " + e.getMessage());
        }
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- JWT接受任意签名测试对话框 -->
        <el-dialog :visible.sync="arbitraryTestDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleArbitraryDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT接受任意签名漏洞测试
            </div>
            <div class="test-container">
                <!-- 1. 登录部分 -->
                <div class="test-section">
                    <h3>1. 用户登录 <span style="color: red; font-size: 14px; font-weight: normal;">(测试账号: zhangsan/123)</span></h3>
                    <el-form :model="loginForm" :rules="loginRules" ref="loginForm" label-width="80px" inline>
                        <el-form-item label="用户名" prop="username">
                            <el-input v-model="loginForm.username" placeholder="请输入用户名" style="width: 200px;"></el-input>
                        </el-form-item>
                        <el-form-item label="密码" prop="password">
                            <el-input v-model="loginForm.password" type="password" placeholder="请输入密码" style="width: 200px;"></el-input>
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" @click="handleArbitraryLogin">登录</el-button>
                        </el-form-item>
                    </el-form>
                </div>

                <!-- 2. JWT校验测试 -->
                <div class="test-section">
                    <h3>2. JWT校验测试</h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="jwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="primary" @click="handleVerifyOriginalJwt" :disabled="!jwtToken">
                            校验原始JWT
                        </el-button>
                    </div>
                    <div v-if="verifyResult" class="result-box">
                        <el-alert
                            :title="verifyResult.success ? '校验成功' : '校验失败'"
                            :description="verifyResult.message"
                            :type="verifyResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 3. 校验篡改JWT -->
                <div class="test-section">
                    <h3>3. 校验篡改JWT <span style="color: red; font-size: 14px; font-weight: normal;">(篡改为用户lisi)</span></h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="tamperedJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="篡改的JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="warning" @click="handleVerifyTamperedJwt" :disabled="!tamperedJwtToken">
                            校验篡改JWT
                        </el-button>
                    </div>
                    <div v-if="tamperedVerifyResult" class="result-box">
                        <el-alert
                            :title="tamperedVerifyResult.success ? '校验成功' : '校验失败'"
                            :description="tamperedVerifyResult.message"
                            :type="tamperedVerifyResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 4. 攻击测试 -->
                <div class="test-section">
                    <h3>4. 攻击测试</h3>
                    <p>点击按钮生成篡改的JWT（使用任意密钥签名）：</p>
                    <div class="attack-buttons">
                        <el-button type="danger" @click="handleTamperJwt" :disabled="!jwtToken">
                            篡改JWT
                        </el-button>
                    </div>
                    <div v-if="tamperResult" class="result-box">
                        <el-alert
                            :title="tamperResult.success ? '篡改成功' : '篡改失败'"
                            :description="tamperResult.message"
                            :type="tamperResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>
            </div>
        </el-dialog>

        <!-- JWT安全实现测试对话框 -->
        <el-dialog :visible.sync="secureTestDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleSecureDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT安全实现测试
            </div>
            <div class="test-container">
                <!-- 1. 登录部分 -->
                <div class="test-section">
                    <h3>1. 用户登录 <span style="color: red; font-size: 14px; font-weight: normal;">(测试账号: zhangsan/123)</span></h3>
                    <el-form :model="loginForm" :rules="loginRules" ref="loginForm2" label-width="80px" inline>
                        <el-form-item label="用户名" prop="username">
                            <el-input v-model="loginForm.username" placeholder="请输入用户名" style="width: 200px;"></el-input>
                        </el-form-item>
                        <el-form-item label="密码" prop="password">
                            <el-input v-model="loginForm.password" type="password" placeholder="请输入密码" style="width: 200px;"></el-input>
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" @click="handleSecureLogin">登录</el-button>
                        </el-form-item>
                    </el-form>
                </div>

                <!-- 2. JWT校验测试 -->
                <div class="test-section">
                    <h3>2. JWT校验测试</h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="secureJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="primary" @click="handleSecureVerifyOriginalJwt" :disabled="!secureJwtToken">
                            校验原始JWT
                        </el-button>
                    </div>
                    <div v-if="secureVerifyResult" class="result-box">
                        <el-alert
                            :title="secureVerifyResult.success ? '校验成功' : '校验失败'"
                            :description="secureVerifyResult.message"
                            :type="secureVerifyResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 3. 校验篡改JWT -->
                <div class="test-section">
                    <h3>3. 校验篡改JWT <span style="color: red; font-size: 14px; font-weight: normal;">(篡改为用户lisi)</span></h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="secureTamperedJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="篡改的JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="warning" @click="handleSecureVerifyTamperedJwt" :disabled="!secureTamperedJwtToken">
                            校验篡改JWT
                        </el-button>
                    </div>
                    <div v-if="secureTamperedVerifyResult" class="result-box">
                        <el-alert
                            :title="secureTamperedVerifyResult.success ? '校验成功' : '校验失败'"
                            :description="secureTamperedVerifyResult.message"
                            :type="secureTamperedVerifyResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 4. 攻击测试 -->
                <div class="test-section">
                    <h3>4. 攻击测试</h3>
                    <p>尝试篡改JWT（安全实现会拒绝）：</p>
                    <div class="attack-buttons">
                        <el-button type="danger" @click="handleSecureTamperJwt" :disabled="!secureJwtToken">
                            篡改JWT
                        </el-button>
                    </div>
                    <div v-if="secureTamperResult" class="result-box">
                        <el-alert
                            :title="secureTamperResult.success ? '篡改成功' : '篡改失败'"
                            :description="secureTamperResult.message"
                            :type="secureTamperResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { jwtArbitraryLogin, jwtArbitraryGetInfo, jwtSecureArbitraryLogin, jwtSecureArbitraryGetInfo } from '@/api/jwt'

export default {
    data() {
        return {
            activeName: 'first',
            arbitraryTestDialogVisible: false,
            secureTestDialogVisible: false,
            loginForm: {
                username: '',
                password: ''
            },
            loginRules: {
                username: [
                    { required: true, message: '请输入用户名', trigger: 'blur' }
                ],
                password: [
                    { required: true, message: '请输入密码', trigger: 'blur' }
                ]
            },
            jwtToken: '',
            secureJwtToken: '',
            tamperedJwtToken: '',
            secureTamperedJwtToken: '',
            verifyResult: null,
            secureVerifyResult: null,
            tamperedVerifyResult: null,
            secureTamperedVerifyResult: null,
            tamperResult: null,
            secureTamperResult: null
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        handleArbitraryTest() {
            this.arbitraryTestDialogVisible = true
            this.loginForm.username = 'zhangsan'
            this.loginForm.password = '123'
            this.jwtToken = ''
            this.tamperedJwtToken = ''
            this.verifyResult = null
            this.tamperedVerifyResult = null
            this.tamperResult = null
        },
        handleSecureTest() {
            this.secureTestDialogVisible = true
            this.loginForm.username = 'zhangsan'
            this.loginForm.password = '123'
            this.secureJwtToken = ''
            this.secureTamperedJwtToken = ''
            this.secureVerifyResult = null
            this.secureTamperedVerifyResult = null
            this.secureTamperResult = null
        },
        handleArbitraryLogin() {
            this.$refs.loginForm.validate((valid) => {
                if (valid) {
                    jwtArbitraryLogin(this.loginForm).then(response => {
                        this.jwtToken = response.data
                        // 存储到localStorage的jwt键中
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                    }).catch(error => {
                        // 检查错误是否已经在响应拦截器中处理过
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        handleSecureLogin() {
            this.$refs.loginForm2.validate((valid) => {
                if (valid) {
                    jwtSecureArbitraryLogin(this.loginForm).then(response => {
                        this.secureJwtToken = response.data
                        // 存储到localStorage的jwt键中
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                    }).catch(error => {
                        // 检查错误是否已经在响应拦截器中处理过
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        handleVerifyOriginalJwt() {
            if (!this.jwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            jwtArbitraryGetInfo().then(response => {
                this.verifyResult = {
                    success: true,
                    message: '原始JWT校验成功，用户信息：' + response.data.username
                }
            }).catch(error => {
                this.verifyResult = {
                    success: false,
                    message: '原始JWT校验失败：' + error.message
                }
            })
        },
        handleVerifyTamperedJwt() {
            if (!this.tamperedJwtToken) {
                this.$message.warning('请先生成篡改的JWT Token')
                return
            }
            
            // 临时存储篡改的JWT到localStorage
            const originalJwt = localStorage.getItem('jwt')
            localStorage.setItem('jwt', this.tamperedJwtToken)
            
            // 使用篡改的JWT调用getInfo接口
            jwtArbitraryGetInfo().then(response => {
                this.tamperedVerifyResult = {
                    success: true,
                    message: '篡改JWT验证成功，用户信息：' + response.data.username
                }
                // 恢复原始JWT
                if (originalJwt) {
                    localStorage.setItem('jwt', originalJwt)
                } else {
                    localStorage.removeItem('jwt')
                }
            }).catch(error => {
                this.tamperedVerifyResult = {
                    success: false,
                    message: '篡改JWT验证失败：' + error.message
                }
                // 恢复原始JWT
                if (originalJwt) {
                    localStorage.setItem('jwt', originalJwt)
                } else {
                    localStorage.removeItem('jwt')
                }
            })
        },
        handleTamperJwt() {
            if (!this.jwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            try {
                // 解析原始JWT
                const parts = this.jwtToken.split('.')
                if (parts.length !== 3) {
                    throw new Error('无效的JWT格式')
                }
                
                // 解码payload
                const payload = JSON.parse(atob(parts[1]))
                
                // 修改payload中的用户信息
                const tamperedPayload = {
                    ...payload,
                    name: "李四",
                    id: 2,
                    username: "lisi"
                }
                
                // 使用任意密钥重新签名（演示漏洞）
                const tamperedPayloadBase64 = btoa(JSON.stringify(tamperedPayload))
                const tamperedJwt = `${parts[0]}.${tamperedPayloadBase64}.${parts[2]}`
                
                this.tamperedJwtToken = tamperedJwt
                this.tamperResult = {
                    success: true,
                    message: 'JWT篡改成功！已修改用户信息为：李四(id=2, username=lisi)'
                }
                
                this.$message.success('JWT篡改成功')
            } catch (error) {
                this.tamperResult = {
                    success: false,
                    message: 'JWT篡改失败：' + error.message
                }
                this.$message.error('JWT篡改失败：' + error.message)
            }
        },
        handleSecureVerifyOriginalJwt() {
            if (!this.secureJwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            jwtSecureArbitraryGetInfo().then(response => {
                this.secureVerifyResult = {
                    success: true,
                    message: '原始JWT校验成功，用户信息：' + response.data.username
                }
            }).catch(error => {
                this.secureVerifyResult = {
                    success: false,
                    message: '原始JWT校验失败：' + error.message
                }
            })
        },
        handleSecureVerifyTamperedJwt() {
            if (!this.secureTamperedJwtToken) {
                this.$message.warning('请先生成篡改的JWT Token')
                return
            }
            
            // 临时存储篡改的JWT到localStorage
            const originalJwt = localStorage.getItem('jwt')
            localStorage.setItem('jwt', this.secureTamperedJwtToken)
            
            // 使用篡改的JWT调用getInfo接口
            jwtSecureArbitraryGetInfo().then(response => {
                this.secureTamperedVerifyResult = {
                    success: true,
                    message: '篡改JWT验证成功，用户信息：' + response.data.username
                }
                // 恢复原始JWT
                if (originalJwt) {
                    localStorage.setItem('jwt', originalJwt)
                } else {
                    localStorage.removeItem('jwt')
                }
            }).catch(error => {
                this.secureTamperedVerifyResult = {
                    success: false,
                    message: '篡改JWT验证失败：' + error.message
                }
                // 恢复原始JWT
                if (originalJwt) {
                    localStorage.setItem('jwt', originalJwt)
                } else {
                    localStorage.removeItem('jwt')
                }
            })
        },
        handleSecureTamperJwt() {
            if (!this.secureJwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            try {
                // 解析原始JWT
                const parts = this.secureJwtToken.split('.')
                if (parts.length !== 3) {
                    throw new Error('无效的JWT格式')
                }
                
                // 解码payload
                const payload = JSON.parse(atob(parts[1]))
                
                // 修改payload中的用户信息
                const tamperedPayload = {
                    ...payload,
                    name: "王五",
                    id: 3,
                    username: "wangwu"
                }
                
                // 使用任意密钥重新签名（演示漏洞）
                const tamperedPayloadBase64 = btoa(JSON.stringify(tamperedPayload))
                const tamperedJwt = `${parts[0]}.${tamperedPayloadBase64}.${parts[2]}`
                
                this.secureTamperedJwtToken = tamperedJwt
                this.secureTamperResult = {
                    success: true,
                    message: 'JWT篡改成功！已修改用户信息为：王五(id=3, username=wangwu)'
                }
                
                this.$message.success('JWT篡改成功')
            } catch (error) {
                this.secureTamperResult = {
                    success: false,
                    message: 'JWT篡改失败：' + error.message
                }
                this.$message.error('JWT篡改失败：' + error.message)
            }
        },
        handleArbitraryDialogClose() {
            this.jwtToken = ''
            this.tamperedJwtToken = ''
            this.verifyResult = null
            this.tamperedVerifyResult = null
            this.tamperResult = null
            // 关闭对话框时清除localStorage中的jwt
            localStorage.removeItem('jwt')
        },
        handleSecureDialogClose() {
            this.secureJwtToken = ''
            this.secureTamperedJwtToken = ''
            this.secureVerifyResult = null
            this.secureTamperedVerifyResult = null
            this.secureTamperResult = null
            // 关闭对话框时清除localStorage中的jwt
            localStorage.removeItem('jwt')
        }
    }
}
</script>

<style>
.vuln-info {
    border-radius: 10px;
    margin-left: 20px;
    margin-right: 20px;
    margin-bottom: 20px;
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
    height: 100%;
    padding: 10px;
}

.grid-flex {
    display: flex;
    align-items: stretch;
}

.row-bg {
    padding: 10px 0;
    background-color: #f9fafc;
}

.test-container {
    padding: 20px;
}

.test-section {
    margin-bottom: 30px;
    padding: 20px;
    border: 1px solid #e4e7ed;
    border-radius: 8px;
    background-color: #fafafa;
}

.test-section h3 {
    margin-top: 0;
    margin-bottom: 15px;
    color: #409EFF;
    font-size: 16px;
}

.jwt-input-section {
    margin-bottom: 15px;
}

.jwt-test-buttons {
    margin-bottom: 15px;
}

.jwt-test-buttons .el-button {
    margin-right: 10px;
}

.attack-buttons {
    margin-bottom: 15px;
}

.attack-buttons .el-button {
    margin-right: 10px;
}

.result-box {
    margin-top: 15px;
}
</style>
