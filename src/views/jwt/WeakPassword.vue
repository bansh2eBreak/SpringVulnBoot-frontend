<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">JWT安全漏洞 -- JWT弱密码</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            JWT（JSON Web Token）弱密码漏洞是指JWT签名密钥过于简单或可预测，攻击者可以通过暴力破解、字典攻击等方式获取签名密钥，从而伪造JWT令牌。<span style="color: red;">弱密码</span>包括常见的默认密码、简单密码、可预测的密码等。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            JWT弱密码漏洞的危害非常严重，攻击者一旦获取到签名密钥，就可以：<br /><br />
                            身份伪造：攻击者可以伪造任意用户的JWT令牌，冒充其他用户身份；<br />
                            权限提升：攻击者可以修改JWT中的权限信息，获取更高权限；<br />
                            会话劫持：攻击者可以劫持用户的会话，进行恶意操作；<br />
                            数据泄露：攻击者可以访问敏感数据，造成信息泄露。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】使用强密码作为JWT签名密钥
                            签名密钥应该足够复杂，包含大小写字母、数字和特殊字符，长度至少32位。<br /><br />
                            【必须】定期更换签名密钥
                            定期更换JWT签名密钥，降低密钥泄露的风险。<br /><br />
                            【建议】使用密钥管理服务
                            使用专业的密钥管理服务来存储和管理JWT签名密钥。<br /><br />
                            【建议】密钥轮换机制
                            实现密钥轮换机制，确保在密钥泄露时能够快速切换。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://jwt.io/" target="_blank" style="text-decoration: underline;">《JWT官方文档》</a>：了解JWT的详细规范和最佳实践。<br />
                            <a href="https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/" target="_blank" style="text-decoration: underline;">《JWT安全最佳实践》</a>：JWT安全配置的最佳实践指南。
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
                            漏洞代码 - JWT弱密码
                            <div>
                                <el-button type="danger" round size="mini" @click="handleWeakTest">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT弱密码漏洞 - 使用简单密码作为签名密钥
public class JwtWeakUtils {
    // 使用弱密码作为签名密钥
    private static String weakSignKey = "Aa123123";
    // 使用强密码作为签名密钥（至少32位，包含大小写字母、数字、特殊字符）
    private static String strongSignKey = "A9b8C7d6E5f4G3h2I1j0K9l8M7n6O5p4Q3r2";
    private static Long expire = 3600000L; // 1小时

    // 弱密码生成JWT
    public static String generateWeakJwt(Map&lt;String, Object&gt; claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, weakSignKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();
        return jwttoken;
    }

    // 弱密码解析JWT
    public static Claims parseWeakJwt(String jwttoken) {
        Claims claims = Jwts.parser()
                .setSigningKey(weakSignKey)
                .parseClaimsJws(jwttoken)
                .getBody();
        return claims;
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - JWT强密码
                            <div>
                                <el-button type="success" round size="mini" @click="handleStrongTest">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT安全实现 - 使用强密码作为签名密钥
public class JwtWeakUtils {
    // 使用弱密码作为签名密钥
    private static String weakSignKey = "Aa123123";
    // 使用强密码作为签名密钥（至少32位，包含大小写字母、数字、特殊字符）
    private static String strongSignKey = "A9b8C7d6E5f4G3h2I1j0K9l8M7n6O5p4Q3r2";
    private static Long expire = 3600000L; // 1小时

    // 强密码生成JWT
    public static String generateStrongJwt(Map&lt;String, Object&gt; claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, strongSignKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();
        return jwttoken;
    }

    // 强密码解析JWT
    public static Claims parseStrongJwt(String jwttoken) {
        Claims claims = Jwts.parser()
                .setSigningKey(strongSignKey)
                .parseClaimsJws(jwttoken)
                .getBody();
        return claims;
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- JWT弱密码测试对话框 -->
        <el-dialog :visible.sync="weakTestDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleWeakDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT弱密码漏洞测试
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
                            <el-button type="primary" @click="handleWeakLogin">登录</el-button>
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
                    <p>点击按钮尝试常见弱密码破解JWT签名密钥：</p>
                    <div class="attack-buttons">
                        <el-button type="danger" @click="handleBruteForce" :loading="bruteForceLoading" style="margin-right: 10px;">
                            {{ bruteForceLoading ? '破解中...' : '开始暴力破解' }}
                        </el-button>
                        <el-button type="warning" @click="handleTamperJwt" :disabled="!crackedPassword || !jwtToken">
                            篡改JWT
                        </el-button>
                    </div>
                    <div v-if="crackedPassword" class="result-box">
                        <el-alert
                            title="破解成功！"
                            :description="`发现弱密码: ${crackedPassword}`"
                            type="success"
                            show-icon>
                        </el-alert>
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

        <!-- JWT强密码测试对话框 -->
        <el-dialog :visible.sync="strongTestDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleStrongDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT强密码安全测试
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
                            <el-button type="primary" @click="handleStrongLogin">登录</el-button>
                        </el-form-item>
                    </el-form>
                </div>

                <!-- 2. JWT校验测试 -->
                <div class="test-section">
                    <h3>2. JWT校验测试</h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="strongJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="primary" @click="handleStrongVerifyOriginalJwt" :disabled="!strongJwtToken">
                            校验原始JWT
                        </el-button>
                    </div>
                    <div v-if="strongVerifyResult" class="result-box">
                        <el-alert
                            :title="strongVerifyResult.success ? '校验成功' : '校验失败'"
                            :description="strongVerifyResult.message"
                            :type="strongVerifyResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 3. 校验篡改JWT -->
                <div class="test-section">
                    <h3>3. 校验篡改JWT <span style="color: red; font-size: 14px; font-weight: normal;">(篡改为用户lisi)</span></h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="strongTamperedJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="篡改的JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="warning" @click="handleStrongVerifyTamperedJwt" :disabled="!strongTamperedJwtToken">
                            校验篡改JWT
                        </el-button>
                    </div>
                    <div v-if="strongTamperedVerifyResult" class="result-box">
                        <el-alert
                            :title="strongTamperedVerifyResult.success ? '校验成功' : '校验失败'"
                            :description="strongTamperedVerifyResult.message"
                            :type="strongTamperedVerifyResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 4. 攻击测试 -->
                <div class="test-section">
                    <h3>4. 攻击测试</h3>
                    <p>尝试破解强密码（这可能需要很长时间）：</p>
                    <div class="attack-buttons">
                        <el-button type="danger" @click="handleStrongBruteForce" :loading="strongBruteForceLoading" style="margin-right: 10px;">
                            {{ strongBruteForceLoading ? '破解中...' : '开始暴力破解' }}
                        </el-button>
                        <el-button type="warning" @click="handleStrongTamperJwt" :disabled="!strongCrackedPassword || !strongJwtToken">
                            篡改JWT
                        </el-button>
                    </div>
                    <div v-if="strongCrackedPassword" class="result-box">
                        <el-alert
                            title="破解成功！"
                            :description="`发现密码: ${strongCrackedPassword}`"
                            type="success"
                            show-icon>
                        </el-alert>
                    </div>
                    <div v-if="strongTamperResult" class="result-box">
                        <el-alert
                            :title="strongTamperResult.success ? '篡改成功' : '篡改失败'"
                            :description="strongTamperResult.message"
                            :type="strongTamperResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { jwtWeakLogin, jwtWeakGetInfo, jwtStrongLogin, jwtStrongGetInfo } from '@/api/jwt'
import CryptoJS from 'crypto-js'
import { Base64 } from 'js-base64'

export default {
    data() {
        return {
            activeName: 'first',
            weakTestDialogVisible: false,
            strongTestDialogVisible: false,
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
            strongJwtToken: '',
            tamperedJwtToken: '',
            strongTamperedJwtToken: '',
            bruteForceLoading: false,
            strongBruteForceLoading: false,
            crackedPassword: '',
            strongCrackedPassword: '',
            verifyResult: null,
            strongVerifyResult: null,
            tamperedVerifyResult: null,
            strongTamperedVerifyResult: null,
            tamperResult: null,
            strongTamperResult: null,
            commonWeakPasswords: [
                '123456', 'password', 'admin', '12345678', 'qwerty', '1234567890',
                '1234567', '123456789', '12345', '1234', '111111', '12345678910',
                '000000', '123123', '123321', '654321', '666666', '888888',
                '11111111', '123456789a', 'abc123', '123456789abc', 'Aa123123'
            ]
        }
    },
    methods: {
        handleClick(tab, event) {
            // 处理标签页点击事件
        },
        handleWeakTest() {
            this.weakTestDialogVisible = true
            this.resetTestData()
        },
        handleStrongTest() {
            this.strongTestDialogVisible = true
            this.resetTestData()
        },
        handleWeakDialogClose() {
            // 关闭弱密码测试对话框时清除localStorage中的jwt
            localStorage.removeItem('jwt')
        },
        handleStrongDialogClose() {
            // 关闭强密码测试对话框时清除localStorage中的jwt
            localStorage.removeItem('jwt')
        },
        resetTestData() {
            this.jwtToken = ''
            this.strongJwtToken = ''
            this.tamperedJwtToken = ''
            this.strongTamperedJwtToken = ''
            this.crackedPassword = ''
            this.strongCrackedPassword = ''
            this.verifyResult = null
            this.strongVerifyResult = null
            this.tamperedVerifyResult = null
            this.strongTamperedVerifyResult = null
            this.tamperResult = null
            this.strongTamperResult = null
            // 不再在这里清除localStorage中的jwt，改为在对话框关闭时清除
        },
        handleWeakLogin() {
            this.$refs.loginForm.validate((valid) => {
                if (valid) {
                    jwtWeakLogin(this.loginForm).then(response => {
                        this.jwtToken = response.data
                        // 存储到localStorage的jwt键中
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                    }).catch(error => {
                        // 检查错误是否已经在响应拦截器中处理过
                        // 如果error.message是"Error"或"error"，说明是响应拦截器处理的，不需要重复显示
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        handleStrongLogin() {
            this.$refs.loginForm2.validate((valid) => {
                if (valid) {
                    // 调用强密码版本的API
                    jwtStrongLogin(this.loginForm).then(response => {
                        this.strongJwtToken = response.data
                        // 存储到localStorage的jwt键中
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                    }).catch(error => {
                        // 检查错误是否已经在响应拦截器中处理过
                        // 如果error.message是"Error"或"error"，说明是响应拦截器处理的，不需要重复显示
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        handleBruteForce() {
            if (!this.jwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            this.bruteForceLoading = true
            this.crackedPassword = ''
            
            // 前端暴力破解JWT
            this.bruteForceJwt(this.jwtToken)
        },
        
        // 前端暴力破解JWT方法
        bruteForceJwt(jwtToken) {
            const parts = jwtToken.split('.')
            if (parts.length !== 3) {
                this.$message.error('无效的JWT格式')
                this.bruteForceLoading = false
                return
            }
            
            // 获取JWT的三个部分
            const header = parts[0]
            const payload = parts[1]
            const originalSignature = parts[2]
            
            // 模拟暴力破解过程
            let currentIndex = 0
            
            const tryNextPassword = () => {
                if (currentIndex >= this.commonWeakPasswords.length) {
                    // 所有密码都尝试失败
                    this.$message.info('暴力破解失败，未找到正确的密码')
                    this.bruteForceLoading = false
                    return
                }
                
                const password = this.commonWeakPasswords[currentIndex]
                currentIndex++
                
                // 模拟尝试密码的过程
                setTimeout(() => {
                    // 使用当前密码尝试签名（参考VerticalPriVuln.vue的逻辑）
                    const signatureInput = header + '.' + payload
                    
                    // 使用Base64编码的密钥进行签名（关键！）
                    const key = CryptoJS.enc.Base64.parse(password)
                    const signature = CryptoJS.HmacSHA256(signatureInput, key)
                    const computedSignature = signature.toString(CryptoJS.enc.Base64)
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '')
                    
                    // 比较计算出的签名与原始签名
                    if (computedSignature === originalSignature) {
                        // 找到正确的密码
                        this.crackedPassword = password
                        this.$message.success(`暴力破解成功！发现弱密码: ${password}`)
                        this.bruteForceLoading = false
                        return
                    }
                    
                    // 继续尝试下一个密码
                    tryNextPassword()
                }, 200) // 200ms延迟，让用户看到破解过程
            }
            
            // 开始暴力破解
            tryNextPassword()
        },
        

        handleStrongBruteForce() {
            if (!this.strongJwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            this.strongBruteForceLoading = true
            this.strongCrackedPassword = ''
            
            // 前端暴力破解强密码JWT（使用相同的弱密码列表，但会失败）
            this.bruteForceStrongJwt(this.strongJwtToken)
        },
        
        // 前端暴力破解强密码JWT方法
        bruteForceStrongJwt(jwtToken) {
            const parts = jwtToken.split('.')
            if (parts.length !== 3) {
                this.$message.error('无效的JWT格式')
                this.strongBruteForceLoading = false
                return
            }
            
            // 获取JWT的三个部分
            const header = parts[0]
            const payload = parts[1]
            const originalSignature = parts[2]
            
            // 模拟暴力破解强密码过程（会失败）
            let currentIndex = 0
            
            const tryNextPassword = () => {
                if (currentIndex >= this.commonWeakPasswords.length) {
                    // 所有密码都尝试失败（强密码JWT的预期结果）
                    this.$message.info('强密码JWT使用强密钥，暴力破解失败')
                    this.strongBruteForceLoading = false
                    return
                }
                
                const password = this.commonWeakPasswords[currentIndex]
                currentIndex++
                
                // 模拟尝试密码的过程
                setTimeout(() => {
                    // 使用当前密码尝试签名（参考VerticalPriVuln.vue的逻辑）
                    const signatureInput = header + '.' + payload
                    
                    // 使用Base64编码的密钥进行签名（关键！）
                    const key = CryptoJS.enc.Base64.parse(password)
                    const signature = CryptoJS.HmacSHA256(signatureInput, key)
                    const computedSignature = signature.toString(CryptoJS.enc.Base64)
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '')
                    
                    // 比较计算出的签名与原始签名
                    if (computedSignature === originalSignature) {
                        // 理论上强密码JWT不应该被破解，但如果意外成功
                        this.strongCrackedPassword = password
                        this.$message.success(`意外破解成功！发现密码: ${password}`)
                        this.strongBruteForceLoading = false
                        return
                    }
                    
                    // 继续尝试下一个密码
                    tryNextPassword()
                }, 200) // 200ms延迟，让用户看到破解过程
            }
            
            // 开始暴力破解
            tryNextPassword()
        },
        handleVerifyOriginalJwt() {
            if (!this.jwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            jwtWeakGetInfo().then(response => {
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
            jwtWeakGetInfo().then(response => {
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
        handleStrongVerifyOriginalJwt() {
            if (!this.strongJwtToken) {
                this.$message.warning('请先登录获取JWT Token')
                return
            }
            
            // 调用强密码版本的API
            jwtStrongGetInfo().then(response => {
                this.strongVerifyResult = {
                    success: true,
                    message: '原始JWT校验成功，用户信息：' + response.data.username
                }
            }).catch(error => {
                this.strongVerifyResult = {
                    success: false,
                    message: '原始JWT校验失败：' + error.message
                }
            })
        },
        handleStrongVerifyTamperedJwt() {
            if (!this.strongTamperedJwtToken) {
                this.$message.warning('请先生成篡改的JWT Token')
                return
            }
            
            // 临时存储篡改的JWT到localStorage
            const originalJwt = localStorage.getItem('jwt')
            localStorage.setItem('jwt', this.strongTamperedJwtToken)
            
            // 使用篡改的JWT调用强密码getInfo接口
            jwtStrongGetInfo().then(response => {
                this.strongTamperedVerifyResult = {
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
                this.strongTamperedVerifyResult = {
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
        
        // 篡改JWT方法
        handleTamperJwt() {
            if (!this.jwtToken || !this.crackedPassword) {
                this.$message.warning('请先登录获取JWT Token并破解密码')
                return
            }
            
            try {
                // 1. 解析原始JWT
                const parts = this.jwtToken.split('.')
                if (parts.length !== 3) {
                    throw new Error('无效的JWT格式')
                }
                
                const header = JSON.parse(Base64.decode(parts[0]))
                const payload = JSON.parse(Base64.decode(parts[1]))
                
                // 2. 修改payload中的用户信息
                const tamperedPayload = {
                    ...payload,
                    name: "李四",
                    id: 2,
                    username: "lisi"
                }
                
                // 3. 使用相同的header和修改后的payload重新签名
                const sHeader = Base64.encode(JSON.stringify(header));
                const sPayload = Base64.encode(JSON.stringify(tamperedPayload));
                
                // 4. 使用crypto-js进行签名
                const signatureInput = sHeader + '.' + sPayload
                
                // 使用破解的密码作为密钥进行签名（参考VerticalPriVuln.vue的逻辑）
                const key = CryptoJS.enc.Base64.parse(this.crackedPassword)
                const signature = CryptoJS.HmacSHA256(signatureInput, key)

                
                // 使用Base64URL编码（去掉末尾的=号）
                const base64Signature = signature.toString(CryptoJS.enc.Base64)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '')

                
                // 5. 生成篡改的JWT
                this.tamperedJwtToken = `${sHeader}.${sPayload}.${base64Signature}`
                
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
        
        // 强密码JWT篡改方法
        handleStrongTamperJwt() {
            if (!this.strongJwtToken || !this.strongCrackedPassword) {
                this.$message.warning('请先登录获取JWT Token并破解密码')
                return
            }
            
            try {
                // 1. 解析原始JWT
                const parts = this.strongJwtToken.split('.')
                if (parts.length !== 3) {
                    throw new Error('无效的JWT格式')
                }
                
                const header = JSON.parse(Base64.decode(parts[0]))
                const payload = JSON.parse(Base64.decode(parts[1]))
                
                // 2. 修改payload中的用户信息
                const tamperedPayload = {
                    ...payload,
                    name: "王五",
                    id: 3,
                    username: "wangwu"
                }
                
                // 3. 使用相同的header和修改后的payload重新签名
                const sHeader = Base64.encode(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
                const sPayload = Base64.encode(JSON.stringify(tamperedPayload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
                
                // 4. 使用crypto-js进行签名
                const signatureInput = sHeader + '.' + sPayload
                
                // 使用破解的密码作为密钥进行签名（参考VerticalPriVuln.vue的逻辑）
                const key = CryptoJS.enc.Base64.parse(this.strongCrackedPassword)
                const signature = CryptoJS.HmacSHA256(signatureInput, key)
                
                // 使用Base64URL编码（去掉末尾的=号）
                const base64Signature = signature.toString(CryptoJS.enc.Base64)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '')
                
                // 5. 生成篡改的JWT
                this.strongTamperedJwtToken = `${sHeader}.${sPayload}.${base64Signature}`
                
                this.strongTamperResult = {
                    success: true,
                    message: 'JWT篡改成功！已修改用户信息为：王五(id=3, username=wangwu)'
                }
                
                this.$message.success('JWT篡改成功')
            } catch (error) {
                this.strongTamperResult = {
                    success: false,
                    message: 'JWT篡改失败：' + error.message
                }
                this.$message.error('JWT篡改失败：' + error.message)
            }
        },
    },
    watch: {
        weakTestDialogVisible(newVal) {
            if (!newVal) {
                this.resetTestData()
            }
        },
        strongTestDialogVisible(newVal) {
            if (!newVal) {
                this.resetTestData()
            }
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

.result-box {
    margin-top: 15px;
}
</style>
