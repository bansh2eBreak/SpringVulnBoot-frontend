<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">JWT安全漏洞 -- JWT 算法混淆漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            JWT算法混淆漏洞是指JWT验证过程中根据JWT header中的算法字段动态选择验证方式，导致攻击者可以通过修改算法类型来绕过验证。<span style="color: red;">攻击者可以获取RSA公钥，将其作为HMAC密钥来签名HS256 JWT</span>，服务器会错误地使用公钥验证HS256签名，从而绕过身份验证。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            JWT算法混淆漏洞的危害非常严重，攻击者一旦成功利用，就可以：<br /><br />
                            身份伪造：攻击者可以伪造任意用户的JWT令牌，冒充其他用户身份；<br />
                            权限提升：攻击者可以修改JWT中的权限信息，获取更高权限；<br />
                            会话劫持：攻击者可以劫持用户的会话，进行恶意操作；<br />
                            数据泄露：攻击者可以访问敏感数据，造成信息泄露。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】固定JWT验证算法
                            在JWT验证时明确指定允许的签名算法，不要根据JWT header动态选择。<br /><br />
                            【必须】拒绝不支持的算法
                            明确拒绝HS256、none等不安全的算法类型。<br /><br />
                            【建议】使用密钥白名单
                            维护一个允许的密钥列表，只接受预定义的密钥。<br /><br />
                            【建议】算法和密钥分离
                            RSA和HMAC使用不同的密钥，避免密钥重用。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://portswigger.net/web-security/jwt/algorithm-confusion" target="_blank" style="text-decoration: underline;">《JWT算法混淆攻击》</a>：Burp Suite官方对JWT算法混淆漏洞的详细说明。<br />
                            <a href="https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/" target="_blank" style="text-decoration: underline;">《JWT库中的关键漏洞》</a>：了解JWT库中的常见安全漏洞。
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
                            JWT RS256算法基本使用
                            <div>
                                <el-button type="primary" round size="mini" @click="handleDemo">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// RS256 JWT生成 - 使用私钥签名

public static String generateRS256Jwt(Map&lt;String, Object&gt; claims) {
    String jwttoken = Jwts.builder()
            .signWith(SignatureAlgorithm.RS256, rsaKeyPair.getPrivate()) // 使用私钥签名
            .setClaims(claims)
            .setExpiration(new Date(System.currentTimeMillis() + expire))
            .compact();
    return jwttoken;
}

// RS256 JWT验证 - 使用公钥验证
public static Claims parseRS256Jwt(String jwttoken) {
    Claims claims = Jwts.parser()
            .setSigningKey(rsaKeyPair.getPublic()) // 使用公钥验证
            .parseClaimsJws(jwttoken)
            .getBody();
    return claims;
}</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <!-- 漏洞代码 - JWT算法混淆漏洞 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - JWT算法混淆漏洞
                            <div>
                                <el-button type="danger" round size="mini" @click="handleVulnerability">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// 易受算法混淆攻击的JWT验证方法
// 完全按照Burp Suite官方文档的伪代码实现

public static Claims verifyVulnerable(String token, PublicKey publicKey) {
    try {
        // 解析JWT获取header
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new RuntimeException("Invalid JWT format");
        }
        
        // 获取header中的算法类型
        String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
        String algorithm = extractAlgorithm(headerJson);
        
        // 根据算法类型选择验证方式（易受攻击的逻辑）
        if ("RS256".equals(algorithm)) {
            // 使用公钥作为RSA公钥验证
            return Jwts.parser()
                    .setSigningKey(publicKey)
                    .parseClaimsJws(token)
                    .getBody();
        } else if ("HS256".equals(algorithm)) {
            // 危险：使用公钥作为HMAC密钥验证
            // 这就是算法混淆漏洞的核心！
            return Jwts.parser()
                    .setSigningKey(publicKey.getEncoded()) // 将公钥字节作为HMAC密钥
                    .parseClaimsJws(token)
                    .getBody();
        } else {
            throw new RuntimeException("Unsupported algorithm: " + algorithm);
        }
    } catch (Exception e) {
        throw new RuntimeException("JWT verification failed: " + e.getMessage(), e);
    }
}
</code></pre>
                    </div>
                </el-col>
                <!-- 安全代码 - JWT算法混淆漏洞修复 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - JWT算法混淆漏洞修复
                            <div>
                                <el-button type="success" round size="mini" @click="handleSecure">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// 安全的JWT验证方法 - 修复算法混淆漏洞
// 强制校验JWT必须是RS256算法，不允许其他算法

public static Claims verifySecure(String token) {
    try {
        // 解析JWT获取header
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new RuntimeException("Invalid JWT format");
        }
        
        // 获取header中的算法类型
        String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
        String algorithm = extractAlgorithm(headerJson);
        
        // 强制校验算法必须是RS256
        if (!"RS256".equals(algorithm)) {
            throw new RuntimeException("Only RS256 algorithm is allowed, but found: " + algorithm);
        }
        
        // 使用公钥验证RS256签名
        return Jwts.parser()
                .setSigningKey(rsaKeyPair.getPublic())
                .parseClaimsJws(token)
                .getBody();
    } catch (Exception e) {
        throw new RuntimeException("Secure JWT verification failed: " + e.getMessage(), e);
    }
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- RS256学习对话框 -->
        <el-dialog :visible.sync="demoDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleDemoDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT RS256算法基本使用
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
                            <el-button type="primary" @click="handleLogin">登录</el-button>
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
                        <el-button type="primary" @click="verifyJwt" :disabled="!jwtToken">
                            校验RS256 JWT
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

                <!-- 3. JWT结构解析 -->
                <div class="test-section">
                    <h3>3. JWT结构解析 <span style="color: red; font-size: 14px; font-weight: normal;">(查看Header和Payload)</span></h3>
                    <div class="jwt-test-buttons">
                        <el-button type="info" @click="parseJwt" :disabled="!jwtToken">
                            解析JWT结构
                        </el-button>
                    </div>
                    <div v-if="parseResult" class="jwt-input-section">
                        <h4>Header（头部）：</h4>
                        <el-input
                            v-model="parseResult.header"
                            type="textarea"
                            :rows="2"
                            readonly>
                        </el-input>
                    </div>
                    <div v-if="parseResult" class="jwt-input-section">
                        <h4>Payload（载荷）：</h4>
                        <el-input
                            v-model="parseResult.payload"
                            type="textarea"
                            :rows="4"
                            readonly>
                        </el-input>
                    </div>
                </div>

            </div>
        </el-dialog>


        <!-- JWT算法混淆漏洞学习对话框 -->
        <el-dialog :visible.sync="vulnerabilityDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleVulnerabilityDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT算法混淆漏洞测试
            </div>
            <div class="test-container">
                <!-- 攻击步骤说明 -->
                <div class="test-section">
                    <h3>🎯 攻击步骤说明</h3>
                    <el-alert
                        title="JWT算法混淆攻击复现步骤"
                        type="warning"
                        :closable="false"
                        show-icon>
                        <div style="text-align: left; line-height: 1.8;">
                            <p><strong>第1步：</strong> 使用测试账号登录，获取正常的RS256 JWT令牌</p>
                            <p><strong>第2步：</strong> 点击"获取攻击公钥"，获取Base64格式的RSA公钥</p>
                            <p><strong>第3步：</strong> 使用Burp Suite JWT Editor插件：</p>
                            <ul style="margin: 10px 0; padding-left: 20px;">
                                <li>创建新的Symmetric Key</li>
                                <li>将获取的Base64公钥作为HMAC密钥</li>
                                <li>修改JWT header为 <code>{"alg":"HS256"}</code></li>
                                <li>修改payload为其他用户信息（如lisi）</li>
                                <li>使用公钥重新签名JWT</li>
                            </ul>
                            <p><strong>第4步：</strong> 将伪造的JWT发送到"JWT校验测试"接口，验证攻击成功</p>
                            <p style="color: #E6A23C; margin-top: 10px;">
                                <i class="el-icon-warning"></i> 
                                <strong>漏洞原理：</strong>服务器根据JWT header中的alg字段动态选择验证算法，当alg=HS256时，错误地将RSA公钥当作HMAC密钥使用
                            </p>
                        </div>
                    </el-alert>
                </div>

                <!-- 1. 登录部分 -->
                <div class="test-section">
                    <h3>1. 用户登录 <span style="color: red; font-size: 14px; font-weight: normal;">(测试账号: zhangsan/123)</span></h3>
                    <el-form :model="loginForm" :rules="loginRules" ref="vulnerabilityLoginForm" label-width="70px" inline>
                        <el-form-item label="用户名" prop="username">
                            <el-input v-model="loginForm.username" placeholder="请输入用户名" style="width: 150px;"></el-input>
                        </el-form-item>
                        <el-form-item label="密码" prop="password">
                            <el-input v-model="loginForm.password" type="password" placeholder="请输入密码" style="width: 150px;"></el-input>
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" @click="handleVulnerabilityLogin">登录</el-button>
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" @click="getPublicKey">获取公钥</el-button>
                        </el-form-item>
                    </el-form>
                </div>

                <!-- 攻击公钥显示区域 -->
                <div v-if="attackKeyInfo" class="test-section">
                    <div class="jwt-input-section">
                        <h4>攻击公钥（Base64格式）：</h4>
                        <el-input
                            v-model="attackKeyInfo.publicKeyBase64"
                            type="textarea"
                            :rows="4"
                            readonly>
                        </el-input>
                    </div>
                </div>

                <!-- 2. JWT校验测试 -->
                <div class="test-section">
                    <h3>2. JWT校验测试</h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="vulnerabilityJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="primary" @click="verifyVulnerableJwt" :disabled="!vulnerabilityJwtToken">
                            校验JWT
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

                <!-- 3. JWT结构解析 -->
                <div class="test-section">
                    <h3>3. JWT结构解析 <span style="color: red; font-size: 14px; font-weight: normal;">(查看Header和Payload)</span></h3>
                    <div class="jwt-test-buttons">
                        <el-button type="info" @click="parseJwt" :disabled="!jwtToken">
                            解析JWT结构
                        </el-button>
                    </div>
                    <div v-if="parseResult" class="jwt-input-section">
                        <h4>Header（头部）：</h4>
                        <el-input
                            v-model="parseResult.header"
                            type="textarea"
                            :rows="2"
                            readonly>
                        </el-input>
                    </div>
                    <div v-if="parseResult" class="jwt-input-section">
                        <h4>Payload（载荷）：</h4>
                        <el-input
                            v-model="parseResult.payload"
                            type="textarea"
                            :rows="4"
                            readonly>
                        </el-input>
                    </div>
                </div>
            </div>
        </el-dialog>

        <!-- JWT安全验证测试对话框 -->
        <el-dialog :visible.sync="secureDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleSecureDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT安全验证测试
            </div>
            <div class="test-container">
                <!-- 攻击步骤说明 -->
                <div class="test-section">
                    <h3>🎯 安全修复说明</h3>
                    <el-alert
                        title="JWT算法混淆漏洞修复方案"
                        type="success"
                        :closable="false"
                        show-icon>
                        <div style="text-align: left; line-height: 1.8;">
                            <p><strong>修复原理：</strong></p>
                            <ul style="margin: 10px 0; padding-left: 20px;">
                                <li>强制校验JWT header中的alg字段必须是"RS256"</li>
                                <li>如果发现其他算法（如HS256），直接拒绝验证</li>
                                <li>只允许使用RSA公钥验证RS256签名的JWT</li>
                                <li>彻底防止算法混淆攻击</li>
                            </ul>
                            <p style="color: #67C23A; margin-top: 10px;">
                                <i class="el-icon-success"></i> 
                                <strong>测试说明：</strong>现在即使用攻击者使用HS256算法伪造JWT，安全验证接口也会拒绝验证，从而防止算法混淆攻击
                            </p>
                        </div>
                    </el-alert>
                </div>

                <!-- 1. 登录部分 -->
                <div class="test-section">
                    <h3>1. 用户登录 <span style="color: red; font-size: 14px; font-weight: normal;">(测试账号: zhangsan/123)</span></h3>
                    <el-form :model="loginForm" :rules="loginRules" ref="secureLoginForm" label-width="70px" inline>
                        <el-form-item label="用户名" prop="username">
                            <el-input v-model="loginForm.username" placeholder="请输入用户名" style="width: 150px;"></el-input>
                        </el-form-item>
                        <el-form-item label="密码" prop="password">
                            <el-input v-model="loginForm.password" type="password" placeholder="请输入密码" style="width: 150px;"></el-input>
                        </el-form-item>
                        <el-form-item>
                            <el-button type="primary" @click="handleSecureLogin">登录</el-button>
                        </el-form-item>
                    </el-form>
                </div>

                <!-- 攻击公钥显示区域 -->
                <div v-if="attackKeyInfo" class="test-section">
                    <div class="jwt-input-section">
                        <h4>攻击公钥（Base64格式）：</h4>
                        <el-input
                            v-model="attackKeyInfo.publicKeyBase64"
                            type="textarea"
                            :rows="4"
                            readonly>
                        </el-input>
                    </div>
                </div>

                <!-- 2. JWT校验测试 -->
                <div class="test-section">
                    <h3>2. JWT校验测试</h3>
                    <div class="jwt-input-section">
                        <h4>JWT Token：</h4>
                        <el-input
                            v-model="secureJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div class="jwt-test-buttons">
                        <el-button type="success" @click="verifySecureJwt" :disabled="!secureJwtToken">
                            安全校验JWT
                        </el-button>
                    </div>
                    <div v-if="secureVerifyResult" class="result-box">
                        <el-alert
                            :title="secureVerifyResult.success ? '安全校验成功' : '安全校验失败'"
                            :description="secureVerifyResult.message"
                            :type="secureVerifyResult.success ? 'success' : 'error'"
                            show-icon>
                        </el-alert>
                    </div>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { 
    rs256Login, 
    verifyJwt, 
    getPublicKey,
    verifyVulnerableJwt,
    verifySecureJwt
} from '@/api/jwt'

export default {
    data() {
        return {
            activeName: 'first',
            demoDialogVisible: false,
            vulnerabilityDialogVisible: false,
            secureDialogVisible: false,
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
            verifyResult: null,
            parseResult: null,
            attackKeyInfo: null,
            vulnerableVerifyResult: null,
            vulnerabilityJwtToken: '',
            secureJwtToken: '',
            secureVerifyResult: null
        }
    },
    methods: {
        handleClick(tab, event) {
            // 处理标签页点击事件
        },
        handleDemo() {
            this.demoDialogVisible = true
            this.loginForm.username = 'zhangsan'
            this.loginForm.password = '123'
            this.resetDemoData()
        },
        handleVulnerability() {
            this.vulnerabilityDialogVisible = true
            this.loginForm.username = 'zhangsan'
            this.loginForm.password = '123'
            this.resetVulnerabilityData()
        },
        handleSecure() {
            this.secureDialogVisible = true
            this.loginForm.username = 'zhangsan'
            this.loginForm.password = '123'
            this.resetSecureData()
        },
        resetDemoData() {
            this.jwtToken = ''
            this.verifyResult = null
            this.parseResult = null
        },
        resetVulnerabilityData() {
            this.attackKeyInfo = null
            this.vulnerableVerifyResult = null
            this.vulnerabilityJwtToken = ''
        },
        resetSecureData() {
            this.secureJwtToken = ''
            this.secureVerifyResult = null
            this.attackKeyInfo = null
        },
        handleLogin() {
            this.$refs.loginForm.validate((valid) => {
                if (valid) {
                    rs256Login(this.loginForm).then(response => {
                        this.jwtToken = response.data
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('RS256登录成功，JWT已生成')
                    }).catch(error => {
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        handleVulnerabilityLogin() {
            this.$refs.vulnerabilityLoginForm.validate((valid) => {
                if (valid) {
                    rs256Login(this.loginForm).then(response => {
                        // 登录成功后设置JWT
                        this.vulnerabilityJwtToken = response.data
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('RS256登录成功，JWT已生成，现在可以进行算法混淆攻击测试')
                    }).catch(error => {
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        handleSecureLogin() {
            this.$refs.secureLoginForm.validate((valid) => {
                if (valid) {
                    rs256Login(this.loginForm).then(response => {
                        // 登录成功后设置JWT
                        this.secureJwtToken = response.data
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('RS256登录成功，JWT已生成，现在可以进行安全验证测试')
                        // 自动获取攻击公钥
                        this.getPublicKey()
                    }).catch(error => {
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        async verifyJwt() {
            if (!this.jwtToken) {
                this.$message.warning('请先生成JWT')
                return
            }

            try {
                const response = await verifyJwt(this.jwtToken)
                if (response.code === 0) {
                    this.verifyResult = {
                        success: true,
                        message: `JWT验证成功！用户：${response.data.username}，姓名：${response.data.name}`
                    }
                    this.$message.success('JWT验证成功')
                } else {
                    this.verifyResult = {
                        success: false,
                        message: 'JWT验证失败：' + response.msg
                    }
                    this.$message.error('JWT验证失败')
                }
            } catch (error) {
                this.verifyResult = {
                    success: false,
                    message: 'JWT验证失败：' + error.message
                }
                this.$message.error('JWT验证失败: ' + error.message)
            }
        },
        parseJwt() {
            if (!this.jwtToken) {
                this.$message.warning('请先生成JWT')
                return
            }

            try {
                // 前端直接解析JWT结构
                const parts = this.jwtToken.split('.')
                if (parts.length !== 3) {
                    throw new Error('Invalid JWT format')
                }

                // 安全的Base64解码函数，支持UTF-8
                const safeBase64Decode = (str) => {
                    // 添加padding
                    str = str.replace(/-/g, '+').replace(/_/g, '/')
                    while (str.length % 4) {
                        str += '='
                    }
                    // 使用decodeURIComponent处理UTF-8字符
                    return decodeURIComponent(escape(atob(str)))
                }

                // 解析Header
                const header = JSON.parse(safeBase64Decode(parts[0]))
                
                // 解析Payload
                const payload = JSON.parse(safeBase64Decode(parts[1]))

                this.parseResult = {
                    header: JSON.stringify(header, null, 2),
                    payload: JSON.stringify(payload, null, 2)
                }
                this.$message.success('JWT解析成功')
            } catch (error) {
                this.$message.error('JWT解析失败: ' + error.message)
            }
        },
        handleDemoDialogClose() {
            this.resetDemoData()
            localStorage.removeItem('jwt')
        },
        handleVulnerabilityDialogClose() {
            this.resetVulnerabilityData()
            localStorage.removeItem('jwt')
        },
        async getPublicKey() {
            try {
                const response = await getPublicKey()
                if (response.code === 0) {
                    this.attackKeyInfo = response.data
                    this.$message.success('获取攻击公钥成功')
                } else {
                    this.$message.error('获取攻击公钥失败')
                }
            } catch (error) {
                this.$message.error('获取攻击公钥失败: ' + error.message)
            }
        },
        async verifyVulnerableJwt() {
            if (!this.vulnerabilityJwtToken) {
                this.$message.warning('请先生成JWT')
                return
            }

            try {
                const response = await verifyVulnerableJwt(this.vulnerabilityJwtToken)
                if (response.code === 0) {
                    this.verifyResult = {
                        success: true,
                        message: `JWT验证成功！用户：${response.data.username}，姓名：${response.data.name}`
                    }
                    this.$message.success('JWT验证成功')
                } else {
                    this.verifyResult = {
                        success: false,
                        message: 'JWT验证失败：' + response.msg
                    }
                    this.$message.error('JWT验证失败')
                }
            } catch (error) {
                this.verifyResult = {
                    success: false,
                    message: 'JWT验证失败: ' + error.message
                }
                this.$message.error('JWT验证失败: ' + error.message)
            }
        },
        async verifySecureJwt() {
            if (!this.secureJwtToken) {
                this.$message.warning('请先生成JWT')
                return
            }

            try {
                const response = await verifySecureJwt(this.secureJwtToken)
                if (response.code === 0) {
                    this.secureVerifyResult = {
                        success: true,
                        message: `安全JWT验证成功！用户：${response.data.username}，姓名：${response.data.name}`
                    }
                    this.$message.success('安全JWT验证成功')
                } else {
                    this.secureVerifyResult = {
                        success: false,
                        message: '安全JWT验证失败：' + response.msg
                    }
                    this.$message.error('安全JWT验证失败')
                }
            } catch (error) {
                this.secureVerifyResult = {
                    success: false,
                    message: '安全JWT验证失败：' + error.message
                }
                this.$message.error('安全JWT验证失败: ' + error.message)
            }
        },
        handleSecureDialogClose() {
            this.resetSecureData()
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

.result-box {
    margin-top: 15px;
}
</style>
