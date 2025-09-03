<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">JWT安全漏洞 -- JWT存储敏感信息</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            JWT存储敏感信息漏洞是指JWT的payload部分存储了敏感信息，如密码、身份证号、银行卡号等。<span style="color: red;">JWT的payload部分只是Base64编码，不是加密</span>，任何人都可以解码查看其中的内容，因此不应该存储敏感信息。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            JWT存储敏感信息的危害包括：<br /><br />
                            信息泄露：攻击者可以轻易解码JWT获取敏感信息；<br />
                            隐私侵犯：用户的个人隐私信息被暴露；<br />
                            合规风险：违反数据保护法规，如GDPR等；<br />
                            安全风险：敏感信息可能被用于进一步的攻击。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】不在JWT中存储敏感信息
                            JWT的payload部分只存储必要的非敏感信息，如用户ID、角色等。<br /><br />
                            【必须】敏感信息加密存储
                            如果必须存储敏感信息，应该使用强加密算法进行加密。<br /><br />
                            【建议】最小化JWT内容
                            只存储认证和授权所需的最小信息集。<br /><br />
                            【建议】使用JWE
                            对于需要存储敏感信息的场景，考虑使用JWE（JSON Web Encryption）。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://jwt.io/introduction" target="_blank" style="text-decoration: underline;">《JWT介绍》</a>：了解JWT的结构和组成部分。<br />
                            <a href="https://auth0.com/blog/ten-things-you-should-know-about-tokens-and-cookies/" target="_blank" style="text-decoration: underline;">《关于Token和Cookie的十个要点》</a>：JWT安全使用的最佳实践。
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
                            漏洞代码 - JWT存储敏感信息
                            <div>
                                <el-button type="danger" round size="mini" @click="handleSensitiveTest">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT存储敏感信息漏洞 - 在payload中存储敏感信息
public class JwtSensitiveUtils {
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
        Claims claims = Jwts.parser()
                .setSigningKey(signKey)
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
                            安全代码 - JWT不存储敏感信息
                            <div>
                                <el-button type="success" round size="mini" @click="handleSecureTest">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT安全实现 - 只存储必要的非敏感信息
public class JwtSecureUtils {
    private static String signKey = "password";
    private static Long expire = 3600000L; // 1小时

    public static String generateJwt(Map&lt;String, Object&gt; claims) {
        // 只存储必要的非敏感信息
        Map&lt;String, Object&gt; secureClaims = new HashMap&lt;&gt;();
        secureClaims.put("id", claims.get("id"));
        secureClaims.put("username", claims.get("username"));
        secureClaims.put("role", claims.get("role"));
        secureClaims.put("iat", new Date());
        
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(secureClaims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();
        return res;
    }

    public static Claims parseJwt(String jwttoken) {
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

        <!-- JWT存储敏感信息测试对话框 -->
        <el-dialog :visible.sync="sensitiveTestDialogVisible" width="800px" :show-close="true" :close-on-click-modal="true" @close="handleSensitiveDialogClose">
            <div slot="title" style="text-align: center; font-size: 18px;">
                JWT存储敏感信息漏洞测试
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
                            <el-button type="primary" @click="handleSensitiveLogin">登录</el-button>
                        </el-form-item>
                    </el-form>
                </div>

                <!-- 2. JWT解码展示 -->
                <div class="test-section">
                    <h3>2. JWT解码展示</h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="jwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div v-if="decodedJwt" class="result-box">
                        <h4>JWT解码结果：</h4>
                        <div class="jwt-decode-result">
                            <div class="jwt-section">
                                <pre class="json-content">{{ decodedJwt.payload }}</pre>
                            </div>
                        </div>
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

                <!-- 2. JWT解码展示 -->
                <div class="test-section">
                    <h3>2. JWT解码展示</h3>
                    <div class="jwt-input-section">
                        <el-input
                            v-model="secureJwtToken"
                            type="textarea"
                            :rows="3"
                            placeholder="JWT Token将在这里显示"
                            readonly>
                        </el-input>
                    </div>
                    <div v-if="secureDecodedJwt" class="result-box">
                        <h4>JWT解码结果：</h4>
                        <div class="jwt-decode-result">
                            <div class="jwt-section">
                                <pre class="json-content">{{ secureDecodedJwt.payload }}</pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { jwtSensitiveVulnLogin, jwtSensitiveSecLogin } from '@/api/jwt'
import { Base64 } from 'js-base64'

export default {
    data() {
        return {
            activeName: 'first',
            sensitiveTestDialogVisible: false,
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
            userInfo: null,
            decodedJwt: '',
            secureDecodedJwt: '',
            jwtToken: '',
            secureJwtToken: ''
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        handleSensitiveTest() {
            this.sensitiveTestDialogVisible = true
            this.loginForm.username = 'zhangsan'
            this.loginForm.password = '123'
            this.jwtToken = ''
            this.decodedJwt = ''
        },
        handleSecureTest() {
            this.secureTestDialogVisible = true
            this.loginForm.username = 'zhangsan'
            this.loginForm.password = '123'
            this.secureJwtToken = ''
            this.secureDecodedJwt = ''
        },
        handleSensitiveLogin() {
            this.$refs.loginForm.validate((valid) => {
                if (valid) {
                    jwtSensitiveVulnLogin(this.loginForm).then(response => {
                        this.jwtToken = response.data
                        // 存储到localStorage的jwt键中
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                        // 自动解码JWT
                        this.handleDecodeJwt()
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
                    jwtSensitiveSecLogin(this.loginForm).then(response => {
                        this.secureJwtToken = response.data
                        // 存储到localStorage的jwt键中
                        localStorage.setItem('jwt', response.data)
                        this.$message.success('登录成功，JWT已生成')
                        // 自动解码JWT
                        this.handleSecureDecodeJwt()
                    }).catch(error => {
                        // 检查错误是否已经在响应拦截器中处理过
                        if (error.message && error.message !== 'Error' && error.message !== 'error') {
                            this.$message.error('登录失败：' + error.message)
                        }
                    })
                }
            })
        },
        handleDecodeJwt() {
            try {
                const parts = this.jwtToken.split('.')
                if (parts.length === 3) {
                    const payload = JSON.parse(Base64.decode(parts[1]))
                    this.decodedJwt = {
                        payload: JSON.stringify(payload, null, 2)
                    }
                }
            } catch (error) {
                this.decodedJwt = {
                    payload: 'JWT解码失败：' + error.message
                }
            }
        },
        handleSecureDecodeJwt() {
            try {
                const parts = this.secureJwtToken.split('.')
                if (parts.length === 3) {
                    const payload = JSON.parse(Base64.decode(parts[1]))
                    this.secureDecodedJwt = {
                        payload: JSON.stringify(payload, null, 2)
                    }
                }
            } catch (error) {
                this.secureDecodedJwt = {
                    payload: 'JWT解码失败：' + error.message
                }
            }
        },
        handleSensitiveDialogClose() {
            this.jwtToken = ''
            this.decodedJwt = ''
            // 关闭对话框时清除localStorage中的jwt
            localStorage.removeItem('jwt')
        },
        handleSecureDialogClose() {
            this.secureJwtToken = ''
            this.secureDecodedJwt = ''
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

.result-box {
    margin-top: 15px;
}

.jwt-decode-result {
    margin-top: 15px;
}

.jwt-section {
    margin-bottom: 20px;
}

.jwt-section h5 {
    margin: 0 0 10px 0;
    color: #409EFF;
    font-size: 14px;
    font-weight: bold;
}

.json-content {
    background-color: #f5f7fa;
    border: 1px solid #e4e7ed;
    border-radius: 4px;
    padding: 15px;
    margin: 0;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 12px;
    line-height: 1.5;
    color: #303133;
    white-space: pre-wrap;
    word-wrap: break-word;
    max-height: 300px;
    overflow-y: auto;
}
</style>
