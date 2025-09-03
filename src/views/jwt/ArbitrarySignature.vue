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
                                <el-button type="success" round size="mini" @click="handleArbitraryLogin">登录测试</el-button>
                                <el-button type="danger" round size="mini" @click="handleArbitraryGetInfo">获取信息</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT接受任意签名漏洞 - 不验证签名或接受任意签名
public class JwtArbitraryUtils {
    private static String signKey = "password";
    private static Long expire = 4320000000L;

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
                                <el-button type="success" round size="mini" @click="handleSecureLogin">登录测试</el-button>
                                <el-button type="success" round size="mini" @click="handleSecureGetInfo">获取信息</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// JWT安全实现 - 严格验证签名
public class JwtSecureUtils {
    private static String signKey = "password";
    private static Long expire = 4320000000L;

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

        <!-- 登录对话框 -->
        <el-dialog title="JWT接受任意签名漏洞登录" :visible.sync="loginDialogVisible" width="400px">
            <el-form :model="loginForm" :rules="loginRules" ref="loginForm" label-width="80px">
                <el-form-item label="用户名" prop="username">
                    <el-input v-model="loginForm.username" placeholder="请输入用户名"></el-input>
                </el-form-item>
                <el-form-item label="密码" prop="password">
                    <el-input v-model="loginForm.password" type="password" placeholder="请输入密码"></el-input>
                </el-form-item>
            </el-form>
            <div slot="footer" class="dialog-footer">
                <el-button @click="loginDialogVisible = false">取 消</el-button>
                <el-button type="primary" @click="submitLogin">确 定</el-button>
            </div>
        </el-dialog>

        <!-- 用户信息对话框 -->
        <el-dialog title="用户信息" :visible.sync="infoDialogVisible" width="500px">
            <div v-if="userInfo">
                <p><strong>用户名：</strong>{{ userInfo.username }}</p>
                <p><strong>姓名：</strong>{{ userInfo.name }}</p>
                <p><strong>JWT Token：</strong>{{ userInfo.jwt }}</p>
            </div>
            <div v-else>
                <p>获取用户信息失败</p>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { jwtArbitraryLogin, jwtArbitraryGetInfo } from '@/api/jwt'

export default {
    data() {
        return {
            activeName: 'first',
            loginDialogVisible: false,
            infoDialogVisible: false,
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
            currentLoginType: '' // 'arbitrary' 或 'secure'
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        handleArbitraryLogin() {
            this.currentLoginType = 'arbitrary'
            this.loginDialogVisible = true
        },
        handleSecureLogin() {
            this.currentLoginType = 'secure'
            this.loginDialogVisible = true
        },
        handleArbitraryGetInfo() {
            jwtArbitraryGetInfo().then(response => {
                this.userInfo = response.data
                this.infoDialogVisible = true
            }).catch(error => {
                this.$message.error('获取用户信息失败：' + error.message)
            })
        },
        handleSecureGetInfo() {
            // 这里应该调用安全版本的API，暂时使用任意签名版本演示
            jwtArbitraryGetInfo().then(response => {
                this.userInfo = response.data
                this.infoDialogVisible = true
            }).catch(error => {
                this.$message.error('获取用户信息失败：' + error.message)
            })
        },
        submitLogin() {
            this.$refs.loginForm.validate((valid) => {
                if (valid) {
                    if (this.currentLoginType === 'arbitrary') {
                        jwtArbitraryLogin(this.loginForm).then(response => {
                            // 存储到localStorage的jwt键中
                            localStorage.setItem('jwt', response.data)
                            this.$message.success('登录成功')
                            this.loginDialogVisible = false
                        }).catch(error => {
                            // 检查错误是否已经在响应拦截器中处理过
                            // 如果error.message是"Error"或"error"，说明是响应拦截器处理的，不需要重复显示
                            if (error.message && error.message !== 'Error' && error.message !== 'error') {
                                this.$message.error('登录失败：' + error.message)
                            }
                        })
                    } else {
                        // 安全版本的登录，暂时使用任意签名版本演示
                        jwtArbitraryLogin(this.loginForm).then(response => {
                            // 存储到localStorage的jwt键中
                            localStorage.setItem('jwt', response.data)
                            this.$message.success('登录成功')
                            this.loginDialogVisible = false
                        }).catch(error => {
                            // 检查错误是否已经在响应拦截器中处理过
                            // 如果error.message是"Error"或"error"，说明是响应拦截器处理的，不需要重复显示
                            if (error.message && error.message !== 'Error' && error.message !== 'error') {
                                this.$message.error('登录失败：' + error.message)
                            }
                        })
                    }
                }
            })
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
</style>
