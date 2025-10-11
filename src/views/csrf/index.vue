<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">CSRF跨站请求伪造漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            CSRF（Cross-Site Request Forgery，跨站请求伪造）是一种网络攻击方式，攻击者诱导用户在已认证的网站上执行非预期的操作。这种攻击利用了Web应用对用户浏览器的信任机制。
                            <br /><br />
                            <span style="color: red;">攻击原理：</span>
                            <br />
                            1. 用户登录目标网站，获得认证Cookie
                            <br />
                            2. 用户访问攻击者控制的恶意网站
                            <br />
                            3. 恶意网站自动向目标网站发送请求
                            <br />
                            4. 浏览器自动携带用户的认证Cookie
                            <br />
                            5. 目标网站误认为这是用户的合法操作
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            CSRF攻击可以造成严重的业务安全风险，包括但不限于：
                            <br /><br />
                            <span style="color: red;">常见攻击场景：</span>
                            <br />
                            • 资金转移：银行转账、支付操作
                            <br />
                            • 账户操作：修改密码、删除账户
                            <br />
                            • 数据篡改：修改个人信息、删除数据
                            <br />
                            • 权限提升：添加管理员权限
                            <br />
                            • 恶意操作：发送垃圾邮件、发布恶意内容
                            <br /><br />
                            <span style="color: red;">影响范围：</span>
                            <br />
                            • 所有依赖Cookie进行身份认证的Web应用
                            <br />
                            • 特别是金融、电商、社交等敏感应用
                            <br />
                            • 影响所有已登录用户
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <span style="color: red;">【必须】CSRF Token验证</span>
                            <br />
                            为每个用户会话生成唯一的CSRF Token，并在所有状态改变操作中验证该Token。
                            <br /><br />
                            <span style="color: red;">【必须】SameSite Cookie属性</span>
                            <br />
                            设置Cookie的SameSite属性为Strict或Lax，防止跨站请求携带Cookie。
                            <br /><br />
                            <span style="color: red;">【建议】验证Referer头</span>
                            <br />
                            检查HTTP Referer头，确保请求来源于可信域名。
                            <br /><br />
                            <span style="color: red;">【建议】双重提交Cookie</span>
                            <br />
                            在Cookie和请求参数中都包含CSRF Token，验证两者是否一致。
                            <br /><br />
                            <span style="color: red;">【建议】自定义HTTP头</span>
                            <br />
                            使用自定义HTTP头传递CSRF Token，避免在URL中暴露。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://owasp.org/www-community/attacks/csrf" target="_blank" style="text-decoration: underline;">《OWASP CSRF攻击防护指南》</a>：权威的CSRF防护最佳实践。<br />
                            <a href="https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Cookies#samesite_cookies" target="_blank" style="text-decoration: underline;">《SameSite Cookie详解》</a>：深入了解SameSite Cookie机制。<br />
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
                            漏洞代码 - CSRF修改密码
                            <div>
                                <el-button type="danger" round size="mini" @click="showVulnerableDialog">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * 修改密码接口 - 存在CSRF漏洞（演示用）
 * 只验证新密码，不验证旧密码，容易被CSRF攻击
 */
@PostMapping("/csrf/changePasswordVuln")
public Result changePasswordVuln(@RequestBody Map&lt;String, String&gt; request, HttpServletRequest httpRequest) {
    String newPassword = request.get("newPassword");
    String token = httpRequest.getHeader("Authorization");
    
    // 验证JWT Token是否存在
    if (token == null || token.trim().isEmpty()) {
        return Result.error("未授权访问");
    }
    
    try {
        // 获取用户ID
        String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        String userId = JwtUtils.parseJwt(cleanToken).get("id").toString();
        
        // 直接修改密码，不验证旧密码 - 存在CSRF漏洞
        boolean success = loginService.changePassword(userId, newPassword);
        
        if (success) {
            log.info("用户ID: {} 密码修改成功（CSRF漏洞演示接口）", userId);
            return Result.success("密码修改成功");
        } else {
            return Result.error("密码修改失败");
        }
    } catch (Exception e) {
        log.error("JWT解析失败", e);
        return Result.error("未授权访问");
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - 校验旧密码（修改密码场景）
                            <div>
                                <el-button type="success" round size="mini" @click="showSecureDialog">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * 修改密码接口 - CSRF防护（演示用）
 * 验证旧密码，防止CSRF攻击
 */
@PostMapping("/csrf/changePasswordSecure")
public Result changePasswordSecure(@RequestBody Map&lt;String, String&gt; request, HttpServletRequest httpRequest) {
    String oldPassword = request.get("oldPassword");
    String newPassword = request.get("newPassword");
    String token = httpRequest.getHeader("Authorization");
    
    // 验证JWT Token是否存在
    if (token == null || token.trim().isEmpty()) {
        return Result.error("未授权访问");
    }
    
    try {
        // 获取用户ID
        String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        String userId = JwtUtils.parseJwt(cleanToken).get("id").toString();
        
        // 验证旧密码
        if (oldPassword == null || oldPassword.trim().isEmpty()) {
            return Result.error("旧密码不能为空");
        }
        
        if (!loginService.verifyOldPassword(userId, oldPassword)) {
            log.warn("用户ID: {} 尝试修改密码，但旧密码验证失败（CSRF防护演示）", userId);
            return Result.error("旧密码错误");
        }
        
        // 修改密码
        boolean success = loginService.changePasswordSecure(userId, oldPassword, newPassword);
        
        if (success) {
            log.info("用户ID: {} 密码修改成功（CSRF防护演示接口）", userId);
            return Result.success("密码修改成功");
        } else {
            return Result.error("密码修改失败");
        }
    } catch (Exception e) {
        log.error("JWT解析失败", e);
        return Result.error("未授权访问");
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - CSRF Token机制防御
                            <div>
                                <el-button type="success" round size="mini" @click="showTokenDialog">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * 生成CSRF Token接口
 * 用于演示CSRF Token机制
 */
@GetMapping("/csrf/generateToken")
public Result generateCsrfToken(HttpServletRequest httpRequest) {
    HttpSession session = httpRequest.getSession();
    
    // 生成唯一的CSRF Token
    String csrfToken = UUID.randomUUID().toString();
    
    // 将Token存储在Session中
    session.setAttribute("CSRF_TOKEN", csrfToken);
    
    log.info("生成CSRF Token: {}", csrfToken);
    
    Map&lt;String, String&gt; data = new HashMap&lt;&gt;();
    data.put("csrfToken", csrfToken);
    
    return Result.success(data);
}

/**
 * 修改密码接口 - CSRF Token防护（演示用）
 * 使用CSRF Token机制防止CSRF攻击
 */
@PostMapping("/csrf/changePasswordWithToken")
public Result changePasswordWithToken(@RequestBody Map&lt;String, String&gt; request, HttpServletRequest httpRequest) {
    String newPassword = request.get("newPassword");
    String csrfToken = request.get("csrfToken");
    String token = httpRequest.getHeader("Authorization");
    
    // 验证JWT Token是否存在
    if (token == null || token.trim().isEmpty()) {
        return Result.error("未授权访问");
    }
    
    try {
        // 验证CSRF Token
        HttpSession session = httpRequest.getSession();
        String sessionToken = (String) session.getAttribute("CSRF_TOKEN");
        
        if (sessionToken == null || !sessionToken.equals(csrfToken)) {
            log.warn("CSRF Token验证失败！Session Token: {}, Request Token: {}", sessionToken, csrfToken);
            return Result.error("CSRF Token验证失败");
        }
        
        // 获取用户ID
        String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
        String userId = JwtUtils.parseJwt(cleanToken).get("id").toString();
        
        // 修改密码
        boolean success = loginService.changePassword(userId, newPassword);
        
        if (success) {
            log.info("用户ID: {} 密码修改成功（CSRF Token防护演示接口）", userId);
            
            // 使用后销毁Token（一次性Token）
            session.removeAttribute("CSRF_TOKEN");
            
            return Result.success("密码修改成功");
        } else {
            return Result.error("密码修改失败");
        }
    } catch (Exception e) {
        log.error("JWT解析失败", e);
        return Result.error("未授权访问");
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 漏洞代码测试对话框 -->
        <el-dialog :visible.sync="vulnerableDialogVisible" width="80%" :show-close="false">
            <div slot="title" class="dialog-title">
                <span>CSRF攻击演示 - 恶意网站</span>
            </div>
            <div class="dialog-content">
                <div class="attack-explanation">
                    <h4>⚠️ CSRF攻击原理说明：</h4>
                    <p>下面的"礼品领取"实际上是一个CSRF攻击演示。当您点击图片时，会：</p>
                    <ol>
                        <li>自动向系统发送修改密码的请求</li>
                        <li>利用您当前的登录状态（JWT Token）</li>
                        <li>在您不知情的情况下修改您的密码</li>
                        <li>这就是典型的CSRF攻击场景</li>
                    </ol>

                    <h4>⚠️ 补充说明</h4>
                    <span style="color: red;">1、因为当前靶场项目的认证会话是JWT而不是Cookie，所以不能像Cookie方式那样通过发送CSRF URL来进行攻击，因此这里仅仅是模拟CSRF的攻击方式和原理演示。</span> <br />
                    <span style="color: red;">2、当你点击图片完成攻击后，你登陆靶场的账号密码会修改为：hacker123</span> 
                </div>
                
                <el-divider></el-divider>
                
                <div class="malicious-site">
                    <h2 style="color: #409EFF; text-align: center; margin-bottom: 20px;">🎁 恭喜您获得免费礼品！</h2>
                    
                    <!-- 诱骗图片 -->
                    <div class="gift-image-container" @click="performCSRFAttack">
                        <img 
                            src="https://img1.baidu.com/it/u=3200425930,2413475553&fm=253&fmt=auto&app=120&f=JPEG?w=800&h=800" 
                            alt="点击领取礼品" 
                            class="gift-image"
                            title="点击图片领取免费礼品"
                        />
                        <div class="gift-overlay">
                            <div class="gift-text">🎁 点击领取礼品</div>
                        </div>
                    </div>
                    
                    <p style="text-align: center; color: #999; margin-top: 20px; font-size: 14px;">
                        * 点击上方图片即可领取您的免费礼品
                    </p>
                </div>
                
                <div v-if="attackResult" class="attack-result">
                    <h4>攻击结果：</h4>
                    <el-alert :title="attackResult" :type="attackResultType" show-icon></el-alert>
                </div>
            </div>
        </el-dialog>

        <!-- 安全代码测试对话框 -->
        <el-dialog :visible.sync="secureDialogVisible" width="80%" :show-close="false">
            <div slot="title" class="dialog-title">
                <span>CSRF防护演示 - 恶意网站</span>
            </div>
            <div class="dialog-content">
                <div class="attack-explanation">
                    <h4>⚠️ CSRF防护原理说明：</h4>
                    <p>下面的"礼品领取"实际上也是一个CSRF攻击演示。但是这次会失败，因为：</p>
                    <ol>
                        <li>服务器要求验证旧密码才能修改密码</li>
                        <li>攻击者无法获取用户的旧密码</li>
                        <li>即使用户点击了恶意图片，攻击也会被阻止</li>
                        <li>这就是校验旧密码的CSRF防护机制</li>
                    </ol>
                    
                    <h4>⚠️ 补充说明</h4>
                    <span style="color: red;">1、因为该项目的认证会话是JWT方式而不是Cookie，所以不能像Cookie方式那样通过发送CSRF URL来进行攻击。这里仅仅是模拟CSRF的攻击方式和原理演示。</span> <br />
                    <span style="color: red;">2、当你点击图片完成攻击后，你会发现攻击失败了，因为缺少旧密码验证</span>
                </div>
                
                <el-divider></el-divider>
                
                <div class="malicious-site">
                    <h2 style="color: #409EFF; text-align: center; margin-bottom: 20px;">🎁 恭喜您获得免费礼品！</h2>
                    
                    <!-- 诱骗图片 -->
                    <div class="gift-image-container" @click="performSecureCSRFAttack">
                        <img 
                            src="https://img1.baidu.com/it/u=3200425930,2413475553&fm=253&fmt=auto&app=120&f=JPEG?w=800&h=800" 
                            alt="点击领取礼品" 
                            class="gift-image"
                            title="点击图片领取免费礼品"
                        />
                        <div class="gift-overlay">
                            <div class="gift-text">🎁 点击领取礼品</div>
                        </div>
                    </div>
                    
                    <p style="text-align: center; color: #999; margin-top: 20px; font-size: 14px;">
                        * 点击上方图片即可领取您的免费礼品
                    </p>
                </div>
                
                <div v-if="protectionResult" class="attack-result">
                    <h4>防护结果：</h4>
                    <el-alert :title="protectionResult" :type="protectionResultType" show-icon></el-alert>
                </div>
            </div>
        </el-dialog>

        <!-- CSRF Token防护测试对话框 -->
        <el-dialog :visible.sync="tokenDialogVisible" width="80%" :show-close="false">
            <div slot="title" class="dialog-title">
                <span>CSRF Token防护演示 - 恶意网站</span>
            </div>
            <div class="dialog-content">
                <div class="attack-explanation">
                    <h4>⚠️ CSRF Token防护原理说明：</h4>
                    <p>CSRF Token是最通用、最彻底的CSRF防护机制。防护原理：</p>
                    <ol>
                        <li>服务器为每个用户会话生成一个唯一的、不可预测的Token</li>
                        <li>前端在发起敏感操作时必须携带这个Token</li>
                        <li>服务器验证Token是否与Session中存储的一致</li>
                        <li>攻击者无法获取或伪造Token，因此攻击失败</li>
                        <li>Token使用后可以销毁，形成一次性Token机制</li>
                    </ol>
                    
                    <h4>⚠️ 补充说明</h4>
                    <span style="color: red;">1、下面演示了CSRF Token的完整流程：获取Token → 模拟攻击</span> <br />
                    <span style="color: red;">2、您会看到，即使点击恶意图片，如果没有正确的Token，攻击也会失败</span> <br />
                    <span style="color: red;">3、如果测试下面提供的”正常修改密码“按钮，会携带正确的Token，密码会被修改为newpassword</span>
                </div>
                
                <el-divider></el-divider>
                
                <div class="token-demo-section">
                    <h3 style="text-align: center; color: #409EFF; margin-bottom: 20px;">🔐 CSRF Token演示</h3>
                    
                    <!-- Token获取区域 -->
                    <div class="token-get-section">
                        <h4>步骤1：页面加载时自动获取CSRF Token</h4>
                        <p>正常情况下，用户访问页面时会自动从服务器获取Token（<font color="red">为了方便用户测试，本对话框打开时已自动获取</font>）</p>
                        <div v-if="csrfToken" class="token-display">
                            <p><strong>✅ CSRF Token已获取:</strong> <code>{{ csrfToken }}</code></p>
                        </div>
                        <div v-else class="token-display" style="background-color: #fff3cd; border-left-color: #ffc107;">
                            <p><strong>⏳ 正在获取CSRF Token...</strong></p>
                        </div>
                    </div>
                    
                    <el-divider></el-divider>
                    
                    <!-- 对比测试区域 -->
                    <div class="comparison-section">
                        <h4 style="color: #409EFF; margin-bottom: 10px;">步骤2：对比测试 - CSRF Token防护效果</h4>
                        
                        <el-row :gutter="20" style="margin-top: 20px;">
                            <!-- 左侧：恶意攻击 -->
                            <el-col :span="12">
                                <div class="test-box attack-box">
                                    <h5 style="color: #f56c6c; text-align: center;">❌ 恶意CSRF攻击（未携带Token）</h5>
                                    <div class="malicious-site">
                                        <h2 style="color: #409EFF; text-align: center; margin-bottom: 15px; font-size: 18px;">🎁 免费礼品</h2>
                                        
                                        <!-- 诱骗图片 -->
                                        <div class="gift-image-container" @click="performTokenCSRFAttack">
                                            <img 
                                                src="https://img1.baidu.com/it/u=3200425930,2413475553&fm=253&fmt=auto&app=120&f=JPEG?w=800&h=800" 
                                                alt="点击领取礼品" 
                                                class="gift-image-small"
                                                title="点击图片领取免费礼品"
                                            />
                                            <div class="gift-overlay">
                                                <div class="gift-text-small">🎁 点击领取</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </el-col>
                            
                            <!-- 右侧：正常请求 -->
                            <el-col :span="12">
                                <div class="test-box normal-box">
                                    <h5 style="color: #67c23a; text-align: center;">✅ 正常请求（携带正确Token）</h5>
                                    <div class="normal-request">
                                        <p style="text-align: center; margin: 20px 0;">
                                            <i class="el-icon-circle-check" style="font-size: 60px; color: #67c23a;"></i>
                                        </p>
                                        <p style="text-align: center; color: #666; margin-bottom: 20px;">
                                            模拟用户正常修改密码<br/>
                                            携带正确的CSRF Token
                                        </p>
                                        <div style="text-align: center;">
                                            <el-button type="success" @click="performNormalRequest" :disabled="!csrfToken">
                                                正常修改密码
                                            </el-button>
                                        </div>
                                    </div>
                                </div>
                            </el-col>
                        </el-row>
                    </div>
                </div>
                
                <div v-if="tokenResult" class="attack-result">
                    <h4>防护结果：</h4>
                    <el-alert :title="tokenResult" :type="tokenResultType" show-icon></el-alert>
                </div>
            </div>
        </el-dialog>

    </div>
</template>

<script>
import { changePasswordVuln, changePasswordSecure, generateCsrfToken, changePasswordWithToken } from '@/api/csrf';

export default {
    data() {
        return {
            activeName: 'first',
            vulnerableDialogVisible: false,
            secureDialogVisible: false,
            tokenDialogVisible: false,
            attackResult: '',
            attackResultType: 'success',
            protectionResult: '',
            protectionResultType: 'success',
            tokenResult: '',
            tokenResultType: 'success',
            csrfToken: ''
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        showVulnerableDialog() {
            this.vulnerableDialogVisible = true;
            this.attackResult = '';
        },
        showSecureDialog() {
            this.secureDialogVisible = true;
            this.protectionResult = '';
        },
        performCSRFAttack() {
            // 模拟CSRF攻击
            const attackData = {
                newPassword: 'hacker123'
            };
            
            changePasswordVuln(attackData)
                .then(response => {
                    this.attackResult = 'CSRF攻击成功！密码已被修改为: hacker123';
                    this.attackResultType = 'error';
                })
                .catch(error => {
                    this.attackResult = 'CSRF攻击失败: ' + (error.message || '未知错误');
                    this.attackResultType = 'warning';
                });
        },
        performSecureCSRFAttack() {
            // 模拟对安全接口的CSRF攻击（不提供旧密码）
            const attackData = {
                newPassword: 'hacker123'
            };
            
            changePasswordSecure(attackData)
                .then(response => {
                    this.protectionResult = 'CSRF攻击成功！这不应该发生，安全机制失效。';
                    this.protectionResultType = 'error';
                })
                .catch(error => {
                    this.protectionResult = 'CSRF攻击被成功阻止！原因：缺少旧密码验证，安全机制有效防护。';
                    this.protectionResultType = 'success';
                });
        },
        showTokenDialog() {
            this.tokenDialogVisible = true;
            this.tokenResult = '';
            this.csrfToken = '';
            // 打开对话框时自动获取CSRF Token（模拟正常页面加载）
            this.getCsrfToken();
        },
        getCsrfToken() {
            generateCsrfToken()
                .then(response => {
                    this.csrfToken = response.data.csrfToken;
                })
                .catch(error => {
                    console.error('CSRF Token获取失败', error);
                });
        },
        performTokenCSRFAttack() {
            // 模拟CSRF攻击（攻击者无法获取正确的Token，完全不携带Token）
            const attackData = {
                newPassword: 'hacker123'
                // 注意：这里不携带csrfToken，模拟CSRF攻击
            };
            
            changePasswordWithToken(attackData)
                .then(response => {
                    this.tokenResult = '❌ CSRF攻击成功！这不应该发生，Token机制失效。';
                    this.tokenResultType = 'error';
                })
                .catch(error => {
                    this.tokenResult = '✅ CSRF攻击被成功阻止！原因：未携带CSRF Token，攻击者无法获取或伪造正确的Token。';
                    this.tokenResultType = 'success';
                });
        },
        performNormalRequest() {
            // 模拟正常请求（使用正确的Token）
            if (!this.csrfToken) {
                this.$message.error('请先获取CSRF Token');
                return;
            }
            
            const normalData = {
                newPassword: 'newpassword',
                csrfToken: this.csrfToken  // 使用正确的Token
            };
            
            changePasswordWithToken(normalData)
                .then(response => {
                    this.tokenResult = `✅ 密码修改成功！新密码为: ${normalData.newPassword}。正确的CSRF Token通过验证，这是正常的用户操作。`;
                    this.tokenResultType = 'success';
                    // 成功后需要重新获取Token（一次性Token）
                    setTimeout(() => {
                        this.getCsrfToken();
                    }, 2000);
                })
                .catch(error => {
                    this.tokenResult = '❌ 密码修改失败：' + (error.message || '未知错误');
                    this.tokenResultType = 'error';
                });
        }
    }
};
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

.dialog-content {
    padding: 20px;
}

.dialog-title {
    text-align: center;
    font-size: 18px;
    font-weight: bold;
    color: #303133;
}

.attack-demo, .protection-demo {
    margin: 20px 0;
    padding: 15px;
    background-color: #f5f7fa;
    border-radius: 5px;
}

.attack-buttons, .protection-buttons {
    margin-top: 15px;
}

.attack-result, .protection-result {
    margin-top: 20px;
}

.protection-form {
    margin: 15px 0;
}

.sql-param {
    color: red;
    font-weight: bold;
}

/* 恶意网站样式 */
.malicious-site {
    text-align: center;
    padding: 20px;
    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    border-radius: 10px;
    margin-bottom: 20px;
}

.gift-image-container {
    position: relative;
    display: inline-block;
    cursor: pointer;
    transition: transform 0.3s ease;
    border-radius: 10px;
    overflow: hidden;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
}

.gift-image-container:hover {
    transform: scale(1.05);
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
}

.gift-image {
    width: 300px;
    height: 300px;
    object-fit: cover;
    display: block;
}

.gift-overlay {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity 0.3s ease;
}

.gift-image-container:hover .gift-overlay {
    opacity: 1;
}

.gift-text {
    color: white;
    font-size: 24px;
    font-weight: bold;
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.8);
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.1); }
    100% { transform: scale(1); }
}

.attack-explanation {
    background-color: #fff3cd;
    border: 1px solid #ffeaa7;
    border-radius: 5px;
    padding: 15px;
    margin-top: 20px;
}

.attack-explanation h4 {
    color: #856404;
    margin-bottom: 10px;
}

.attack-explanation ol {
    color: #856404;
    margin: 10px 0;
}

.attack-explanation p {
    color: #856404;
    margin: 10px 0;
}

.token-demo-section {
    padding: 20px;
    background-color: #f5f7fa;
    border-radius: 10px;
    margin: 20px 0;
}

.token-get-section {
    padding: 15px;
    background-color: #fff;
    border-radius: 5px;
    margin-bottom: 20px;
}

.token-get-section h4 {
    color: #409EFF;
    margin-bottom: 10px;
}

.token-display {
    margin-top: 15px;
    padding: 15px;
    background-color: #f0f9ff;
    border-left: 4px solid #409EFF;
    border-radius: 4px;
}

.token-display code {
    background-color: #e6f7ff;
    padding: 2px 8px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    color: #1890ff;
    word-break: break-all;
}

.comparison-section {
    margin-top: 20px;
}

.test-box {
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.1);
    min-height: 320px;
    display: flex;
    flex-direction: column;
}

.attack-box {
    background: linear-gradient(135deg, #fff5f5 0%, #fff 100%);
    border: 2px solid #f56c6c;
}

.normal-box {
    background: linear-gradient(135deg, #f0f9ff 0%, #fff 100%);
    border: 2px solid #67c23a;
}

.test-box h5 {
    margin-top: 0;
    margin-bottom: 15px;
}

.gift-image-small {
    width: 100%;
    max-width: 150px;
    height: auto;
    cursor: pointer;
    border-radius: 8px;
    transition: transform 0.3s ease;
}

.gift-image-small:hover {
    transform: scale(1.05);
}

.gift-text-small {
    font-size: 14px;
    font-weight: bold;
    color: white;
}

.normal-request {
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: center;
}
</style>
