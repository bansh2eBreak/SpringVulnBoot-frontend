<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">其他漏洞 -- LDAP 注入漏洞</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              LDAP 注入是一种注入攻击，当应用程序将用户输入直接拼接到 LDAP 查询语句中时，攻击者可以通过特殊字符（如 <code>*</code>、<code>(</code>、<code>)</code>、<code>&</code> 等）改变查询逻辑，从而绕过身份认证或泄露敏感信息。<br/>
              <br/>
              <strong>LDAP 过滤器语法：</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 基础过滤器：<code>(uid=admin)</code> 精确匹配，<code>(uid=*admin*)</code> 通配符匹配<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 逻辑运算：<code>(&(uid=admin)(cn=*))</code> AND逻辑，<code>(|(uid=admin)(uid=guest))</code> OR逻辑<br/>
              <br/>
              <strong>核心漏洞原理：LDAP 过滤器注入</strong><br/>
              <br/>
              <strong>1. 正常登录查询：</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 输入：<code>{"username":"admin", "password":"admin123"}</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 拼接代码：<code>String filter = "(&(uid=" + username + ")(userPassword=" + password + "))"</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 实际查询：<code>(&(uid=admin)(userPassword=admin123))</code><br/>
              <br/>
              <strong>2. 注入攻击：</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 输入：<code>{"username":"admin)(uid=*))(&(uid=*", "password":"anything"}</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 拼接代码：<code>String filter = "(&(uid=" + username + ")(userPassword=" + password + "))"</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 实际查询：<code>(&(uid=admin)(uid=*))(&(uid=*)(userPassword=anything))</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• <span style="color: #f56c6c;"><strong>结果：绕过密码验证，直接登录成功！</strong></span><br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              <strong>1. 身份认证绕过</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 攻击者无需知道密码即可登录任意账户<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 特别是管理员账户，危害巨大<br/>
              <br/>
              <strong>2. 信息泄露</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 通过通配符（如 <code>*</code>）枚举所有用户<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 泄露用户名、邮箱、部门等敏感信息<br/>
              <br/>
              <strong>3. 权限提升</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 登录管理员账户后获取系统最高权限<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 可能导致整个系统被控制<br/>
              <br/>
              <strong>4. 攻击成本低</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 只需构造简单的注入 Payload<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 难以通过 WAF 拦截（看起来是正常字符）<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <strong>【必须】使用参数化查询</strong><br/>
              使用 Spring LDAP 的 Filter API，自动转义特殊字符。<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 示例：<code>AndFilter filter = new AndFilter();</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 添加条件：<code>filter.and(new EqualsFilter("uid", username));</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 自动转义：<code>String safeFilter = filter.encode();</code><br/>
              <br/>
              <strong>【建议】手动转义特殊字符</strong><br/>
              如果无法使用 Filter API，需手动转义 LDAP 特殊字符：<code>\</code>、<code>*</code>、<code>(</code>、<code>)</code>、<code>\0</code><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 转义规则：<code>* → \2a</code>，<code>( → \28</code>，<code>) → \29</code>，<code>\ → \5c</code><br/>
              <br/>
              <strong>【建议】输入验证和白名单</strong><br/>
              限制输入字符范围，只允许字母、数字、下划线等安全字符。<br/>
              <br/>
              <strong>【建议】最小权限原则</strong><br/>
              限制 LDAP 查询账号的权限，避免查询敏感信息。<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <strong>相关技术文档和参考资源：</strong>
              <br/><br/>
              <strong>官方文档：</strong>
              <ul>
                <li><a href="https://docs.spring.io/spring-ldap/docs/current/reference/" target="_blank" style="text-decoration: underline;">Spring LDAP 官方文档</a></li>
                <li><a href="https://ldap.com/ldap-filters/" target="_blank" style="text-decoration: underline;">LDAP 过滤器语法参考</a></li>
              </ul>
              <br/>
              <strong>安全最佳实践：</strong>
              <ul>
                <li><a href="https://owasp.org/www-community/attacks/LDAP_Injection" target="_blank" style="text-decoration: underline;">OWASP LDAP 注入攻击</a></li>
                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP LDAP 注入防御清单</a></li>
              </ul>
              <br/>
              <strong>漏洞分析文章：</strong>
              <ul>
                <li><a href="https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf" target="_blank" style="text-decoration: underline;">LDAP 注入与盲注技术</a></li>
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
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - 直接拼接用户输入
              <el-button type="danger" round size="mini" @click="testVuln">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@PostMapping("/vuln/login")
public Result vulnerableLogin(@RequestBody LdapLoginRequest request) {
    String username = request.getUsername();
    String password = request.getPassword();
    
    // ❌ 危险：直接拼接用户输入到 LDAP 过滤器
    String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
    
    log.warn("LDAP 过滤器: {}", filter);
    
    // 执行 LDAP 查询
    List&lt;Map&lt;String, String&gt;&gt; users = ldapTemplate.search(
        "ou=users", filter, 
        attrs -&gt; {
            Map&lt;String, String&gt; user = new HashMap&lt;&gt;();
            user.put("uid", getAttributeValue(attrs, "uid"));
            user.put("cn", getAttributeValue(attrs, "cn"));
            user.put("mail", getAttributeValue(attrs, "mail"));
            return user;
        }
    );
    
    if (!users.isEmpty()) {
        return Result.success(responseData); // 包含用户信息和执行的过滤器
    } else {
        return Result.error(responseData);
    }
}

// 攻击 Payload 1（绕过认证）：
// POST Body: {"username":"admin)(uid=*))(&(uid=*","password":"anything"}
// 实际查询：(&(uid=admin)(uid=*))(&(uid=*)(userPassword=anything))
// 结果：绕过密码验证，登录成功！

// 攻击 Payload 2（通配符）：
// POST Body: {"username":"*","password":"*"}
// 实际查询：(&(uid=*)(userPassword=*))
// 结果：匹配所有用户，登录第一个找到的用户</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 使用参数化查询
              <el-button type="success" round size="mini" @click="testSafe">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@PostMapping("/safe/login")
public Result safeLogin(@RequestBody LdapLoginRequest request) {
    String username = request.getUsername();
    String password = request.getPassword();
    
    // ✅ 安全：使用 Spring LDAP 的 Filter API
    AndFilter filter = new AndFilter();
    filter.and(new EqualsFilter("uid", username));
    filter.and(new EqualsFilter("userPassword", password));
    
    // 执行 LDAP 查询（自动转义特殊字符）
    List&lt;Map&lt;String, String&gt;&gt; users = ldapTemplate.search(
        "ou=users", filter.encode(),
        attrs -&gt; {
            Map&lt;String, String&gt; user = new HashMap&lt;&gt;();
            user.put("uid", getAttributeValue(attrs, "uid"));
            user.put("cn", getAttributeValue(attrs, "cn"));
            user.put("mail", getAttributeValue(attrs, "mail"));
            return user;
        }
    );
    
    if (!users.isEmpty()) {
        return Result.success(responseData);
    } else {
        return Result.error(responseData);
    }
}

// 测试攻击 Payload：
// POST Body: {"username":"admin)(uid=*))(&(uid=*","password":"anything"}
// 自动转义为：admin\29\28uid=\2a\29\29\28&\28uid=\2a
// 结果：无法匹配任何用户，注入失败！</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>
    
    
    <!-- 漏洞代码测试对话框 -->
    <el-dialog :visible.sync="vulnDialogVisible" width="55%" class="test-dialog" @close="resetVulnForm">
      <div slot="title" style="text-align: center; font-size: 18px;">
        LDAP 注入漏洞代码测试
      </div>
      <div class="dialog-content">
        <div class="test-info">
          <h4>⚠️ 测试说明：</h4>
          <p>此测试将向后端发送<b>恶意构造的 LDAP 过滤器</b>，尝试绕过身份认证。</p>
          <br/>
          <h4>💡 攻击原理：</h4>
          <p><b>正常登录：</b><code>(&(uid=admin)(userPassword=admin123))</code></p>
          <p><b>注入攻击：</b><code>(&(uid=admin)(uid=*))(&(uid=*)(userPassword=anything))</code></p>
          <p>通过注入 <code>)(uid=*))(&(uid=*</code>，关闭了密码检查，直接通过认证！</p>
          <br/>
          <h4>📋 测试账号（正常登录）：</h4>
          <ul style="list-style: none; padding: 0;">
            <li>• 用户名: <code>admin</code>, 密码: <code>admin123</code></li>
            <li>• 用户名: <code>zhangsan</code>, 密码: <code>zhangsan123</code></li>
            <li>• 用户名: <code>finance</code>, 密码: <code>finance123</code></li>
          </ul>
        </div>
        
        <el-form :model="vulnForm" label-width="120px">
          <el-form-item label="攻击Payload:">
            <el-select v-model="vulnForm.payloadType" placeholder="选择预设payload" @change="updateVulnPayload" style="width: 100%;">
              <el-option label="正常登录（admin/admin123）" value="normal"></el-option>
              <el-option label="⚠️ 绕过认证（闭合注入）" value="bypass"></el-option>
              <el-option label="⚠️ 通配符注入（匹配所有）" value="wildcard"></el-option>
              <el-option label="自定义输入" value="custom"></el-option>
            </el-select>
          </el-form-item>
          <el-form-item label="用户名:">
            <el-input
              v-model="vulnForm.username"
              placeholder="输入用户名"
            ></el-input>
          </el-form-item>
          <el-form-item label="密码:">
            <el-input
              v-model="vulnForm.password"
              type="password"
              placeholder="输入密码"
              show-password
            ></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="danger" @click="testVulnCode" :loading="vulnLoading">
              <i class="el-icon-warning"></i> 发起攻击测试
            </el-button>
            <el-button @click="clearVulnResult">清空结果</el-button>
          </el-form-item>
        </el-form>
        
        <div class="test-result" v-if="vulnResult">
          <h4>测试结果：</h4>
          <el-alert
            :title="vulnResult.title"
            :type="vulnResult.type"
            :description="vulnResult.description"
            show-icon
            :closable="false">
          </el-alert>
        </div>
      </div>
    </el-dialog>

    <!-- 安全代码测试对话框 -->
    <el-dialog :visible.sync="safeDialogVisible" width="55%" class="test-dialog" @close="resetSafeForm">
      <div slot="title" style="text-align: center; font-size: 18px;">
        LDAP 注入安全代码测试
      </div>
      <div class="dialog-content">
        <div class="test-info">
          <h4>✅ 测试说明：</h4>
          <p>此测试使用添加了参数化查询的安全代码，会自动转义所有特殊字符。</p>
          <p>你可以尝试输入注入 Payload，观察安全代码如何进行防护。</p>
          <br/>
          <h4>📋 测试账号：</h4>
          <ul style="list-style: none; padding: 0;">
            <li>• 用户名: <code>admin</code>, 密码: <code>admin123</code></li>
            <li>• 用户名: <code>zhangsan</code>, 密码: <code>zhangsan123</code></li>
          </ul>
        </div>
        
        <el-form :model="safeForm" label-width="120px">
          <el-form-item label="测试Payload:">
            <el-select v-model="safeForm.payloadType" placeholder="选择测试payload" @change="updateSafePayload" style="width: 100%;">
              <el-option label="正常登录（admin/admin123）" value="normal"></el-option>
              <el-option label="错误密码测试" value="wrong_password"></el-option>
              <el-option label="尝试注入攻击（会被拦截）" value="attack"></el-option>
            </el-select>
          </el-form-item>
          <el-form-item label="用户名:">
            <el-input
              v-model="safeForm.username"
              placeholder="输入用户名"
            ></el-input>
          </el-form-item>
          <el-form-item label="密码:">
            <el-input
              v-model="safeForm.password"
              type="password"
              placeholder="输入密码"
              show-password
            ></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="success" @click="testSafeCode" :loading="safeLoading">
              <i class="el-icon-success"></i> 安全测试
            </el-button>
            <el-button @click="clearSafeResult">清空结果</el-button>
          </el-form-item>
        </el-form>
        
        <div class="test-result" v-if="safeResult">
          <h4>测试结果：</h4>
          <el-alert
            :title="safeResult.title"
            :type="safeResult.type"
            :description="safeResult.description"
            show-icon
            :closable="false">
          </el-alert>
        </div>
      </div>
    </el-dialog>
    
  </div>
</template>

<script>
import { ldapVulnLogin, ldapSafeLogin } from '@/api/ldapInjection'

export default {
  name: 'LdapInjection',
  data() {
    return {
      activeName: 'first',
      // 漏洞代码测试对话框
      vulnDialogVisible: false,
      vulnForm: {
        payloadType: 'normal',
        username: 'admin',
        password: 'admin123'
      },
      vulnLoading: false,
      vulnResult: null,
      // 安全代码测试对话框
      safeDialogVisible: false,
      safeForm: {
        payloadType: 'normal',
        username: 'admin',
        password: 'admin123'
      },
      safeLoading: false,
      safeResult: null
    }
  },
  methods: {
    handleClick(tab, event) {},
    
    // 打开漏洞代码测试对话框
    testVuln() {
      this.vulnDialogVisible = true
    },
    
    // 打开安全代码测试对话框
    testSafe() {
      this.safeDialogVisible = true
    },
    
    // 更新漏洞测试payload
    updateVulnPayload(type) {
      const payloads = {
        'normal': { username: 'admin', password: 'admin123' },
        'bypass': { username: 'admin)(uid=*))(&(uid=*', password: 'anything' },
        'wildcard': { username: '*', password: '*' },
        'custom': { username: '', password: '' }
      }
      if (payloads[type]) {
        this.vulnForm.username = payloads[type].username
        this.vulnForm.password = payloads[type].password
      }
    },
    
    // 更新安全测试payload
    updateSafePayload(type) {
      const payloads = {
        'normal': { username: 'admin', password: 'admin123' },
        'wrong_password': { username: 'admin', password: 'wrongpassword' },
        'attack': { username: 'admin)(uid=*))(&(uid=*', password: 'anything' }
      }
      if (payloads[type]) {
        this.safeForm.username = payloads[type].username
        this.safeForm.password = payloads[type].password
      }
    },
    
    // 测试漏洞代码
    async testVulnCode() {
      if (!this.vulnForm.username || !this.vulnForm.password) {
        this.$message.warning('请输入用户名和密码')
        return
      }
      
      this.vulnLoading = true
      this.vulnResult = null
      
      try {
        const response = await ldapVulnLogin(this.vulnForm)
        
        if (response.code === 0 && response.data.success) {
          const user = response.data.user
          this.vulnResult = {
            title: '漏洞代码执行结果 - 登录成功！ ⚠️',
            type: 'warning',
            description: `用户：${user.cn} (${user.uid})\n邮箱：${user.mail}\n执行的过滤器：${response.data.filter}\n匹配用户数：${response.data.matchedCount}`
          }
        } else if (response.code === 0) {
          this.vulnResult = {
            title: '漏洞代码执行结果 - 登录失败',
            type: 'info',
            description: `${response.data.message}\n执行的过滤器：${response.data.filter}`
          }
        } else {
          this.vulnResult = {
            title: '漏洞代码执行异常',
            type: 'error',
            description: response.msg || '执行失败'
          }
        }
      } catch (error) {
        this.vulnResult = {
          title: '漏洞代码测试异常',
          type: 'error',
          description: '请求失败: ' + (error.message || '未知错误')
        }
      } finally {
        this.vulnLoading = false
      }
    },
    
    // 测试安全代码
    async testSafeCode() {
      if (!this.safeForm.username || !this.safeForm.password) {
        this.$message.warning('请输入用户名和密码')
        return
      }
      
      this.safeLoading = true
      this.safeResult = null
      
      try {
        const response = await ldapSafeLogin(this.safeForm)
        
        if (response.code === 0 && response.data.success) {
          const user = response.data.user
          this.safeResult = {
            title: '安全代码执行成功 - 登录成功！ ✅',
            type: 'success',
            description: `用户：${user.cn} (${user.uid})\n邮箱：${user.mail}`
          }
        } else if (response.code === 0) {
          this.safeResult = {
            title: '安全代码执行结果 - 登录失败',
            type: 'info',
            description: response.data.message
          }
        } else {
          this.safeResult = {
            title: '安全验证拦截 🛡️',
            type: 'warning',
            description: response.msg || '输入被拒绝'
          }
        }
      } catch (error) {
        this.safeResult = {
          title: '安全代码测试异常',
          type: 'error',
          description: '请求失败: ' + (error.message || '未知错误')
        }
      } finally {
        this.safeLoading = false
      }
    },
    
    // 清空漏洞代码测试结果
    clearVulnResult() {
      this.vulnResult = null
    },
    
    // 清空安全代码测试结果
    clearSafeResult() {
      this.safeResult = null
    },
    
    // 重置漏洞代码测试表单
    resetVulnForm() {
      this.vulnForm.payloadType = 'normal'
      this.vulnForm.username = 'admin'
      this.vulnForm.password = 'admin123'
      this.vulnResult = null
    },
    
    // 重置安全代码测试表单
    resetSafeForm() {
      this.safeForm.payloadType = 'normal'
      this.safeForm.username = 'admin'
      this.safeForm.password = 'admin123'
      this.safeResult = null
    }
  }
}
</script>

<style scoped>
.vuln-info {
  border-radius: 10px;
  margin-left: 20px;
  margin-right: 20px;
  margin-bottom: 20px;
  margin-top: 10px;
}

.vuln-detail {
    background-color: #dce9f8;
    padding: 10px;
    line-height: 1.8;
}

.vuln-detail code {
    background-color: #f0f0f0;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    color: #e74c3c;
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

/* 测试对话框样式 */
.test-dialog >>> .el-dialog__body {
  padding: 20px;
}

.dialog-content {
  line-height: 1.6;
}

.test-info {
  background-color: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  margin-bottom: 20px;
  border-left: 4px solid #409EFF;
}

.test-info h4 {
  color: #409EFF;
  margin: 0 0 10px 0;
  font-size: 14px;
}

.test-info p {
  margin: 5px 0;
  color: #606266;
  font-size: 13px;
}

.test-info code {
  background-color: #e6f7ff;
  color: #1890ff;
  padding: 2px 4px;
  border-radius: 3px;
  font-family: 'Courier New', monospace;
}

.test-result {
  margin-top: 20px;
}

.test-result h4 {
  color: #409EFF;
  margin: 0 0 10px 0;
  font-size: 14px;
}
</style>
