<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">XPath注入漏洞</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              XPath注入（XPath Injection）是一种类似于SQL注入的攻击方式，发生在应用程序使用用户输入直接构造XPath查询时。XPath是用于在XML文档中定位节点的查询语言，当用户输入未经过滤直接拼接到XPath表达式时，攻击者可以构造恶意XPath查询来绕过身份验证、提取敏感数据、进行权限提升等。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 身份验证绕过：通过构造恶意XPath表达式绕过登录验证，如使用 'or '1'='1' 等技巧<br/>
              2. 敏感数据泄露：可以提取XML文档中的所有数据，包括密码、个人信息等<br/>
              3. 权限提升：通过修改XPath查询逻辑，访问未授权的数据<br/>
              4. 数据篡改：某些XPath实现支持更新操作，可能导致数据被修改<br/>
              5. 影响范围：所有使用XPath查询XML数据的应用，特别是基于XML的用户认证系统
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】使用参数化查询（如果XPath实现支持）<br/>
              1. 避免直接拼接用户输入到XPath表达式<br/>
              2. 使用XPath变量绑定机制（如果可用）<br/>
              <br/>
              【必须】输入验证和转义<br/>
              1. 验证用户输入，拒绝包含特殊字符（'、"、=、or、and、|等）的输入<br/>
              2. 对单引号和双引号进行转义处理<br/>
              3. 使用白名单验证输入格式<br/>
              <br/>
              【建议】最小权限原则<br/>
              1. 限制XPath查询范围，只允许查询必要的字段<br/>
              2. 避免在XPath中暴露敏感信息（如密码）<br/>
              3. 使用安全的XML解析库
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-community/vulnerabilities/XPATH_Injection" target="_blank" style="text-decoration: underline;">《OWASP XPath注入漏洞详解》</a><br/>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《XML安全防护速查表》</a><br/>
              <a href="https://portswigger.net/web-security/xpath-injection" target="_blank" style="text-decoration: underline;">《PortSwigger XPath注入教程》</a>
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
              漏洞代码 - 登录验证XPath注入
              <el-button type="danger" round size="mini" @click="showLoginVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * XPath注入漏洞 - 登录验证（漏洞代码）
 * 直接拼接用户输入到XPath表达式，存在XPath注入漏洞
 */
@PostMapping("/login/vuln")
public Result xpathLoginVulnerable(@RequestBody Map&lt;String, String&gt; request) {
    String username = request.get("username");
    String password = request.get("password");
    
    if (username == null || password == null) {
        return Result.error("用户名和密码不能为空");
    }
    
    try {
        // 危险：直接拼接用户输入到XPath表达式
        String xpathExpression = "//user[username='" + username + 
                                 "' and password='" + password + "']";
        
        // 解析XML文档
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(USERS_XML)));
        
        // 执行XPath查询
        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath = xPathFactory.newXPath();
        XPathExpression expr = xpath.compile(xpathExpression);
        NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        
        if (nodes != null && nodes.getLength() > 0) {
            // 收集所有匹配的用户信息
            // ...
            return Result.success("登录成功！用户信息: " + userInfo.toString());
        } else {
            return Result.error("用户名或密码错误");
        }
    } catch (Exception e) {
        return Result.error("登录失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 输入验证和转义
              <el-button type="success" round size="mini" @click="showLoginSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * XPath注入漏洞 - 登录验证（安全代码）
 * 使用输入验证和转义，防止XPath注入
 */
@PostMapping("/login/sec")
public Result xpathLoginSecure(@RequestBody Map&lt;String, String&gt; request) {
    String username = request.get("username");
    String password = request.get("password");
    
    if (username == null || password == null) {
        return Result.error("用户名和密码不能为空");
    }
    
    try {
        // 安全：验证输入，防止特殊字符注入
        if (Security.checkXPath(username) || Security.checkXPath(password)) {
            return Result.error("输入包含非法字符，拒绝登录");
        }
        
        // 安全：使用转义后的值构建XPath
        String escapedUsername = Security.escapeXPath(username);
        String escapedPassword = Security.escapeXPath(password);
        
        String xpathExpression = "//user[username='" + escapedUsername + 
                                 "' and password='" + escapedPassword + "']";
        
        // 解析XML文档
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(USERS_XML)));
        
        // 执行XPath查询
        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath = xPathFactory.newXPath();
        XPathExpression expr = xpath.compile(xpathExpression);
        NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        
        if (nodes != null && nodes.getLength() > 0) {
            return Result.success("登录成功！用户信息: " + userInfo.toString());
        } else {
            return Result.error("用户名或密码错误");
        }
    } catch (Exception e) {
        return Result.error("登录失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 登录验证漏洞测试对话框 -->
    <el-dialog title="XPath注入漏洞测试 - 登录验证" :visible.sync="loginVulnDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，以下是一些常见的XPath注入攻击payload：<br>
        1. 正常登录（admin/admin123）<br>
        2. XPath注入绕过：用户名使用 admin' or '1'='1' --<br>
        3. XPath注入绕过：用户名使用 ' or 1=1 or '（数字比较，永远为真，会匹配所有用户）
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="loginVulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateLoginVulnPayload" style="width: 100%">
            <el-option label="【正常】admin/admin123" value="normal"></el-option>
            <el-option label="【攻击】XPath注入绕过 - admin' or '1'='1'" value="bypass2"></el-option>
            <el-option label="【攻击】XPath注入绕过 - ' or 1=1 or '（获取所有用户）" value="union"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="loginVulnForm.username" placeholder="请输入用户名"></el-input>
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="loginVulnForm.password" type="password" placeholder="请输入密码" show-password></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testLoginVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="loginVulnForm.result" class="result-display">
        <h4>登录结果：</h4>
        <div class="result-text">
          <pre>{{ loginVulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- 登录验证安全代码测试对话框 -->
    <el-dialog title="XPath注入安全防护测试 - 登录验证" :visible.sync="loginSecDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: green; font-style: italic;">
        安全代码已实现输入验证和转义，以下攻击payload将被拦截：<br>
        测试相同的payload，观察安全机制如何阻止XPath注入攻击。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="loginSecForm.selectedPayload" placeholder="请选择测试Payload" @change="updateLoginSecPayload" style="width: 100%">
            <el-option label="【正常】admin/admin123 - 应该成功" value="normal"></el-option>
            <el-option label="XPath注入绕过 - 应该被拦截" value="bypass2"></el-option>
            <el-option label="XPath注入绕过 - 应该被拦截" value="union"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="loginSecForm.username" placeholder="请输入用户名"></el-input>
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="loginSecForm.password" type="password" placeholder="请输入密码" show-password></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testLoginSecure">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="loginSecForm.result" class="result-display">
        <h4>登录结果：</h4>
        <div class="result-text">
          <pre>{{ loginSecForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

  </div>
</template>

<script>
import { xpathLoginVulnerable, xpathLoginSecure } from '@/api/xml'

export default {
  data() {
    return {
      activeName: 'first',
      // 登录验证漏洞
      loginVulnDialogVisible: false,
      loginSecDialogVisible: false,
      loginVulnForm: {
        selectedPayload: '',
        username: '',
        password: '',
        result: ''
      },
      loginSecForm: {
        selectedPayload: '',
        username: '',
        password: '',
        result: ''
      },
    }
  },
  methods: {
    handleClick(tab, event) {
      // Tab切换处理
    },
    // ==================== 登录验证方法 ====================
    showLoginVulnDialog() {
      this.loginVulnDialogVisible = true
      this.loginVulnForm.selectedPayload = ''
      this.loginVulnForm.username = ''
      this.loginVulnForm.password = ''
      this.loginVulnForm.result = ''
    },
    showLoginSecDialog() {
      this.loginSecDialogVisible = true
      this.loginSecForm.selectedPayload = ''
      this.loginSecForm.username = ''
      this.loginSecForm.password = ''
      this.loginSecForm.result = ''
    },
    updateLoginVulnPayload() {
      const payloads = this.getLoginPayloads()
      const payload = payloads[this.loginVulnForm.selectedPayload]
      if (payload) {
        this.loginVulnForm.username = payload.username
        this.loginVulnForm.password = payload.password
      }
    },
    updateLoginSecPayload() {
      const payloads = this.getLoginPayloads()
      const payload = payloads[this.loginSecForm.selectedPayload]
      if (payload) {
        this.loginSecForm.username = payload.username
        this.loginSecForm.password = payload.password
      }
    },
    testLoginVulnerable() {
      if (!this.loginVulnForm.username || !this.loginVulnForm.password) {
        this.$message.warning('请输入用户名和密码')
        return
      }
      
      xpathLoginVulnerable({
        username: this.loginVulnForm.username,
        password: this.loginVulnForm.password
      })
        .then(response => {
          this.loginVulnForm.result = response.data
        })
        .catch(error => {
          this.loginVulnForm.result = '登录失败: ' + (error.msg || error.message || '未知错误')
        })
    },
    testLoginSecure() {
      if (!this.loginSecForm.username || !this.loginSecForm.password) {
        this.$message.warning('请输入用户名和密码')
        return
      }
      
      xpathLoginSecure({
        username: this.loginSecForm.username,
        password: this.loginSecForm.password
      })
        .then(response => {
          this.loginSecForm.result = response.data
        })
        .catch(error => {
          this.loginSecForm.result = '安全机制生效，攻击被拦截: ' + (error.msg || error.message || '未知错误')
        })
    },
    // ==================== 共享方法 ====================
    getLoginPayloads() {
      return {
        'normal': {
          username: 'admin',
          password: 'admin123'
        },
        'bypass2': {
          username: "admin' or '1'='1",
          password: 'anything'
        },
        'union': {
          username: "' or 1=1 or '",
          password: 'anything'
        }
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

.center-dialog {
    text-align: center;
    margin: 0 auto;
}

.demo-form-inline {
    text-align: left;
}

.result-display {
    margin-top: 20px;
    text-align: center;
}

.result-display h4 {
    text-align: left;
    margin-bottom: 10px;
}

.result-text {
    text-align: left;
    background-color: #f5f7fa;
    padding: 10px;
    border-radius: 4px;
    max-height: 300px;
    overflow: auto;
}

.result-text pre {
    margin: 0;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-family: Consolas, Monaco, 'Andale Mono', monospace;
    font-size: 12px;
    line-height: 1.5;
}
</style>

