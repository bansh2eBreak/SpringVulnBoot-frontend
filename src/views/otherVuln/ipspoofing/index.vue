<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">其他漏洞 -- IP地址伪造漏洞</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              IP地址伪造漏洞是指攻击者通过伪造HTTP请求头中的IP地址信息，绕过基于IP地址的安全限制，如IP白名单、频率限制、地理位置限制等。<br/>
              <br/>
              常见原因：<br/>
              1. 直接信任X-Forwarded-For等HTTP头<br/>
              2. 未验证代理服务器或负载均衡器的可信度<br/>
              3. 缺乏对真实IP地址的验证机制<br/>
              4. 未正确配置反向代理的IP传递<br/>
              5. 忽略了对IP地址格式和范围的验证<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              <strong>1. 绕过IP限制</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 攻击者可以伪造IP绕过黑名单限制<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 绕过IP白名单访问受限资源<br/>
              <br/>
              <strong>2. 绕过频率限制</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 通过伪造不同IP绕过请求频率限制<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 绕过防刷机制进行恶意请求<br/>
              <br/>
              <strong>3. 绕过地理位置限制</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 伪造特定地区的IP地址<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 访问有地域限制的内容或服务<br/>
              <br/>
              <strong>4. 绕过白名单限制</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 伪造白名单中的IP地址<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 获取特权访问权限<br/>
              <br/>
              <strong>5. 隐藏真实身份</strong><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 攻击者可以隐藏真实的IP地址<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;• 绕过基于IP的安全策略和访问控制<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <strong>【必须】不信任HTTP头</strong><br/>
              不要直接信任X-Forwarded-For、X-Real-IP等HTTP头，这些头可以被客户端伪造。<br/>
              <br/>
              <strong>【必须】使用直接连接IP</strong><br/>
              优先使用request.getRemoteAddr()获取直接连接的IP地址，这是最可靠的IP来源。<br/>
              <br/>
              <strong>【必须】验证代理服务器</strong><br/>
              如果使用代理服务器，需要验证代理服务器的可信度，并正确配置IP传递。<br/>
              <br/>
              <strong>【建议】IP地址验证</strong><br/>
              对获取到的IP地址进行格式验证，确保IP地址的有效性和合理性。<br/>
              <br/>
              <strong>【建议】多重验证</strong><br/>
              结合多种方式验证用户身份，不仅仅依赖IP地址进行安全判断。<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <strong>相关技术文档和参考资源：</strong>
              <br/><br/>
              <strong>官方文档：</strong>
              <ul>
                <li><a href="https://docs.oracle.com/javase/tutorial/networking/sockets/" target="_blank" style="text-decoration: underline;">Java网络编程官方教程</a></li>
                <li><a href="https://docs.oracle.com/javase/8/docs/api/java/net/InetAddress.html" target="_blank" style="text-decoration: underline;">Java InetAddress类文档</a></li>
              </ul>
              <br/>
              <strong>安全最佳实践：</strong>
              <ul>
                <li><a href="https://owasp.org/www-community/attacks/IP_Spoofing" target="_blank" style="text-decoration: underline;">OWASP IP伪造攻击说明</a></li>
                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP输入验证检查清单</a></li>
              </ul>
              <br/>
              <strong>漏洞分析文章：</strong>
              <ul>
                <li><a href="https://en.wikipedia.org/wiki/IP_address_spoofing" target="_blank" style="text-decoration: underline;">Wikipedia - IP地址伪造</a></li>
                <li><a href="https://www.imperva.com/learn/application-security/ip-spoofing/" target="_blank" style="text-decoration: underline;">Imperva - IP伪造详解</a></li>
              </ul>
              <br/>
              <b>工具和检测：</b>
              <ul>
                <li><a href="https://www.cloudflare.com/learning/ddos/glossary/ip-spoofing/" target="_blank" style="text-decoration: underline;">Cloudflare - IP伪造防护</a></li>
                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" style="text-decoration: underline;">OWASP安全编码检查清单</a></li>
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
              漏洞代码 - IP地址伪造
              <el-button type="danger" round size="mini" @click="testIpSpoofingVuln">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
// 测试方法：通过伪造X-Forwarded-For头绕过IP限制
// curl -H "X-Forwarded-For: 192.168.1.100" -X POST /ipspoofing/vuln

@PostMapping("/ipspoofing/vuln")
public Result ipSpoofingVuln(@RequestBody User user, HttpServletRequest request) {
    // 1. 获取用户登录IP - 存在漏洞：信任HTTP头
    String ip = getClientIpVuln(request);
    
    log.info("IP地址伪造测试 - 获取到的IP: {}", ip);

    // 2. 登录
    User u = userService.passwordLogin(user);

    if (u != null) {
        // 登录成功，记录登录成功日志
        userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "成功");
        log.info("{} 登录成功！IP: {}", u.getUsername(), ip);
        return Result.success("登录成功，账号：" + user.getUsername() + "，IP: " + ip);
    } else {
        // 登录失败，记录登录失败日志
        userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "失败");
        log.error("登录失败，账号密码是：{},{}，IP: {}", user.getUsername(), user.getPassword(), ip);
        return Result.success("登录失败，账号：" + user.getUsername() + "，IP: " + ip);
    }
}

private String getClientIpVuln(HttpServletRequest request) {
    // 漏洞：直接信任X-Forwarded-For头
    String ip = request.getHeader("X-Forwarded-For");
    if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
        ip = request.getHeader("X-Real-IP");
    }
    if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
        ip = request.getHeader("Proxy-Client-IP");
    }
    if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
        ip = request.getHeader("WL-Proxy-Client-IP");
    }
    if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
        ip = request.getRemoteAddr();
    }
    
    // 处理多个IP的情况，取第一个
    if (ip != null && ip.contains(",")) {
        ip = ip.split(",")[0].trim();
    }
    
    return ip;
}
</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 获取客户端真实IP
              <el-button type="success" round size="mini" @click="testIpSpoofingSec">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 安全方式：无法通过伪造HTTP头绕过IP限制
              
@PostMapping("/ipspoofing/sec")
public Result ipSpoofingSec(@RequestBody User user, HttpServletRequest request) {
    // 1. 获取用户登录IP - 安全方式：只使用request.getRemoteAddr()
    String ip = getClientIpSec(request);
    
    log.info("安全IP获取测试 - 获取到的IP: {}", ip);

    // 2. 登录
    User u = userService.passwordLogin(user);

    if (u != null) {
        // 登录成功，记录登录成功日志
        userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "成功");
        log.info("{} 登录成功！IP: {}", u.getUsername(), ip);
        return Result.success("登录成功，账号：" + user.getUsername() + "，IP: " + ip);
    } else {
        // 登录失败，记录登录失败日志
        userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "失败");
        log.error("登录失败，账号密码是：{},{}，IP: {}", user.getUsername(), user.getPassword(), ip);
        return Result.success("登录失败，账号：" + user.getUsername() + "，IP: " + ip);
    }
}

private String getClientIpSec(HttpServletRequest request) {
    // 安全：只使用request.getRemoteAddr()，不信任任何HTTP头
    return request.getRemoteAddr();
}
</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>
    
    <!-- IP地址伪造测试对话框 -->
    <el-dialog :visible.sync="vulnDialogVisible" class="center-dialog" @close="resetVulnForm">
      <div slot="title" style="text-align: center; font-size: 18px;">
        IP地址伪造测试
      </div>
      <div style="text-align: center;">
        <el-form :model="vulnForm" label-width="80px" style="display: inline-block;">
          <el-form-item label="账号">
            <el-input v-model="username1" style="width: 300px;"></el-input>
          </el-form-item>
          <el-form-item label="密码">
            <el-input v-model="password1" type="password" style="width: 300px;"></el-input>
          </el-form-item>
          <el-form-item label="伪造IP">
            <el-input v-model="fakeIp1" style="width: 300px;"></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="success" @click="onSubmit13" :loading="normalLoading">正常登录</el-button>
            <el-button type="danger" @click="onSubmit11" :loading="vulnLoading">攻击测试</el-button>
          </el-form-item>
        </el-form>
      </div>
      <div v-if="loginLogs.length > 0">
        <hr style="border: 0.5px solid #e4e7ed; margin: 20px 0;">
        <el-table :data="loginLogs" style="width: 100%;" align="center">
          <el-table-column property="id" label="ID" width="60"></el-table-column>
          <el-table-column property="username" label="用户名" width="100"></el-table-column>
          <el-table-column property="ip" label="登录IP" width="130"></el-table-column>
          <el-table-column property="loginResult" label="登录结果" width="100">
            <template slot-scope="scope">
              <el-tag :type="scope.row.loginResult === '成功' ? 'success' : 'danger'" size="mini">
                {{ scope.row.loginResult }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column property="loginTime" label="登录时间" width="160"></el-table-column>
        </el-table>
      </div>
      <div v-else-if="vulnResult">
        <div v-html="vulnResult.description"></div>
      </div>
    </el-dialog>

    <!-- 安全IP获取测试对话框 -->
    <el-dialog :visible.sync="secDialogVisible" class="center-dialog" @close="resetSecForm">
      <div slot="title" style="text-align: center; font-size: 18px;">
        获取真实IP测试
      </div>
      <div style="text-align: center;">
        <el-form :model="secForm" label-width="80px" style="display: inline-block;">
          <el-form-item label="账号">
            <el-input v-model="username1" style="width: 300px;"></el-input>
          </el-form-item>
          <el-form-item label="密码">
            <el-input v-model="password1" type="password" style="width: 300px;"></el-input>
          </el-form-item>
          <el-form-item label="伪造IP">
            <el-input v-model="fakeIp1" style="width: 300px;"></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="danger" @click="onSubmit22" :loading="secAttackLoading">攻击测试</el-button>
          </el-form-item>
        </el-form>
      </div>
      <div v-if="loginLogs.length > 0">
        <hr style="border: 0.5px solid #e4e7ed; margin: 20px 0;">
        <el-table :data="loginLogs" style="width: 100%;" align="center">
          <el-table-column property="id" label="ID" width="60"></el-table-column>
          <el-table-column property="username" label="用户名" width="100"></el-table-column>
          <el-table-column property="ip" label="登录IP" width="130"></el-table-column>
          <el-table-column property="loginResult" label="登录结果" width="100">
            <template slot-scope="scope">
              <el-tag :type="scope.row.loginResult === '成功' ? 'success' : 'danger'" size="mini">
                {{ scope.row.loginResult }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column property="loginTime" label="登录时间" width="160"></el-table-column>
        </el-table>
      </div>
      <div v-else-if="secResult">
        <div v-html="secResult.description"></div>
      </div>
    </el-dialog>

  </div>
</template>

<script>
import { testIpSpoofingVuln, testIpSpoofingSec, normalLogin, getAllUserLoginLogs } from '@/api/ipspoofing'

export default {
  name: 'IpSpoofing',
  data() {
    return {
      activeName: 'first',
      // IP地址伪造测试对话框
      vulnDialogVisible: false,
      vulnForm: {},
      username1: 'zhangsan',
      password1: '123',
      fakeIp1: '192.168.1.100',
      vulnLoading: false,
      vulnResult: null,
      normalLoading: false,
      loginLogs: [],
      // 安全IP获取测试对话框
      secDialogVisible: false,
      secForm: {},
      secAttackLoading: false,
      secResult: null
    }
  },
  methods: {
    handleClick(tab, event) {},
    
    // 打开IP地址伪造测试对话框
    testIpSpoofingVuln() {
      this.vulnDialogVisible = true;
      // 默认查询最新的登录日志
      this.fetchLoginLogs();
    },
    
    // 打开安全IP获取测试对话框
    testIpSpoofingSec() {
      this.secDialogVisible = true;
      // 默认查询最新的登录日志
      this.fetchLoginLogs();
    },
    
    // 测试漏洞代码
    async onSubmit11() {
      if (!this.username1 || !this.password1) {
        this.$message.warning('请输入用户名和密码');
        return;
      }

      this.vulnLoading = true;
      try {
        const headers = {};
        if (this.fakeIp1) {
          headers['X-Forwarded-For'] = this.fakeIp1;
        }
        
        const response = await testIpSpoofingVuln({
          username: this.username1,
          password: this.password1
        }, headers);
        
        this.vulnResult = {
          title: 'IP地址伪造测试结果',
          type: 'warning',
          description: response.data
        };
        
        // 查询登录日志
        this.fetchLoginLogs();
      } catch (error) {
        this.vulnResult = {
          title: 'IP地址伪造测试失败',
          type: 'error',
          description: '测试失败: ' + error.message
        };
      } finally {
        this.vulnLoading = false;
      }
    },
    
    // 正常登录测试
    async onSubmit13() {
      if (!this.username1 || !this.password1) {
        this.$message.warning('请输入用户名和密码');
        return;
      }

      this.normalLoading = true;
      try {
        const response = await normalLogin({
          username: this.username1,
          password: this.password1
        });
        
        this.vulnResult = {
          title: '正常登录测试结果',
          type: 'success',
          description: response.data
        };
        
        // 查询登录日志
        this.fetchLoginLogs();
      } catch (error) {
        this.vulnResult = {
          title: '正常登录测试失败',
          type: 'error',
          description: '测试失败: ' + error.message
        };
      } finally {
        this.normalLoading = false;
      }
    },
    
    // 安全代码攻击测试
    async onSubmit22() {
      if (!this.username1 || !this.password1) {
        this.$message.warning('请输入用户名和密码');
        return;
      }

      this.secAttackLoading = true;
      try {
        const headers = {};
        if (this.fakeIp1) {
          headers['X-Forwarded-For'] = this.fakeIp1;
        }
        
        const response = await testIpSpoofingSec({
          username: this.username1,
          password: this.password1
        }, headers);
        
        this.secResult = {
          title: '安全IP获取攻击测试结果',
          type: 'warning',
          description: response.data
        };
        
        // 查询登录日志
        this.fetchLoginLogs();
      } catch (error) {
        this.secResult = {
          title: '安全IP获取攻击测试失败',
          type: 'error',
          description: '测试失败: ' + error.message
        };
      } finally {
        this.secAttackLoading = false;
      }
    },
    
    // 查询登录日志
    async fetchLoginLogs() {
      try {
        const response = await getAllUserLoginLogs();
        this.loginLogs = response.data || [];
      } catch (error) {
        console.error('查询登录日志失败:', error);
        this.loginLogs = [];
      }
    },
    
    // 重置漏洞代码测试表单
    resetVulnForm() {
      this.username1 = 'zhangsan';
      this.password1 = '123';
      this.fakeIp1 = '192.168.1.100';
      this.vulnResult = null;
      this.loginLogs = [];
    },
    
    // 重置安全代码测试表单
    resetSecForm() {
      this.username1 = 'zhangsan';
      this.password1 = '123';
      this.fakeIp1 = '192.168.1.100';
      this.secResult = null;
      this.secAttackLoading = false;
      this.loginLogs = [];
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

.test-results {
    margin: 20px;
}

.result-item {
    margin-bottom: 10px;
    padding: 10px;
    border-radius: 4px;
    background-color: #f5f7fa;
}

.result-success {
    background-color: #f0f9ff;
    border-left: 4px solid #67c23a;
}

.result-error {
    background-color: #fef0f0;
    border-left: 4px solid #f56c6c;
}

.result-warning {
    background-color: #fdf6ec;
    border-left: 4px solid #e6a23c;
}

.test-dialog .el-dialog__body {
    padding: 20px;
}

.test-info {
    margin-bottom: 20px;
    padding: 15px;
    background-color: #f0f9ff;
    border-radius: 4px;
    border-left: 4px solid #409EFF;
}

.test-info h4 {
    margin: 0 0 10px 0;
    color: #409EFF;
    font-size: 14px;
}

.test-info p {
    margin: 0;
    color: #666;
    font-size: 13px;
    line-height: 1.6;
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
