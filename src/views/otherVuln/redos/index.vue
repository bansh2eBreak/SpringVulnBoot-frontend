<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">其他漏洞 -- 正则表达式拒绝服务漏洞（ReDoS）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              正则表达式拒绝服务漏洞（ReDoS - Regular Expression Denial of Service）是由于正则表达式引擎在处理某些特殊构造的正则表达式时，会出现回溯爆炸（Catastrophic Backtracking）现象，导致CPU使用率急剧上升，最终使服务器拒绝服务。<br/>
              <br/>
              常见原因：<br/>
              1. 使用嵌套量词（如 (a+)+、(a*)*）<br/>
              2. 重叠的备选项（如 (a|aa)*）<br/>
              3. 多层嵌套结构（如 ((a+)+)+）<br/>
              4. 嵌套后跟固定字符（如 (a+)+b）<br/>
              5. 复杂的嵌套结构（如 (a|a+)*）<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. CPU资源耗尽 - 正则表达式引擎陷入大量回溯计算<br/>
              2. 服务器拒绝服务 - 无法处理其他正常请求<br/>
              3. 系统响应缓慢 - 影响整体系统性能<br/>
              4. 资源竞争 - 可能导致其他服务受影响<br/>
              5. 隐蔽性强 - 看似正常的正则表达式可能隐藏危险<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】避免嵌套量词
              不要使用 (a+)+、(a*)* 等嵌套量词模式，使用简单的量词如 a+、a* 即可。
              <br />
              <br />
              【必须】避免重叠备选项
              避免使用 (a|aa)*、(a|a+)* 等重叠的备选项模式，确保备选项之间没有重叠。
              <br />
              <br />
              【必须】使用超时机制
              为正则表达式匹配设置超时时间，防止长时间的回溯计算。
              <br />
              <br />
              【建议】限制输入长度
              对用户输入进行长度限制，避免过长的恶意输入。
              <br />
              <br />
              【建议】使用原子组
              如果正则表达式引擎支持，使用原子组避免回溯。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <b>相关技术文档和参考资源：</b>
              <br/><br/>
              <b>官方文档：</b>
              <ul>
                <li><a href="https://docs.oracle.com/javase/tutorial/essential/regex/" target="_blank" style="text-decoration: underline;">Java正则表达式官方教程</a></li>
                <li><a href="https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html" target="_blank" style="text-decoration: underline;">Java Pattern类文档</a></li>
              </ul>
              <br/>
              <b>安全最佳实践：</b>
              <ul>
                <li><a href="https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS" target="_blank" style="text-decoration: underline;">OWASP ReDoS攻击说明</a></li>
                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP输入验证检查清单</a></li>
              </ul>
              <br/>
              <b>漏洞分析文章：</b>
              <ul>
                <li><a href="https://www.regular-expressions.info/catastrophic.html" target="_blank" style="text-decoration: underline;">正则表达式灾难性回溯分析</a></li>
                <li><a href="https://www.rexegg.com/regex-explosive-quantifiers.html" target="_blank" style="text-decoration: underline;">爆炸性量词详解</a></li>
              </ul>
              <br/>
              <b>工具和检测：</b>
              <ul>
                <li><a href="https://github.com/substack/safe-regex" target="_blank" style="text-decoration: underline;">safe-regex - 检测危险正则表达式</a></li>
                <li><a href="https://github.com/davisjam/vuln-regex-detector" target="_blank" style="text-decoration: underline;">vuln-regex-detector - 漏洞正则表达式检测器</a></li>
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
              漏洞代码 - 复杂嵌套 ((a+)+)+b
              <el-button type="danger" round size="mini" @click="testReDoS">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@PostMapping("/redos/vuln")
public Result testReDoS(@RequestBody Map&lt;String, String&gt; request) {
    String input = request.get("input");
    // 复杂嵌套模式，这个在Java中确实会产生ReDoS
    String dangerousPattern = "((a+)+)+b";
    boolean matches = input.matches(dangerousPattern);
    return Result.success("匹配结果: " + matches + ", 耗时: " + duration + "ms");
}

// 测试输入：aaaaaaaaaaaaaaaaaaaaa (21个a字符)
// 预期结果：处理时间指数级增长，21-27字符耗时从81ms到5242ms</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 简单量词 a+
              <el-button type="success" round size="mini" @click="testSafeRegex">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@PostMapping("/redos/sec")
public Result testSafeRegex(@RequestBody Map&lt;String, String&gt; request) {
    String input = request.get("input");
    // 安全的正则表达式：简单量词
    String safePattern = "a+";
    boolean matches = input.matches(safePattern);
    return Result.success("匹配结果: " + matches + ", 耗时: " + duration + "ms");
}

// 测试输入：aaaaaaaaaaaaaaaaaaaaa (21个a字符)
// 预期结果：快速匹配，耗时很短，不会产生回溯爆炸</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>
    
    
    <!-- 漏洞代码测试对话框 -->
    <el-dialog :visible.sync="vulnDialogVisible" width="60%" class="test-dialog" @close="resetVulnForm">
      <div slot="title" style="text-align: center; font-size: 18px;">
        ReDoS漏洞代码测试
      </div>
      <div class="dialog-content">
        <div class="test-info">
          <h4>测试说明：</h4>
          <p>此测试使用复杂嵌套正则表达式 <code>((a+)+)+b</code>，当输入全是a字符时会产生大量回溯，会导致接口明显耗时很长。</p>
          <p>如果需要测试拒绝服务，可以通过创建多个如下curl请求，会让后端服务真的拒绝服务！！！</p>
          <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-size: 12px; overflow-x: auto;"><code>curl -X POST 'http://127.0.0.1:8080/redos/vuln' -H 'Authorization: eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoi57O757uf566h55CG5ZGYIiwiaWQiOjEsImV4cCI6MTc2MzQzNDAxNywidXNlcm5hbWUiOiJhZG1pbiJ9.oHgURgX_BnfrChJsqBTa_x_uJeAiEljWTzPsVb-5UWs' -H 'Content-Type: application/json;charset=UTF-8' --data-raw "{\"input\":\"$(printf 'a%.0s' {1..50})\"}"</code></pre>
        </div>
        
        <el-form :model="vulnForm" label-width="100px">
          <el-form-item label="测试输入:">
            <div style="display: flex; align-items: center; gap: 10px;">
              <el-input
                v-model="vulnForm.input"
                placeholder="测试字符串"
                readonly
                style="width: 200px;"
              ></el-input>
              <el-input-number
                v-model="vulnForm.length"
                :min="1"
                :max="50"
                @change="updateVulnInput"
                style="width: 120px;"
              ></el-input-number>
              <span style="color: #909399; font-size: 12px;">
                字符长度
              </span>
            </div>
          </el-form-item>
          <el-form-item>
            <el-button type="danger" @click="testVulnCode" :loading="vulnLoading">攻击测试</el-button>
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
    <el-dialog :visible.sync="safeDialogVisible" width="60%" class="test-dialog" @close="resetSafeForm">
      <div slot="title" style="text-align: center; font-size: 18px;">
        ReDoS安全代码测试
      </div>
      <div class="dialog-content">
        <div class="test-info">
          <h4>测试说明：</h4>
          <p>此测试使用简单量词正则表达式 <code>a+</code>，不会产生回溯爆炸，处理速度快。</p>
        </div>
        
        <el-form :model="safeForm" label-width="100px">
          <el-form-item label="测试输入:">
            <div style="display: flex; align-items: center; gap: 10px;">
              <el-input
                v-model="safeForm.input"
                placeholder="测试字符串"
                readonly
                style="width: 200px;"
              ></el-input>
              <el-input-number
                v-model="safeForm.length"
                :min="1"
                :max="50"
                @change="updateSafeInput"
                style="width: 120px;"
              ></el-input-number>
              <span style="color: #909399; font-size: 12px;">
                字符长度
              </span>
            </div>
          </el-form-item>
          <el-form-item>
            <el-button type="success" @click="testSafeCode" :loading="safeLoading">安全测试</el-button>
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
import { testReDoS, testSafeRegex } from '@/api/redos'

export default {
  name: 'ReDoS',
  data() {
    return {
      activeName: 'first',
      // 漏洞代码测试对话框
      vulnDialogVisible: false,
      vulnForm: {
        input: 'aaaaaaaaaaaaaaaaaaaaa', // 21个a字符
        length: 21 // 字符长度
      },
      vulnLoading: false,
      vulnResult: null,
      // 安全代码测试对话框
      safeDialogVisible: false,
      safeForm: {
        input: 'aaaaaaaaaaaaaaaaaaaaa', // 21个a字符
        length: 21 // 字符长度
      },
      safeLoading: false,
      safeResult: null
    }
  },
  methods: {
    handleClick(tab, event) {},
    
    // 打开漏洞代码测试对话框
    testReDoS() {
      this.vulnDialogVisible = true;
    },
    
    // 打开安全代码测试对话框
    testSafeRegex() {
      this.safeDialogVisible = true;
    },
    
    // 测试漏洞代码
    async testVulnCode() {
      if (!this.vulnForm.input || this.vulnForm.input.trim() === '') {
        this.$message.warning('请输入测试字符串');
        return;
      }
      
      this.vulnLoading = true;
      try {
        const response = await testReDoS(this.vulnForm.input);
        this.vulnResult = {
          title: '漏洞代码测试结果',
          type: 'warning',
          description: response.data
        };
      } catch (error) {
        this.vulnResult = {
          title: '漏洞代码测试失败',
          type: 'error',
          description: '测试失败: ' + error.message
        };
      } finally {
        this.vulnLoading = false;
      }
    },
    
    // 测试安全代码
    async testSafeCode() {
      if (!this.safeForm.input || this.safeForm.input.trim() === '') {
        this.$message.warning('请输入测试字符串');
        return;
      }
      
      this.safeLoading = true;
      try {
        const response = await testSafeRegex(this.safeForm.input);
        this.safeResult = {
          title: '安全代码测试结果',
          type: 'success',
          description: response.data
        };
      } catch (error) {
        this.safeResult = {
          title: '安全代码测试失败',
          type: 'error',
          description: '测试失败: ' + error.message
        };
      } finally {
        this.safeLoading = false;
      }
    },
    
    // 清空漏洞代码测试结果
    clearVulnResult() {
      this.vulnResult = null;
    },
    
    // 清空安全代码测试结果
    clearSafeResult() {
      this.safeResult = null;
    },
    
    // 更新漏洞代码测试输入
    updateVulnInput() {
      this.vulnForm.input = 'a'.repeat(this.vulnForm.length);
    },
    
    // 更新安全代码测试输入
    updateSafeInput() {
      this.safeForm.input = 'a'.repeat(this.safeForm.length);
    },
    
    // 重置漏洞代码测试表单
    resetVulnForm() {
      this.vulnForm.input = 'aaaaaaaaaaaaaaaaaaaaa'; // 重置为21个a字符
      this.vulnForm.length = 21; // 重置长度为21
      this.vulnResult = null; // 清空测试结果
    },
    
    // 重置安全代码测试表单
    resetSafeForm() {
      this.safeForm.input = 'aaaaaaaaaaaaaaaaaaaaa'; // 重置为21个a字符
      this.safeForm.length = 21; // 重置长度为21
      this.safeResult = null; // 清空测试结果
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


.test-results {
    margin: 20px;
}

.result-item {
    margin-bottom: 10px;
}

.result-item:last-child {
    margin-bottom: 0;
}

/* 测试对话框样式 */
.test-dialog .el-dialog__body {
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
    margin: 0;
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
