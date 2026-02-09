<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">其他漏洞 -- 科学记数法拒绝服务漏洞（Scientific Notation DoS）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              科学记数法拒绝服务漏洞是指当服务端使用 BigDecimal 处理用户输入的科学记数法数字时，恶意用户可以传入<b>极端scale</b>的科学记数法（如 <code>0.1e-121312222</code>），导致 BigDecimal 在进行算术运算时需要对齐精度，创建超大内部数组，最终消耗大量 CPU 和内存资源，使服务器响应时间长达数分钟甚至更久，造成拒绝服务。<br/>
              <br/>
              <b>核心漏洞原理：精度对齐导致的DoS</b><br/>
              <br/>
              <b>1. BigDecimal 的内部存储机制</b><br/>
              - BigDecimal 使用 <code>unscaledValue</code> + <code>scale</code> 来存储数字<br/>
              - 例如：<code>0.1e-121312222</code> 存储为 unscaledValue=1, scale=121312223（约1.2亿！）<br/>
              - 这意味着这个数字有<b>1.2亿位小数</b><br/>
              <br/>
              <b>2. 运算时的精度对齐</b><br/>
              当两个 BigDecimal 进行算术运算（加减乘除）时，需要对齐两个数字的 scale：<br/>
              <pre style="background-color: #f5f5f5; padding: 10px; margin: 10px 0;">
BigDecimal num = 0.1e-121312222;  // scale = 121312223
BigDecimal num1 = new BigDecimal(0.005);  // scale ≈ 3
BigDecimal result = num1.subtract(num);  
// ⚠️ 需要对齐到 121312223 位！
// BigDecimal 内部要创建一个容纳1.2亿位小数的巨大数组
// 遍历整个数组进行计算，消耗大量CPU和内存</pre>
              <br/>
              <b>3. DoS 攻击效果</b><br/>
              - 单个请求可能阻塞线程数分钟<br/>
              - CPU 占用率飙升至 100%<br/>
              - 多个并发请求可使服务器完全瘫痪<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              <b>1. 服务器响应时间极长</b><br/>
              - 单个请求可能导致响应时间长达数分钟<br/>
              - 用户体验极差，看似服务器宕机<br/>
              <br/>
              <b>2. CPU 资源耗尽</b><br/>
              - BigDecimal 精度对齐需要遍历超大数组<br/>
              - CPU 占用率持续 100%<br/>
              - 影响服务器上的所有其他服务<br/>
              <br/>
              <b>3. 线程池耗尽</b><br/>
              - 每个攻击请求阻塞一个线程数分钟<br/>
              - 几个并发请求就能耗尽整个线程池<br/>
              - 正常用户的请求无法得到处理<br/>
              <br/>
              <b>4. 内存溢出风险</b><br/>
              - 极端情况下可能触发 OutOfMemoryError<br/>
              - 导致整个 JVM 崩溃<br/>
              <br/>
              <b>5. 攻击成本极低</b><br/>
              - 攻击者只需发送一个简单的 HTTP 请求<br/>
              - Payload 只有十几个字符：<code>0.1e-121312222</code><br/>
              - 难以通过 WAF 拦截（看起来是正常数字）<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <b>【必须】验证 scale 范围</b><br/>
              这是最关键的防护措施！限制 BigDecimal 的 scale 在安全范围内（如 ±1000）。<br/>
              <pre style="background-color: #f5f5f5; padding: 10px; margin: 10px 0;">
int scale = Math.abs(num.scale());
if (scale > 1000) {
    return Result.error("数字精度过高，scale=" + scale + " 超过限制");
}</pre>
              <br/>
              <b>【建议】设置超时保护</b><br/>
              为计算密集型操作设置超时时间，防止长时间阻塞。<br/>
              <br/>
              <b>【建议】限制输入长度</b><br/>
              对输入字符串进行长度限制，避免超长输入。<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <b>相关技术文档和参考资源：</b>
              <br/><br/>
              <b>官方文档：</b>
              <ul>
                <li><a href="https://docs.oracle.com/javase/8/docs/api/java/math/BigDecimal.html" target="_blank" style="text-decoration: underline;">Java BigDecimal 官方文档</a></li>
                <li><a href="https://docs.oracle.com/javase/tutorial/java/nutsandbolts/datatypes.html" target="_blank" style="text-decoration: underline;">Java 数据类型教程</a></li>
              </ul>
              <br/>
              <b>安全最佳实践：</b>
              <ul>
                <li><a href="https://owasp.org/www-community/vulnerabilities/Denial_of_Service" target="_blank" style="text-decoration: underline;">OWASP 拒绝服务攻击</a></li>
                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP 输入验证检查清单</a></li>
              </ul>
              <br/>
              <b>漏洞分析文章：</b>
              <ul>
                <li><a href="https://www.javacodegeeks.com/2019/03/bigdecimal-performance-pitfalls.html" target="_blank" style="text-decoration: underline;">BigDecimal 性能陷阱分析</a></li>
                <li><a href="https://stackoverflow.com/questions/4591206/arithmeticexception-non-terminating-decimal-expansion" target="_blank" style="text-decoration: underline;">BigDecimal 计算异常讨论</a></li>
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
              漏洞代码 - 直接接收 BigDecimal 参数
              <el-button type="danger" round size="mini" @click="testVuln">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@PostMapping("/vuln")
public Result testVuln(@RequestParam(name = "num") BigDecimal num) {
    // ❌ 危险：直接接收 BigDecimal 参数，没有验证就进行运算
    BigDecimal num1 = new BigDecimal(0.005);
    
    // ⚠️ 精度对齐：当 scale 相差巨大时（如 3 vs 121312223）
    // BigDecimal 需要创建超大数组对齐精度
    BigDecimal result = num1.subtract(num);
    
    // 限制返回长度
    String resultStr = result.toPlainString();
    String displayResult = resultStr.length() > 100 ? 
        resultStr.substring(0, 100) + "..." : resultStr;
    
    return Result.success("结果: " + displayResult + "，耗时: " + duration + " ms");
}

// 攻击payload: 0.1e-121312222
// scale = 121312223（约1.2亿位小数！）
// 
// DoS效果：
// - 响应时间：数分钟
// - CPU占用：100%
// - 线程阻塞：长时间无响应</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 验证 scale 范围
              <el-button type="success" round size="mini" @click="testSafe">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@PostMapping("/sec")
public Result testSec(@RequestParam(name = "num") BigDecimal num) {
    // ✅ scale 验证 - 关键防护！
    int scale = Math.abs(num.scale());
    if (scale > 1000) {
        return Result.error("数字精度过高，scale=" + scale + " 超过限制");
    }
    
    // ✅ 执行安全运算
    BigDecimal num1 = new BigDecimal(0.005);
    BigDecimal result = num1.subtract(num);
    
    return Result.success("运算完成，结果: " + result + "，耗时: " + duration + " ms");
}

// 测试payload: 0.1e-121312222
// 结果：被 scale 验证拦截，返回错误信息</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>
    
    
    <!-- 漏洞代码测试对话框 -->
    <el-dialog :visible.sync="vulnDialogVisible" width="55%" class="test-dialog" @close="resetVulnForm">
      <div slot="title" style="text-align: center; font-size: 18px;">
        科学记数法DoS漏洞代码测试
      </div>
      <div class="dialog-content">
        <div class="test-info">
          <h4>⚠️ 测试说明：</h4>
          <p>此测试将向后端发送<b>极端scale</b>的科学记数法（如 <code>0.1e-121312222</code>），导致 BigDecimal 运算时需要对齐精度到1.2亿位小数，消耗大量 CPU 和内存。</p>
          <p><b style="color: red;">警告：</b>测试可能导致后端响应时间长达数分钟，请耐心等待！建议从较小的指数开始测试。</p>
          <br/>
          <h4>💡 攻击原理：</h4>
          <p><code>0.1e-121312222</code> 的 scale = 121312223（正数，约1.2亿）</p>
          <p>当与 <code>0.005</code>（scale ≈ 3）进行减法运算时，需要对齐到 121312223 位小数，创建超大数组！</p>
          <br/>
          <h4>📋 使用 curl 进行测试：</h4>
          <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-size: 12px; overflow-x: auto;"><code>curl -X POST 'http://127.0.0.1:8080/scientificNotationDoS/vuln?num=0.1e-121312222' \
  -H 'Authorization: YOUR_TOKEN'</code></pre>
          <div style="margin-top: 10px; padding: 10px; background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
            <p style="margin: 5px 0; font-size: 13px;"><b>预期：</b>响应时间极长（数百秒），CPU 100%</p>
            <p style="margin: 5px 0; font-size: 13px; color: #d9534f;"><b>⚠️ 注意：</b>要让后端服务真正拒绝服务（完全瘫痪），需要同时发起多个并发请求！</p>
            <p style="margin: 5px 0; font-size: 13px;">单个请求只会阻塞一个线程，服务器仍可处理其他请求</p>
            <p style="margin: 5px 0; font-size: 13px;"><b>建议：</b>同时发起 50-100 个并发请求，耗尽线程池，使服务器无法响应任何请求</p>
            <p style="margin: 10px 0 5px 0; font-size: 13px;"><b>并发测试示例（在多个终端窗口同时执行，或使用 & 后台执行）：</b></p>
            <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-size: 12px; margin: 5px 0;"><code>for i in {1..100}; do
  curl -X POST 'http://127.0.0.1:8080/scientificNotationDoS/vuln?num=0.1e-121312222' \
    -H 'Authorization: YOUR_TOKEN' &
done</code></pre>
          </div>
        </div>
        
        <el-form :model="vulnForm" label-width="120px">
          <el-form-item label="攻击Payload:">
            <el-select v-model="vulnForm.payloadType" placeholder="选择预设payload" @change="updateVulnPayload" style="width: 100%;">
              <el-option label="温和测试 (0.1e-10000)" value="mild"></el-option>
              <el-option label="中等测试 (0.1e-1000000)" value="medium"></el-option>
              <el-option label="强力测试 (0.1e-10000000)" value="strong"></el-option>
              <el-option label="⚠️ 极限测试 (0.1e-121312222)" value="extreme"></el-option>
            </el-select>
          </el-form-item>
          <el-form-item label="测试输入:">
            <el-input
              v-model="vulnForm.input"
              placeholder="输入科学记数法"
            ></el-input>
            <div style="margin-top: 5px; color: #909399; font-size: 12px;">
              提示：极小的负指数（如 e-121312222）会让 scale 变成超大正数
            </div>
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
        科学记数法DoS安全代码测试
      </div>
      <div class="dialog-content">
        <div class="test-info">
          <h4>✅ 测试说明：</h4>
          <p>此测试使用添加了 scale 范围验证的安全代码，会拒绝 scale 超过 1000 的输入。</p>
          <p>你可以尝试输入极端的科学记数法，观察安全代码如何进行防护。</p>
        </div>
        
        <el-form :model="safeForm" label-width="120px">
          <el-form-item label="测试Payload:">
            <el-select v-model="safeForm.payloadType" placeholder="选择测试payload" @change="updateSafePayload" style="width: 100%;">
              <el-option label="正常数字 (123.45)" value="normal"></el-option>
              <el-option label="科学记数法 (1.23e10)" value="scientific"></el-option>
              <el-option label="尝试攻击 (0.1e-10000)" value="attack_mild"></el-option>
              <el-option label="尝试攻击 (0.1e-121312222)" value="attack_extreme"></el-option>
            </el-select>
          </el-form-item>
          <el-form-item label="测试输入:">
            <el-input
              v-model="safeForm.input"
              placeholder="输入科学记数法"
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
import { testScientificNotationDoSVuln, testScientificNotationDoSSafe } from '@/api/scientificNotationDoS'

export default {
  name: 'ScientificNotationDoS',
  data() {
    return {
      activeName: 'first',
      // 漏洞代码测试对话框
      vulnDialogVisible: false,
      vulnForm: {
        payloadType: 'mild',
        input: '0.1e-10000'
      },
      vulnLoading: false,
      vulnResult: null,
      // 安全代码测试对话框
      safeDialogVisible: false,
      safeForm: {
        payloadType: 'normal',
        input: '123.45'
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
        'mild': '0.1e-10000',
        'medium': '0.1e-1000000',
        'strong': '0.1e-10000000',
        'extreme': '0.1e-121312222'
      }
      this.vulnForm.input = payloads[type] || this.vulnForm.input
    },
    
    // 更新安全测试payload
    updateSafePayload(type) {
      const payloads = {
        'normal': '123.45',
        'scientific': '1.23e10',
        'attack_mild': '0.1e-10000',
        'attack_extreme': '0.1e-121312222'
      }
      this.safeForm.input = payloads[type] || this.safeForm.input
    },
    
    // 测试漏洞代码
    async testVulnCode() {
      if (!this.vulnForm.input || this.vulnForm.input.trim() === '') {
        this.$message.warning('请输入测试数字')
        return
      }
      
      this.vulnLoading = true
      this.vulnResult = null
      
      const startTime = Date.now()
      
      try {
        const response = await testScientificNotationDoSVuln(this.vulnForm.input)
        const duration = ((Date.now() - startTime) / 1000).toFixed(2)
        
        if (response.code === 0) {
          this.vulnResult = {
            title: `漏洞代码执行结果（前端耗时: ${duration}秒）`,
            type: 'warning',
            description: response.data
          }
        } else {
          this.vulnResult = {
            title: '漏洞代码执行失败',
            type: 'error',
            description: response.msg || '执行失败'
          }
        }
      } catch (error) {
        const duration = ((Date.now() - startTime) / 1000).toFixed(2)
        this.vulnResult = {
          title: `漏洞代码测试异常（前端耗时: ${duration}秒）`,
          type: 'error',
          description: '请求失败: ' + (error.message || '未知错误')
        }
      } finally {
        this.vulnLoading = false
      }
    },
    
    // 测试安全代码
    async testSafeCode() {
      if (!this.safeForm.input || this.safeForm.input.trim() === '') {
        this.$message.warning('请输入测试数字')
        return
      }
      
      this.safeLoading = true
      this.safeResult = null
      
      try {
        const response = await testScientificNotationDoSSafe(this.safeForm.input)
        
        if (response.code === 0) {
          this.safeResult = {
            title: '安全代码执行成功 ✅',
            type: 'success',
            description: response.data
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
      this.vulnForm.payloadType = 'mild'
      this.vulnForm.input = '0.1e-10000'
      this.vulnResult = null
    },
    
    // 重置安全代码测试表单
    resetSafeForm() {
      this.safeForm.payloadType = 'normal'
      this.safeForm.input = '123.45'
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
