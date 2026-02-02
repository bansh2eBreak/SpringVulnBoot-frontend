<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">XInclude 注入漏洞</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              XInclude（XML Inclusions）是 W3C 标准，允许在 XML 中通过 <code>&lt;xi:include href="..."/&gt;</code> 在解析时把外部资源（本地文件或 URL）包含进文档。<br/><br/>
              <b>XInclude 注入</b>：当解析器<b>开启了 XInclude</b>（setXIncludeAware(true)）且未限制 href 时，攻击者可在可控 XML 里插入 <code>&lt;xi:include href="file:///etc/passwd" parse="text"/&gt;</code> 或 <code>href="http://内网"</code>，使服务端解析时读文件或发起 SSRF，并将结果插入文档。<br/><br/>
              <b>与 XXE 的区别</b>：XInclude <b>不依赖 DTD</b>，仅禁用 DTD 无法防御，必须关闭 XInclude 或对 href 做白名单。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 读服务器本地文件：配置文件、密钥、源码等<br/>
              2. SSRF：访问内网、云元数据、本机管理接口等<br/>
              3. 绕过「只关 DTD」的防护：仅禁用 DTD 仍会被 XInclude 打穿
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【推荐】不开启 XInclude：不调用 setXIncludeAware(true)，或设为 false<br/>
              【若必须用 XInclude】对 xi:include 的 href 做白名单，仅允许可信协议和路径，禁止 file://、http:// 等
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://www.w3.org/TR/xinclude/" target="_blank" style="text-decoration: underline;">W3C XInclude 1.0</a><br/>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">XML 安全防护速查表（含 XInclude）</a>
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
              漏洞代码 - 开启 XInclude且关闭DTD
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * XInclude 注入 - 漏洞代码
 * 开启 XInclude，xi:include 会展开，可读文件或 SSRF
 */
@PostMapping("/vuln")
public Result xincludeVulnerable(@RequestBody String xmlContent) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    dbf.setXIncludeAware(true);  // 危险：开启 XInclude
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
    String result = doc.getDocumentElement().getTextContent();
    return Result.success(result);
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 关闭 XInclude 与 DTD
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * XInclude 注入 - 安全代码
 * 关闭 XInclude，xi:include 不展开；并禁用 DTD
 */
@PostMapping("/sec")
public Result xincludeSecure(@RequestBody String xmlContent) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    dbf.setXIncludeAware(false);  // 安全：关闭 XInclude
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // ... 禁用外部实体等
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
    return Result.success(doc.getDocumentElement().getTextContent());
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-dialog title="XInclude 注入漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: red; font-style: italic;">
        说明：<br/><br/>
        选择不同 payload 对比效果——【XXE】依赖 DTD，本接口已关闭 DTD，会解析失败；【XInclude】不依赖 DTD，仍会展开并回显内容。<br/><br/>
        本靶场后端地址：{{ baseUrl }}（若端口不同请手动修改 payload 中的 URL）。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="vulnForm.selectedPayload" placeholder="请选择" @change="updateVulnPayload" style="width: 100%">
            <el-option label="【正常】简单 XML（无 xi:include）" value="normal" />
            <el-option label="【XXE】常规 XXE - 依赖 DTD 读文件（本接口已关 DTD，应失败）" value="xxe" />
            <el-option label="【XInclude】本地文件 - xi:include file:///etc/passwd" value="file" />
            <el-option label="【XInclude】内网/本机 - xi:include 请求 /actuator/health" value="http" />
          </el-select>
        </el-form-item>
        <el-form-item label="XML 内容">
          <el-input v-model="vulnForm.xmlContent" type="textarea" :rows="10" placeholder="请输入 XML" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="vulnForm.result" class="result-display">
        <h4>解析结果（XInclude 包含的内容会出现在此处）：</h4>
        <div class="result-text">
          <pre>{{ vulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <el-dialog title="XInclude 注入安全防护测试" :visible.sync="secDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: green; font-style: italic;">
        说明：<br/><br/>
        安全代码已关闭 XInclude，含 xi:include 的 payload 不会被展开（或含 DTD 的被拒绝）。<br/><br/>
        【正常】无 xi:include 的 XML 应解析成功。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="secForm.selectedPayload" placeholder="请选择" @change="updateSecPayload" style="width: 100%">
            <el-option label="【正常】简单 XML（无 xi:include）- 应成功" value="normal" />
            <el-option label="【攻击】XInclude 读文件 - 应被拦截或未展开" value="file" />
          </el-select>
        </el-form-item>
        <el-form-item label="XML 内容">
          <el-input v-model="secForm.xmlContent" type="textarea" :rows="10" placeholder="请输入 XML" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testSecure">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="secForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ secForm.result }}</pre>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { xincludeVulnerable, xincludeSecure } from '@/api/xml'

export default {
  data() {
    const base = (process.env.VUE_APP_BASE_API || '').replace(/\/$/, '') || 'http://127.0.0.1:8080'
    return {
      activeName: 'first',
      baseUrl: base,
      vulnDialogVisible: false,
      secDialogVisible: false,
      vulnForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      secForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      }
    }
  },
  methods: {
    handleClick() {},
    showVulnDialog() {
      this.vulnDialogVisible = true
      this.vulnForm.selectedPayload = ''
      this.vulnForm.xmlContent = ''
      this.vulnForm.result = ''
    },
    showSecDialog() {
      this.secDialogVisible = true
      this.secForm.selectedPayload = ''
      this.secForm.xmlContent = ''
      this.secForm.result = ''
    },
    updateVulnPayload() {
      const payloads = this.getPayloads()
      this.vulnForm.xmlContent = payloads[this.vulnForm.selectedPayload] || ''
    },
    updateSecPayload() {
      const payloads = this.getPayloads()
      this.secForm.xmlContent = payloads[this.secForm.selectedPayload] || ''
    },
    testVulnerable() {
      if (!this.vulnForm.xmlContent || !this.vulnForm.xmlContent.trim()) {
        this.$message.warning('请输入 XML 内容')
        return
      }
      xincludeVulnerable(this.vulnForm.xmlContent)
        .then(res => {
          this.vulnForm.result = res.data
        })
        .catch(err => {
          this.vulnForm.result = '解析失败: ' + (err.msg || err.message || '未知错误')
        })
    },
    testSecure() {
      if (!this.secForm.xmlContent || !this.secForm.xmlContent.trim()) {
        this.$message.warning('请输入 XML 内容')
        return
      }
      xincludeSecure(this.secForm.xmlContent)
        .then(res => {
          this.secForm.result = res.data
        })
        .catch(err => {
          this.secForm.result = '安全策略拦截或解析失败: ' + (err.msg || err.message || '未知错误')
        })
    },
    getPayloads() {
      const base = this.baseUrl
      return {
        normal: `<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <message>Hello, normal XML without xi:include.</message>
</root>`,
        xxe: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`,
        file: `<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <message>Below is file content if XInclude is enabled:</message>
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>`,
        http: `<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <message>Below is HTTP response if XInclude is enabled:</message>
  <xi:include href="` + base + `/actuator/health" parse="text"/>
</root>`
      }
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
  border-bottom: 1px solid #ccc;
}
.body-div {
  padding: 10px;
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
pre code { font-size: 12px; }
.el-row { margin-bottom: 20px; }
.el-col { border-radius: 4px; }
.bg-purple { background: #d3dce6; }
.grid-content { border-radius: 4px; height: 100%; padding: 10px; }
.grid-flex { display: flex; align-items: stretch; }
.center-dialog { text-align: center; margin: 0 auto; }
.demo-form-inline { text-align: left; }
.result-display { margin-top: 20px; text-align: center; }
.result-display h4 { text-align: left; margin-bottom: 10px; }
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
