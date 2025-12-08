<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">XML外部实体注入（XXE）漏洞</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              XXE（XML External Entity Injection，XML外部实体注入）是一种针对解析XML输入的应用程序的攻击。当XML解析器配置不当时，攻击者可以通过构造恶意的XML文档来读取服务器文件、执行SSRF攻击、造成拒绝服务等。XML标准支持外部实体功能，攻击者在DTD中定义恶意的外部实体，XML解析器在解析时会尝试加载这些外部实体，通过file://、http://等协议读取文件或发起请求。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 读取敏感文件：可以读取/etc/passwd、配置文件、源代码等服务器文件<br/>
              2. SSRF攻击：探测内网主机和服务，访问内网资源<br/>
              3. 拒绝服务：通过XML炸弹（Billion Laughs Attack）消耗服务器资源<br/>
              4. 端口扫描：探测内网开放端口<br/>
              5. 数据外泄：通过外带通道泄露敏感信息<br/>
              6. 影响范围：所有接受XML输入的应用、SOAP/XML Web Services、文件上传（SVG、DOCX、XLSX）
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】禁用DTD（最彻底的方式）<br/>
              1. 设置 disallow-doctype-decl 特性，完全禁止DTD解析<br/>
              <br/>
              【必须】禁用外部实体<br/>
              1. 禁用 external-general-entities 和 external-parameter-entities<br/>
              2. 禁用 load-external-dtd 特性，防止加载外部DTD<br/>
              <br/>
              【建议】禁用XInclude和实体扩展<br/>
              1. XInclude也可能被用于XXE攻击<br/>
              2. 使用安全的XML解析库，如Jackson的XML模块
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing" target="_blank" style="text-decoration: underline;">《OWASP XXE漏洞详解》</a><br/>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《XXE防护速查表》</a><br/>
              <a href="https://portswigger.net/web-security/xxe" target="_blank" style="text-decoration: underline;">《PortSwigger XXE教程》</a>
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
              漏洞代码 - DocumentBuilder解析器XXE
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * XXE漏洞 - 漏洞代码
 * 未禁用外部实体，存在XXE漏洞
 */
@PostMapping("/vuln")
public Result xxeVulnerable(@RequestBody String xmlContent) {
    if (xmlContent == null || xmlContent.trim().isEmpty()) {
        return Result.error("XML内容不能为空");
    }
    
    try {
        // 危险：默认配置允许外部实体
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        
        Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
        String result = doc.getDocumentElement().getTextContent();
        
        return Result.success(result);
    } catch (Exception e) {
        return Result.error("XML解析失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - DocumentBuilder禁用外部实体
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * XXE漏洞 - 安全代码
 * 禁用外部实体和DTD，防止XXE攻击
 */
@PostMapping("/sec")
public Result xxeSecure(@RequestBody String xmlContent) {
    try {
        // 安全：禁用所有可能导致XXE的功能
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // 禁用DTD
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // 禁用外部通用实体
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // 禁用外部参数实体
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        // 禁用外部DTD
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // 禁用XInclude
        dbf.setXIncludeAware(false);
        // 禁用实体扩展
        dbf.setExpandEntityReferences(false);
        
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
        String result = doc.getDocumentElement().getTextContent();
        
        return Result.success(result);
    } catch (Exception e) {
        return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - SAX解析器XXE
              <el-button type="danger" round size="mini" @click="showSaxVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * SAXParser 漏洞代码
 * SAX解析器，默认配置存在XXE漏洞
 */
@PostMapping("/sax/vuln")
public Result saxVulnerable(@RequestBody String xmlContent) {
    try {
        // 危险：默认配置允许外部实体
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();
        
        ContentHandler handler = new ContentHandler();
        saxParser.parse(new InputSource(new StringReader(xmlContent)), handler);
        
        return Result.success(handler.getContent());
    } catch (Exception e) {
        return Result.error("XML解析失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - SAX禁用外部实体
              <el-button type="success" round size="mini" @click="showSaxSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * SAXParser 安全代码
 * 禁用外部实体和DTD
 */
@PostMapping("/sax/sec")
public Result saxSecure(@RequestBody String xmlContent) {
    try {
        // 安全：禁用外部实体
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        SAXParser saxParser = factory.newSAXParser();
        ContentHandler handler = new ContentHandler();
        saxParser.parse(new InputSource(new StringReader(xmlContent)), handler);
        
        return Result.success(handler.getContent());
    } catch (Exception e) {
        return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - StAX解析器XXE
              <el-button type="danger" round size="mini" @click="showStaxVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * XMLStreamReader 漏洞代码
 * StAX解析器，默认配置存在XXE漏洞
 */
@PostMapping("/stax/vuln")
public Result staxVulnerable(@RequestBody String xmlContent) {
    try {
        // 危险：默认配置允许外部实体
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        StringBuilder content = new StringBuilder();
        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamReader.CHARACTERS) {
                content.append(reader.getText());
            }
        }
        
        return Result.success(content.toString().trim());
    } catch (Exception e) {
        return Result.error("XML解析失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - StAX禁用DTD和外部实体
              <el-button type="success" round size="mini" @click="showStaxSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * XMLStreamReader 安全代码
 * 禁用外部实体和DTD
 */
@PostMapping("/stax/sec")
public Result staxSecure(@RequestBody String xmlContent) {
    try {
        // 安全：禁用外部实体和DTD
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        StringBuilder content = new StringBuilder();
        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamReader.CHARACTERS) {
                content.append(reader.getText());
            }
        }
        
        return Result.success(content.toString().trim());
    } catch (Exception e) {
        return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - JAXB自动绑定XXE
              <el-button type="danger" round size="mini" @click="showJaxbVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * Unmarshaller 漏洞代码
 * JAXB解析器，默认配置存在XXE漏洞
 */
@PostMapping("/jaxb/vuln")
public Result jaxbVulnerable(@RequestBody String xmlContent) {
    try {
        // 危险：默认配置允许外部实体
        JAXBContext context = JAXBContext.newInstance(XmlUser.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        
        XmlUser user = (XmlUser) unmarshaller.unmarshal(new StringReader(xmlContent));
        
        return Result.success(user.getName());
    } catch (Exception e) {
        return Result.error("XML解析失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - JAXB使用安全的SAXSource
              <el-button type="success" round size="mini" @click="showJaxbSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * Unmarshaller 安全代码
 * 使用安全的XMLReader
 */
@PostMapping("/jaxb/sec")
public Result jaxbSecure(@RequestBody String xmlContent) {
    try {
        // 安全：使用配置了安全特性的SAXParser
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        SAXParser saxParser = spf.newSAXParser();
        
        JAXBContext context = JAXBContext.newInstance(XmlUser.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        
        SAXSource source = new SAXSource(
            saxParser.getXMLReader(), 
            new InputSource(new StringReader(xmlContent))
        );
        
        XmlUser user = (XmlUser) unmarshaller.unmarshal(source);
        
        return Result.success(user.getName());
    } catch (Exception e) {
        return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - SAXReader(dom4j)XXE
              <el-button type="danger" round size="mini" @click="showDom4jVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * SAXReader 漏洞代码
 * dom4j库的SAXReader解析器，默认配置存在XXE漏洞
 */
@PostMapping("/dom4j/vuln")
public Result dom4jVulnerable(@RequestBody String xmlContent) {
    try {
        // 危险：默认配置允许外部实体
        SAXReader reader = new SAXReader();
        org.dom4j.Document doc = reader.read(new StringReader(xmlContent));
        
        String result = doc.getRootElement().getText();
        
        return Result.success(result);
    } catch (Exception e) {
        return Result.error("XML解析失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - SAXReader禁用外部实体
              <el-button type="success" round size="mini" @click="showDom4jSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * SAXReader 安全代码
 * 禁用外部实体和DTD
 */
@PostMapping("/dom4j/sec")
public Result dom4jSecure(@RequestBody String xmlContent) {
    try {
        // 安全：禁用外部实体
        SAXReader reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        org.dom4j.Document doc = reader.read(new StringReader(xmlContent));
        String result = doc.getRootElement().getText();
        
        return Result.success(result);
    } catch (Exception e) {
        return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - TransformerFactory(XSLT)XXE
              <el-button type="danger" round size="mini" @click="showXsltVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * TransformerFactory 漏洞代码
 * XSLT转换器，默认配置存在XXE漏洞
 */
@PostMapping("/xslt/vuln")
public Result xsltVulnerable(@RequestBody String xmlContent) {
    try {
        // 危险：默认配置允许外部实体
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        
        StreamSource source = new StreamSource(new StringReader(xmlContent));
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        
        transformer.transform(source, result);
        
        return Result.success(writer.toString());
    } catch (Exception e) {
        return Result.error("XML转换失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - TransformerFactory禁用外部实体
              <el-button type="success" round size="mini" @click="showXsltSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * TransformerFactory 安全代码
 * 禁用外部实体和DTD
 */
@PostMapping("/xslt/sec")
public Result xsltSecure(@RequestBody String xmlContent) {
    try {
        // 安全：禁用外部实体和DTD
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        
        Transformer transformer = factory.newTransformer();
        
        StreamSource source = new StreamSource(new StringReader(xmlContent));
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        
        transformer.transform(source, result);
        
        return Result.success(writer.toString());
    } catch (Exception e) {
        return Result.error("XML转换失败（安全机制生效）: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- DocumentBuilder 漏洞测试对话框 -->
    <el-dialog title="XXE漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，以下是一些常见的XXE攻击payload：<br>
        1. 读取 /etc/passwd 文件（Linux）<br>
        2. 读取 /etc/hosts 文件<br>
        3. SSRF 攻击示例<br>
        4. 正常XML（无攻击）
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="vulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateVulnPayload" style="width: 100%">
            <el-option label="【安全】正常XML" value="normal"></el-option>
            <el-option label="【危险】读取 /etc/passwd" value="passwd"></el-option>
            <el-option label="【危险】读取 /etc/hosts" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="vulnForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
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

    <!-- 安全代码测试对话框 -->
    <el-dialog title="XXE安全防护测试" :visible.sync="secDialogVisible" class="center-dialog">
      <div style="text-align: left; color: green; font-style: italic;">
        安全代码已禁用外部实体和DTD，以下攻击payload将被拦截：<br>
        测试相同的payload，观察安全机制如何阻止XXE攻击。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="secForm.selectedPayload" placeholder="请选择测试Payload" @change="updateSecPayload" style="width: 100%">
            <el-option label="【安全】正常XML - 应该成功" value="normal"></el-option>
            <el-option label="读取 /etc/passwd - 应该被拦截" value="passwd"></el-option>
            <el-option label="读取 /etc/hosts - 应该被拦截" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例 - 应该被拦截" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="secForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
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

    <!-- SAXParser 漏洞测试对话框 -->
    <el-dialog title="SAXParser XXE漏洞测试" :visible.sync="saxVulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        SAXParser是事件驱动的XML解析器，默认配置同样存在XXE漏洞。<br>
        测试以下payload验证漏洞是否存在。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="saxVulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateSaxVulnPayload" style="width: 100%">
            <el-option label="【安全】正常XML" value="normal"></el-option>
            <el-option label="【危险】读取 /etc/passwd" value="passwd"></el-option>
            <el-option label="【危险】读取 /etc/hosts" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="saxVulnForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testSaxVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="saxVulnForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ saxVulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- SAXParser 安全代码测试对话框 -->
    <el-dialog title="SAXParser XXE安全防护测试" :visible.sync="saxSecDialogVisible" class="center-dialog">
      <div style="text-align: left; color: green; font-style: italic;">
        安全代码已禁用外部实体和DTD，攻击payload将被拦截。<br>
        测试相同的payload，观察安全机制如何阻止XXE攻击。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="saxSecForm.selectedPayload" placeholder="请选择测试Payload" @change="updateSaxSecPayload" style="width: 100%">
            <el-option label="【安全】正常XML - 应该成功" value="normal"></el-option>
            <el-option label="读取 /etc/passwd - 应该被拦截" value="passwd"></el-option>
            <el-option label="读取 /etc/hosts - 应该被拦截" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例 - 应该被拦截" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="saxSecForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testSaxSecure">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="saxSecForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ saxSecForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- StAX 漏洞测试对话框 -->
    <el-dialog title="XMLStreamReader (StAX) XXE漏洞测试" :visible.sync="staxVulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        StAX是流式API for XML，基于游标方式解析，默认配置存在XXE漏洞。<br>
        测试以下payload验证漏洞是否存在。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="staxVulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateStaxVulnPayload" style="width: 100%">
            <el-option label="【安全】正常XML" value="normal"></el-option>
            <el-option label="【危险】读取 /etc/passwd" value="passwd"></el-option>
            <el-option label="【危险】读取 /etc/hosts" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="staxVulnForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testStaxVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="staxVulnForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ staxVulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- StAX 安全代码测试对话框 -->
    <el-dialog title="XMLStreamReader (StAX) XXE安全防护测试" :visible.sync="staxSecDialogVisible" class="center-dialog">
      <div style="text-align: left; color: green; font-style: italic;">
        安全代码已禁用外部实体和DTD，攻击payload将被拦截。<br>
        测试相同的payload，观察安全机制如何阻止XXE攻击。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="staxSecForm.selectedPayload" placeholder="请选择测试Payload" @change="updateStaxSecPayload" style="width: 100%">
            <el-option label="【安全】正常XML - 应该成功" value="normal"></el-option>
            <el-option label="读取 /etc/passwd - 应该被拦截" value="passwd"></el-option>
            <el-option label="读取 /etc/hosts - 应该被拦截" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例 - 应该被拦截" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="staxSecForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testStaxSecure">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="staxSecForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ staxSecForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- JAXB 漏洞测试对话框 -->
    <el-dialog title="Unmarshaller (JAXB) XXE漏洞测试" :visible.sync="jaxbVulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        JAXB用于XML与Java对象映射，默认配置的Unmarshaller存在XXE漏洞。<br>
        测试以下payload验证漏洞是否存在。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="jaxbVulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateJaxbVulnPayload" style="width: 100%">
            <el-option label="【安全】正常XML" value="normal"></el-option>
            <el-option label="【危险】读取 /etc/passwd" value="passwd"></el-option>
            <el-option label="【危险】读取 /etc/hosts" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="jaxbVulnForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testJaxbVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="jaxbVulnForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ jaxbVulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- JAXB 安全代码测试对话框 -->
    <el-dialog title="Unmarshaller (JAXB) XXE安全防护测试" :visible.sync="jaxbSecDialogVisible" class="center-dialog">
      <div style="text-align: left; color: green; font-style: italic;">
        安全代码已禁用外部实体和DTD，攻击payload将被拦截。<br>
        测试相同的payload，观察安全机制如何阻止XXE攻击。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="jaxbSecForm.selectedPayload" placeholder="请选择测试Payload" @change="updateJaxbSecPayload" style="width: 100%">
            <el-option label="【安全】正常XML - 应该成功" value="normal"></el-option>
            <el-option label="读取 /etc/passwd - 应该被拦截" value="passwd"></el-option>
            <el-option label="读取 /etc/hosts - 应该被拦截" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例 - 应该被拦截" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="jaxbSecForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testJaxbSecure">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="jaxbSecForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ jaxbSecForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- SAXReader (dom4j) 漏洞测试对话框 -->
    <el-dialog title="dom4j SAXReader XXE漏洞测试" :visible.sync="dom4jVulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        dom4j是一个流行的Java XML解析库，默认配置存在XXE漏洞。<br>
        测试以下payload验证漏洞是否存在。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="dom4jVulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateDom4jVulnPayload" style="width: 100%">
            <el-option label="【安全】正常XML" value="normal"></el-option>
            <el-option label="【危险】读取 /etc/passwd" value="passwd"></el-option>
            <el-option label="【危险】读取 /etc/hosts" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="dom4jVulnForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testDom4jVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="dom4jVulnForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ dom4jVulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- SAXReader (dom4j) 安全测试对话框 -->
    <el-dialog title="dom4j SAXReader 安全防护测试" :visible.sync="dom4jSecDialogVisible" class="center-dialog">
      <div style="text-align: left; color: green; font-style: italic;">
        安全代码已禁用外部实体和DTD，攻击payload将被拦截。<br>
        测试相同的payload，观察安全机制如何阻止XXE攻击。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="dom4jSecForm.selectedPayload" placeholder="请选择测试Payload" @change="updateDom4jSecPayload" style="width: 100%">
            <el-option label="【安全】正常XML - 应该成功" value="normal"></el-option>
            <el-option label="读取 /etc/passwd - 应该被拦截" value="passwd"></el-option>
            <el-option label="读取 /etc/hosts - 应该被拦截" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例 - 应该被拦截" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="dom4jSecForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testDom4jSecure">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="dom4jSecForm.result" class="result-display">
        <h4>解析结果：</h4>
        <div class="result-text">
          <pre>{{ dom4jSecForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- TransformerFactory (XSLT) 漏洞测试对话框 -->
    <el-dialog title="TransformerFactory XSLT XXE漏洞测试" :visible.sync="xsltVulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        XSLT转换器用于XML样式转换，默认配置存在XXE漏洞。<br>
        测试以下payload验证漏洞是否存在。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="xsltVulnForm.selectedPayload" placeholder="请选择测试Payload" @change="updateXsltVulnPayload" style="width: 100%">
            <el-option label="【安全】正常XML" value="normal"></el-option>
            <el-option label="【危险】读取 /etc/passwd" value="passwd"></el-option>
            <el-option label="【危险】读取 /etc/hosts" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="xsltVulnForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testXsltVulnerable">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="xsltVulnForm.result" class="result-display">
        <h4>转换结果：</h4>
        <div class="result-text">
          <pre>{{ xsltVulnForm.result }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- TransformerFactory (XSLT) 安全测试对话框 -->
    <el-dialog title="TransformerFactory XSLT 安全防护测试" :visible.sync="xsltSecDialogVisible" class="center-dialog">
      <div style="text-align: left; color: green; font-style: italic;">
        安全代码已禁用外部实体和DTD，攻击payload将被拦截。<br>
        测试相同的payload，观察安全机制如何阻止XXE攻击。
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="选择Payload">
          <el-select v-model="xsltSecForm.selectedPayload" placeholder="请选择测试Payload" @change="updateXsltSecPayload" style="width: 100%">
            <el-option label="【安全】正常XML - 应该成功" value="normal"></el-option>
            <el-option label="读取 /etc/passwd - 应该被拦截" value="passwd"></el-option>
            <el-option label="读取 /etc/hosts - 应该被拦截" value="hosts"></el-option>
            <el-option label="【危险】SSRF攻击示例 - 应该被拦截" value="ssrf"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="XML内容">
          <el-input v-model="xsltSecForm.xmlContent" type="textarea" :rows="8" placeholder="请输入XML内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="testXsltSecure">提交测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="xsltSecForm.result" class="result-display">
        <h4>转换结果：</h4>
        <div class="result-text">
          <pre>{{ xsltSecForm.result }}</pre>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { xxeVulnerable, xxeSecure, saxVulnerable, saxSecure, staxVulnerable, staxSecure, jaxbVulnerable, jaxbSecure, dom4jVulnerable, dom4jSecure, xsltVulnerable, xsltSecure } from '@/api/xml';

export default {
  data() {
    return {
      activeName: 'first',
      // DocumentBuilder
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
      },
      // SAXParser
      saxVulnDialogVisible: false,
      saxSecDialogVisible: false,
      saxVulnForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      saxSecForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      // XMLStreamReader (StAX)
      staxVulnDialogVisible: false,
      staxSecDialogVisible: false,
      staxVulnForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      staxSecForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      // Unmarshaller (JAXB)
      jaxbVulnDialogVisible: false,
      jaxbSecDialogVisible: false,
      jaxbVulnForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      jaxbSecForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      // SAXReader (dom4j)
      dom4jVulnDialogVisible: false,
      dom4jSecDialogVisible: false,
      dom4jVulnForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      dom4jSecForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      // TransformerFactory (XSLT)
      xsltVulnDialogVisible: false,
      xsltSecDialogVisible: false,
      xsltVulnForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      },
      xsltSecForm: {
        selectedPayload: '',
        xmlContent: '',
        result: ''
      }
    };
  },
  methods: {
    handleClick(tab, event) {
      // Tab切换处理
    },
    showVulnDialog() {
      this.vulnDialogVisible = true;
      this.vulnForm.selectedPayload = '';
      this.vulnForm.xmlContent = '';
      this.vulnForm.result = '';
    },
    showSecDialog() {
      this.secDialogVisible = true;
      this.secForm.selectedPayload = '';
      this.secForm.xmlContent = '';
      this.secForm.result = '';
    },
    updateVulnPayload() {
      const payloads = this.getPayloads();
      this.vulnForm.xmlContent = payloads[this.vulnForm.selectedPayload] || '';
    },
    updateSecPayload() {
      const payloads = this.getPayloads();
      this.secForm.xmlContent = payloads[this.secForm.selectedPayload] || '';
    },
    testVulnerable() {
      if (!this.vulnForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      xxeVulnerable(this.vulnForm.xmlContent)
        .then(response => {
          this.vulnForm.result = response.data;
        })
        .catch(error => {
          this.vulnForm.result = 'XML解析失败: ' + (error.msg || error.message || '未知错误');
        });
    },
    testSecure() {
      if (!this.secForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      xxeSecure(this.secForm.xmlContent)
        .then(response => {
          this.secForm.result = response.data;
        })
        .catch(error => {
          this.secForm.result = '安全机制生效，攻击被拦截: ' + (error.msg || error.message || '未知错误');
        });
    },

    // ==================== SAXParser 方法 ====================
    showSaxVulnDialog() {
      this.saxVulnDialogVisible = true;
      this.saxVulnForm.selectedPayload = '';
      this.saxVulnForm.xmlContent = '';
      this.saxVulnForm.result = '';
    },
    showSaxSecDialog() {
      this.saxSecDialogVisible = true;
      this.saxSecForm.selectedPayload = '';
      this.saxSecForm.xmlContent = '';
      this.saxSecForm.result = '';
    },
    updateSaxVulnPayload() {
      const payloads = this.getPayloads();
      this.saxVulnForm.xmlContent = payloads[this.saxVulnForm.selectedPayload] || '';
    },
    updateSaxSecPayload() {
      const payloads = this.getPayloads();
      this.saxSecForm.xmlContent = payloads[this.saxSecForm.selectedPayload] || '';
    },
    testSaxVulnerable() {
      if (!this.saxVulnForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      saxVulnerable(this.saxVulnForm.xmlContent)
        .then(response => {
          this.saxVulnForm.result = response.data;
        })
        .catch(error => {
          this.saxVulnForm.result = 'XML解析失败: ' + (error.msg || error.message || '未知错误');
        });
    },
    testSaxSecure() {
      if (!this.saxSecForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      saxSecure(this.saxSecForm.xmlContent)
        .then(response => {
          this.saxSecForm.result = response.data;
        })
        .catch(error => {
          this.saxSecForm.result = '安全机制生效，攻击被拦截: ' + (error.msg || error.message || '未知错误');
        });
    },

    // ==================== StAX 方法 ====================
    showStaxVulnDialog() {
      this.staxVulnDialogVisible = true;
      this.staxVulnForm.selectedPayload = '';
      this.staxVulnForm.xmlContent = '';
      this.staxVulnForm.result = '';
    },
    showStaxSecDialog() {
      this.staxSecDialogVisible = true;
      this.staxSecForm.selectedPayload = '';
      this.staxSecForm.xmlContent = '';
      this.staxSecForm.result = '';
    },
    updateStaxVulnPayload() {
      const payloads = this.getPayloads();
      this.staxVulnForm.xmlContent = payloads[this.staxVulnForm.selectedPayload] || '';
    },
    updateStaxSecPayload() {
      const payloads = this.getPayloads();
      this.staxSecForm.xmlContent = payloads[this.staxSecForm.selectedPayload] || '';
    },
    testStaxVulnerable() {
      if (!this.staxVulnForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      staxVulnerable(this.staxVulnForm.xmlContent)
        .then(response => {
          this.staxVulnForm.result = response.data;
        })
        .catch(error => {
          this.staxVulnForm.result = 'XML解析失败: ' + (error.msg || error.message || '未知错误');
        });
    },
    testStaxSecure() {
      if (!this.staxSecForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      staxSecure(this.staxSecForm.xmlContent)
        .then(response => {
          this.staxSecForm.result = response.data;
        })
        .catch(error => {
          this.staxSecForm.result = '安全机制生效，攻击被拦截: ' + (error.msg || error.message || '未知错误');
        });
    },

    // ==================== JAXB 方法 ====================
    showJaxbVulnDialog() {
      this.jaxbVulnDialogVisible = true;
      this.jaxbVulnForm.selectedPayload = '';
      this.jaxbVulnForm.xmlContent = '';
      this.jaxbVulnForm.result = '';
    },
    showJaxbSecDialog() {
      this.jaxbSecDialogVisible = true;
      this.jaxbSecForm.selectedPayload = '';
      this.jaxbSecForm.xmlContent = '';
      this.jaxbSecForm.result = '';
    },
    updateJaxbVulnPayload() {
      const payloads = this.getPayloads();
      this.jaxbVulnForm.xmlContent = payloads[this.jaxbVulnForm.selectedPayload] || '';
    },
    updateJaxbSecPayload() {
      const payloads = this.getPayloads();
      this.jaxbSecForm.xmlContent = payloads[this.jaxbSecForm.selectedPayload] || '';
    },
    testJaxbVulnerable() {
      if (!this.jaxbVulnForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      jaxbVulnerable(this.jaxbVulnForm.xmlContent)
        .then(response => {
          this.jaxbVulnForm.result = response.data;
        })
        .catch(error => {
          this.jaxbVulnForm.result = 'XML解析失败: ' + (error.msg || error.message || '未知错误');
        });
    },
    testJaxbSecure() {
      if (!this.jaxbSecForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      jaxbSecure(this.jaxbSecForm.xmlContent)
        .then(response => {
          this.jaxbSecForm.result = response.data;
        })
        .catch(error => {
          this.jaxbSecForm.result = '安全机制生效，攻击被拦截: ' + (error.msg || error.message || '未知错误');
        });
    },

    // ==================== SAXReader (dom4j) 方法 ====================
    showDom4jVulnDialog() {
      this.dom4jVulnDialogVisible = true;
      this.dom4jVulnForm.selectedPayload = '';
      this.dom4jVulnForm.xmlContent = '';
      this.dom4jVulnForm.result = '';
    },
    showDom4jSecDialog() {
      this.dom4jSecDialogVisible = true;
      this.dom4jSecForm.selectedPayload = '';
      this.dom4jSecForm.xmlContent = '';
      this.dom4jSecForm.result = '';
    },
    updateDom4jVulnPayload() {
      const payloads = this.getPayloads();
      this.dom4jVulnForm.xmlContent = payloads[this.dom4jVulnForm.selectedPayload] || '';
    },
    updateDom4jSecPayload() {
      const payloads = this.getPayloads();
      this.dom4jSecForm.xmlContent = payloads[this.dom4jSecForm.selectedPayload] || '';
    },
    testDom4jVulnerable() {
      if (!this.dom4jVulnForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      dom4jVulnerable(this.dom4jVulnForm.xmlContent)
        .then(response => {
          this.dom4jVulnForm.result = response.data;
        })
        .catch(error => {
          this.dom4jVulnForm.result = 'XML解析失败: ' + (error.msg || error.message || '未知错误');
        });
    },
    testDom4jSecure() {
      if (!this.dom4jSecForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      dom4jSecure(this.dom4jSecForm.xmlContent)
        .then(response => {
          this.dom4jSecForm.result = response.data;
        })
        .catch(error => {
          this.dom4jSecForm.result = '安全机制生效，攻击被拦截: ' + (error.msg || error.message || '未知错误');
        });
    },

    // ==================== TransformerFactory (XSLT) 方法 ====================
    showXsltVulnDialog() {
      this.xsltVulnDialogVisible = true;
      this.xsltVulnForm.selectedPayload = '';
      this.xsltVulnForm.xmlContent = '';
      this.xsltVulnForm.result = '';
    },
    showXsltSecDialog() {
      this.xsltSecDialogVisible = true;
      this.xsltSecForm.selectedPayload = '';
      this.xsltSecForm.xmlContent = '';
      this.xsltSecForm.result = '';
    },
    updateXsltVulnPayload() {
      const payloads = this.getPayloads();
      this.xsltVulnForm.xmlContent = payloads[this.xsltVulnForm.selectedPayload] || '';
    },
    updateXsltSecPayload() {
      const payloads = this.getPayloads();
      this.xsltSecForm.xmlContent = payloads[this.xsltSecForm.selectedPayload] || '';
    },
    testXsltVulnerable() {
      if (!this.xsltVulnForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      xsltVulnerable(this.xsltVulnForm.xmlContent)
        .then(response => {
          this.xsltVulnForm.result = response.data;
        })
        .catch(error => {
          this.xsltVulnForm.result = 'XML转换失败: ' + (error.msg || error.message || '未知错误');
        });
    },
    testXsltSecure() {
      if (!this.xsltSecForm.xmlContent) {
        this.$message.warning('请输入XML内容');
        return;
      }
      
      xsltSecure(this.xsltSecForm.xmlContent)
        .then(response => {
          this.xsltSecForm.result = response.data;
        })
        .catch(error => {
          this.xsltSecForm.result = '安全机制生效，攻击被拦截: ' + (error.msg || error.message || '未知错误');
        });
    },

    // ==================== 共享方法 ====================
    getPayloads() {
      return {
        'normal': `<?xml version="1.0" encoding="UTF-8"?>
<user>
    <name>张三</name>
    <age>25</age>
</user>`,
        'passwd': `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
    <name>&xxe;</name>
</user>`,
        'hosts': `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<user>
    <name>&xxe;</name>
</user>`,
        'ssrf': `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://localhost:8080/actuator/health">
]>
<user>
    <name>&xxe;</name>
</user>`
      };
    }
  }
};
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
