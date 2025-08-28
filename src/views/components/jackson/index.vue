<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">组件漏洞 -- Jackson反序列化漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            Jackson反序列化漏洞是指由于使用不安全的Jackson配置进行JSON数据反序列化，导致攻击者可以通过构造恶意JSON数据触发反序列化漏洞，从而在目标系统上执行任意代码。<br/><br/>
                            <span style="color: red;">Jackson是一个流行的Java JSON处理库，用于将对象序列化为JSON格式，以及从JSON反序列化对象。当启用多态反序列化功能时，如果配置不当，可能导致严重的安全漏洞。</span><br />
                            <br/>
                            漏洞原理：<br/>
                            1. Jackson默认情况下相对安全，但启用多态反序列化时存在风险<br/>
                            2. 通过@type注解可以指定任意类进行实例化<br/>
                            3. 利用Runtime、ProcessBuilder等危险类执行系统命令<br/>
                            4. 通过JNDI注入、URLClassLoader等方式实现远程代码执行<br/>
                            <br/>
                            常见原因：<br/>
                            1. 启用了不安全的ObjectMapper配置<br/>
                            2. 使用LaissezFaireSubTypeValidator进行类型验证<br/>
                            3. 未对输入数据进行严格的类型验证和过滤<br/>
                            4. 未配置类白名单，允许危险类的加载<br/>
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
                            【必须】禁用多态反序列化<br/>
                            避免使用activateDefaultTyping()方法，特别是与LaissezFaireSubTypeValidator结合使用。<br/>
                            <br/>
                            【必须】实施类白名单验证<br/>
                            如果必须使用多态反序列化，应实施严格的类白名单验证，只允许反序列化可信任的类。<br/>
                            <br/>
                            【必须】对输入数据进行严格验证<br/>
                            对JSON输入数据进行格式验证、类型检查，确保只处理预期的数据结构。<br/>
                            <br/>
                            【建议】使用安全的ObjectMapper配置<br/>
                            禁用不必要的DeserializationFeature，只启用必要的功能。<br/>
                            <br/>
                            【建议】使用类型安全的反序列化<br/>
                            明确指定反序列化的目标类型，避免使用Object.class。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <b>相关技术文档和参考资源：</b>
                            <br/><br/>
                            <b>官方文档：</b>
                            <ul>
                                <li><a href="https://github.com/FasterXML/jackson" target="_blank" style="text-decoration: underline;">Jackson官方GitHub</a></li>
                                <li><a href="https://github.com/FasterXML/jackson-docs" target="_blank" style="text-decoration: underline;">Jackson官方文档</a></li>
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
                                <li><a href="https://blog.csdn.net/qq_45521281/article/details/106647490" target="_blank" style="text-decoration: underline;">Jackson反序列化漏洞分析</a></li>
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
                        <el-row type="flex" justify="space-between" align="middle">Jackson序列化和反序列化介绍<div>
                                <el-button type="primary" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                                                 <pre v-highlightjs><code class="java">// Jackson序列化和反序列化介绍
// 1. Jackson序列化Person对象为JSON
Person person = new Person();
person.setName("张三");
person.setAge(25);
String json = serializeToJSON(person);

// 2. Jackson反序列化JSON为Person对象
Object result = deserializeFromJSON(json);

// 后端代码 - JSON序列化接口
@PostMapping("/serializePersonToJson")
public Result serializePersonToJson(@RequestBody Person person) {
    try {
        String jsonResult = serializeToJSON(person);
        return Result.success("Jackson JSON序列化Person对象成功: " + jsonResult);
    } catch (Exception e) {
        return Result.error("Jackson JSON序列化异常: " + e.getMessage());
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
        return Result.success("Jackson JSON反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("Jackson JSON反序列化异常: " + e.getMessage());
    }
}

// JSON序列化方法
private String serializeToJSON(Object obj) throws IOException {
    ObjectMapper mapper = new ObjectMapper();
    return mapper.writeValueAsString(obj);
}

// JSON反序列化方法
private Object deserializeFromJSON(String jsonStr) throws IOException {
    ObjectMapper mapper = new ObjectMapper();
    return mapper.readValue(jsonStr, Person.class);
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用安全配置<div>
                                <el-button type="success" round size="mini"
                                    @click="fetchDataAndFillTable4">去测试</el-button>
                            </div></el-row>
                            <pre v-highlightjs><code class="java">// 安全代码 - 使用安全配置

// 安全反序列化
@PostMapping("/sec1")
public Result jacksonSec1(@RequestBody String jsonData) {
    try {
        // 使用安全配置的Jackson进行反序列化
        Object result = deserializeFromJSONSecurely(jsonData);
        return Result.success("安全配置反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("反序列化异常: " + e.getMessage());
    }
}

// 使用安全的ObjectMapper配置
private Object deserializeFromJSONSecurely(String jsonStr) throws IOException {
    ObjectMapper mapper = new ObjectMapper();
    
    // 禁用危险功能
    mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    mapper.disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);
    
    // 只允许反序列化为Person类
    return mapper.readValue(jsonStr, Person.class);
}

</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码-Jackson反序列化恶意对象<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable2">去测试</el-button>
                            </div></el-row>
                                                 <pre v-highlightjs><code class="java">// 漏洞代码-Jackson反序列化恶意对象

// JNDI注入攻击 (需要RMI/LDAP服务器)
// 注意：Jackson 2.13.5版本已阻止JdbcRowSetImpl反序列化
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName": "rmi://localhost:1099/Exploit", "autoCommit": true}]

// 后端漏洞代码
@PostMapping("/vuln1")
public Result jacksonVuln1(@RequestBody String jsonData) {
    try {
        Object result = deserializeFromJSONUnsafe(jsonData);
        return Result.success("恶意对象反序列化成功: " + result.toString());
    } catch (Exception e) {
        return Result.error("反序列化异常: " + e.getMessage());
    }
}

// 不安全的反序列化方法
private Object deserializeFromJSONUnsafe(String jsonStr) throws IOException {
    ObjectMapper mapper = new ObjectMapper();
    
    // 启用默认类型识别，使用数组格式
    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
    
    return mapper.readValue(jsonStr, Object.class);
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 - 基础功能演示 -->
        <el-dialog title="Jackson序列化和反序列化介绍" :visible.sync="dialogFormVisible1" class="center-dialog" width="60%">
            <div style="text-align: center; color: blue; font-style: italic; margin-bottom: 20px;">
                展示Jackson序列化和反序列化的完整流程：支持JSON格式的转换
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
                                <el-button type="primary" @click="serializePerson">序列化并输出JSON</el-button>
                            </el-form-item>
                        </el-form>
                        <div v-if="serializeResult" style="margin-top: 15px;">
                            <h4 style="margin: 0 0 10px 0; color: #409EFF;">序列化结果：</h4>
                            <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 12px; background-color: #f0f9ff; padding: 10px; border: 1px solid #409EFF; border-radius: 4px;">{{ serializeResult }}</pre>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="反序列化操作" name="deserialize">
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
                                <el-button type="success" @click="deserializePerson">反序列化JSON</el-button>
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
        <el-dialog title="Jackson反序列化恶意对象测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic;">
                注意：这些payload会执行系统命令或进行网络探测，请谨慎测试！
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="简单测试 Payload">
                    <el-input v-model="processBuilderPayloadMac" type="textarea" :rows="4"></el-input>
                </el-form-item>
                <el-form-item label="写文件 Payload">
                    <el-input v-model="writeFilePayload" type="textarea" :rows="4" placeholder="用于写文件攻击的JSON payload"></el-input>
                </el-form-item>
                <el-form-item label="命令执行 Payload">
                    <el-input v-model="reverseShellPayload" type="textarea" :rows="4" placeholder="用于命令执行的JSON payload"></el-input>
                </el-form-item>
                <el-form-item label="JNDI注入 Payload">
                    <el-input v-model="jndiPayload" type="textarea" :rows="4" placeholder="用于JNDI注入的JSON payload"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" @click="onSubmitProcessBuilderMac">简单测试</el-button>
                    <el-button type="warning" @click="onSubmitWriteFile">写文件测试</el-button>
                    <el-button type="danger" @click="onSubmitReverseShell">命令执行测试</el-button>
                    <el-button type="danger" @click="onSubmitJndi">JNDI注入测试</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text2"></div>
                </template>
            </div>
        </el-dialog>



        <!-- 打开嵌套表格的对话框4 - 安全配置测试 -->
        <el-dialog title="Jackson安全代码测试 - 安全配置" :visible.sync="dialogFormVisible4" class="center-dialog">
            <div style="text-align: left; color: green; font-style: italic;">
                使用安全的ObjectMapper配置，提供更强的安全保护
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Person对象JSON数据">
                    <el-input v-model="normalJsonData" type="textarea" :rows="6"></el-input>
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
import { serializePersonToJson, deserializePersonFromJson } from '@/api/jackson';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible4: false,

            
            // 基础序列化/反序列化相关
            basicTab: 'serialize',
            basicForm: {
                name: '张三',
                age: 25
            },
            serializeResult: '',
            deserializeResult: '',
            normalJsonData: '{"name": "张三", "age": 25}',
            
            // 恶意对象测试相关
            processBuilderPayloadMac: '["java.lang.ProcessBuilder", {"command": ["echo", "Jackson反序列化漏洞测试成功"]}]',
            writeFilePayload: '["java.lang.ProcessBuilder", {"command": ["touch", "/tmp/jackson_flag"]}]',
            reverseShellPayload: '["java.lang.ProcessBuilder", {"command": ["bash", "-c", "echo Jackson反序列化漏洞测试成功 > /tmp/jackson_test.txt"]}]',
            jndiPayload: '["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName": "rmi://localhost:1099/Exploit", "autoCommit": true}]',
            resp_text2: '',
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
        },
        fetchDataAndFillTable2() {
            this.$message.info('抱歉，暂时无法提供Jackson漏洞环境');
        },

        fetchDataAndFillTable4() {
            this.$message.info('抱歉，暂时无法提供Jackson漏洞环境');
        },


        serializePerson() {
            if (!this.basicForm.name || !this.basicForm.age) {
                this.$message.error('请填写姓名和年龄');
                return;
            }
            serializePersonToJson(this.basicForm).then(response => {
                this.serializeResult = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.serializeResult = 'Error fetching data: ' + error.message;
            });
        },
        deserializePerson() {
            if (!this.normalJsonData) {
                this.$message.error('JSON数据不能为空');
                return;
            }
            deserializePersonFromJson(this.normalJsonData).then(response => {
                this.deserializeResult = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.deserializeResult = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitProcessBuilderMac() {
            if (!this.processBuilderPayloadMac) {
                this.$message.error('ProcessBuilder Payload不能为空');
                return;
            }
            jacksonVuln1(this.processBuilderPayloadMac).then(response => {
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
            jacksonVuln1(this.writeFilePayload).then(response => {
                this.resp_text2 = response.data + "\n\n请检查/tmp/jackson_flag文件是否被创建";
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitReverseShell() {
            if (!this.reverseShellPayload) {
                this.$message.error('命令执行 Payload不能为空');
                return;
            }
            jacksonVuln1(this.reverseShellPayload).then(response => {
                this.resp_text2 = response.data + "\n\n请检查/tmp/jackson_test.txt文件是否被创建";
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitJndi() {
            if (!this.jndiPayload) {
                this.$message.error('JNDI注入 Payload不能为空');
                return;
            }
            jacksonVuln1(this.jndiPayload).then(response => {
                this.resp_text2 = response.data + "\n\n注意：JNDI注入需要RMI/LDAP服务器支持";
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text2 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitSec2Normal() {
            if (!this.normalJsonData) {
                this.$message.error('Person对象JSON数据不能为空');
                return;
            }
            jacksonSec2(this.normalJsonData).then(response => {
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
            jacksonSec2(this.processBuilderPayloadMac).then(response => {
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
