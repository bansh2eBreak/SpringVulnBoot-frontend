<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">任意命令执行</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            任意命令执行漏洞（Remote Code
                            Execution，RCE）是一种常见的、非常严重的安全漏洞，当应用程序没有对用户输入进行充分过滤或验证时，攻击者就可以通过构造特殊的输入，让服务器执行任意的系统命令。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            任意命令执行漏洞的危害在于攻击者可以利用漏洞执行恶意系统命令，导致系统被完全控制，敏感数据泄露，系统崩溃，甚至造成服务中断和损失。攻击者可以执行恶意操作，包括删除文件、植入后门、修改数据等，严重影响系统的安全性和稳定性。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【建议】避免不可信数据拼接操作系统命令 <br />
                            当不可信数据存在时，应尽量避免外部数据拼接到操作系统命令使用 Runtime 和 ProcessBuilder <br />
                            来执行。优先使用其他同类操作进行代替，比如通过文件系统API进行文件操作而非直接调用操作系统命令。<br />
                            <br />
                            【必须】避免创建SHELL操作<br />
                            禁止外部数据直接直接作为操作系统命令执行。<br />
                            避免通过"cmd"、“bash”、“sh”等命令创建shell后拼接外部数据来执行操作系统命令。<br />
                            对外部传入数据进行过滤。可通过白名单限制字符类型，仅允许字符、数字、下划线；或过滤转义以下符号：|;&$&lt;&gt;`（反引号）!
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <!-- 给超链接配置下划线 -->
                            <a href="https://y4er.com/posts/java-exec-command/" target="_blank"
                                style="text-decoration: underline;">《Java下多种执行命令的姿势及问题》</a>
                            <br />
                            <a href="https://xz.aliyun.com/t/15874?time__1311=GqjxnDgQDQGQqGXPeeqBK0QG8F8CuG%2B7LbD#toc-5"
                                target="_blank" style="text-decoration: underline;">《JAVA安全之命令执行研究分析》</a>
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - Runtime方式<div><el-button
                                    type="danger" round size="mini" @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">@RestController
@Slf4j
@RequestMapping("/rce")
public class RCEController {
    /**
     * @Poc：http://127.0.0.1:8080/rce/vulnPing?ip=127.0.0.1 -c 1;whoami
     * @param ip IP地址
     * @return  返回命令执行结果
     */
    @GetMapping("/vulnPing")
    public String vulnPing(String ip) {
        String line;    // 用于保存命令执行结果
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};

        try {
            // 执行命令并获取进程
            Process process = Runtime.getRuntime().exec(cmd);

            // 获取命令的输出流
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            // 获取命令的错误流
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            int exitValue = process.waitFor();
            System.out.println("Process exited with value " + exitValue);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        //将命令执行结果或者错误结果输出
        return Result.success(sb.toString());
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 自定义过滤<div><el-button
                                    type="success" round size="mini" @click="fetchDataAndFillTable2">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">/**
 * 命令执行恶意字符检测
 */
public static boolean checkCommand(String content) {
    String[] black_list = {";", "&&", "||", "`", "$", "(", ")", "&gt;", "&lt;", "|", "\\", "[", "]", "{", "}", "echo", "exec", "system", "passthru", "popen", "proc_open", "shell_exec", "eval", "assert"};
    for (String str : black_list) {
        if (content.toLowerCase().contains(str)) {
            return true;
        }
    }
    return false;
}

@GetMapping("/secPing")
public String secPing(String ip) {
    if (Security.checkCommand(ip)) {
        log.warn("非法字符：{}", ip);
        return "检测到非法命令注入！";
    }

    String line;
    StringBuilder sb = new StringBuilder();

    // 要执行的命令
    String[] cmd = {"bash" , "-c", "ping " + ip};

    ...... //其他代码省略
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - ProcessBuilder方式
                            <div><el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable3">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">/**
 * @Poc： http://127.0.0.1:8080/rce/vulnPing2?ip=127.0.0.1 -c 1;whoami
 * @param ip
 * @return
 */
@GetMapping("/vulnPing2")
public String vulnPing2(String ip) {
    String line;
    StringBuilder sb = new StringBuilder();

    // 要执行的命令
    String[] cmd = {"bash" , "-c", "ping " + ip};

    try {
        // 执行命令并获取进程
        ProcessBuilder processBuilder = new ProcessBuilder(cmd);
        // ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", "ping " + ip); // 也可以这样写
        Process process = processBuilder.start();

        // 获取命令的输出流
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }

        // 获取命令的错误流
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        while ((line = errorReader.readLine()) != null) {
            sb.append(line).append("\n");
        }

        int exitValue = process.waitFor();
        System.out.println("Process exited with value " + exitValue);

    } catch (IOException | InterruptedException e) {
        e.printStackTrace();
    }
    //将命令执行结果或者错误结果输出
    return Result.success(sb.toString());
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 合法IP地址检测
                            <div><el-button type="success" round size="mini"
                                    @click="fetchDataAndFillTable4">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// 合法IP地址检测
public static boolean checkIp(String ip) {
    String[] ipArr = ip.split("\\.");
    if (ipArr.length != 4) {
        return false;
    }
    for (String ipSegment : ipArr) {
        //需要进行异常判断，万一不是数字
        try {
            int ipSegmentInt = Integer.parseInt(ipSegment);
            if (ipSegmentInt &lt; 0 || ipSegmentInt &gt; 255) {
                return false;
            }
        } catch (NumberFormatException e) {
            return false;
        }
    }
    return true;
}

/**
 * @Poc：http://127.0.0.1:8080/rce/secPing2?ip=127.0.0.1 -c 1;whoami
 * @param ip
 * @return
 */
@GetMapping("/secPing2")
public String secPing2(String ip) {
    if (Security.checkIp(ip)) {
        String line;
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};

        try {
            // 执行命令并获取进程
            ProcessBuilder processBuilder = new ProcessBuilder(cmd);

            // 设置超时时间为10秒
            // 退出值为 124 表示进程因为超时被终止
            processBuilder.command().add(0, "timeout");
            processBuilder.command().add(1, "10s");

            Process process = processBuilder.start();
            // 其他代码省略
        }
    }
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
        <!-- 打开嵌套表单的对话框1 -->
        <el-dialog title="Ping测试" :visible.sync="dialogFormVisible1" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="Ping">
                    <el-input v-model="ipaddress1"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit1">测试</el-button>
                </el-form-item>
                <br />
                <pre>{{ pingResult1 }}</pre>
            </el-form>
        </el-dialog>
        <!-- 打开嵌套表单的对话框2 -->
        <el-dialog title="Ping测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="Ping">
                    <el-input v-model="ipaddress2"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit2">测试</el-button>
                </el-form-item>
                <br />
                <pre>{{ pingResult2 }}</pre>
            </el-form>
        </el-dialog>
        <!-- 打开嵌套表单的对话框3 -->
        <el-dialog title="Ping测试" :visible.sync="dialogFormVisible3" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="Ping">
                    <el-input v-model="ipaddress3"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit3">测试</el-button>
                </el-form-item>
                <br />
                <pre>{{ pingResult3 }}</pre>
            </el-form>
        </el-dialog>
        <!-- 打开嵌套表单的对话框4 -->
        <el-dialog title="Ping测试" :visible.sync="dialogFormVisible4" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="Ping">
                    <el-input v-model="ipaddress4"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit4">测试</el-button>
                </el-form-item>
                <br />
                <pre>{{ pingResult4 }}</pre>
            </el-form>
        </el-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import { vulnPing, secPing, vulnPing2, secPing2 } from '@/api/rce';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false,
            dialogFormVisible4: false,
            ipaddress1: '127.0.0.1 -c 1;whoami',
            ipaddress2: '127.0.0.1 -c 1;whoami',
            ipaddress3: '127.0.0.1 -c 1;whoami',
            ipaddress4: '127.0.0.1 -c 1;whoami',
            pingResult1: '',
            pingResult2: '',
            pingResult3: '',
            pingResult4: '',
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true; // 显示对话框
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true; // 显示对话框
        },
        fetchDataAndFillTable3() {
            this.dialogFormVisible3 = true; // 显示对话框
        },
        fetchDataAndFillTable4() {
            this.dialogFormVisible4 = true; // 显示对话框
        },
        onSubmit1() {
            if (!this.ipaddress1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('留言内容不能为空');
                return;
            }
            vulnPing({ ip: this.ipaddress1 })
                .then(response => {
                    // 展示返回的数据
                    this.pingResult1 = response.data;
                }).catch(error => {
                    // 处理异常
                });
        },
        onSubmit2() {
            if (!this.ipaddress2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('留言内容不能为空');
                return;
            }
            secPing({ ip: this.ipaddress2 })
                .then(response => {
                    // 展示返回的数据
                    this.pingResult2 = response.data;
                }).catch(error => {
                    // 处理异常
                });
        },
        onSubmit3() {
            if (!this.ipaddress3) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('留言内容不能为空');
                return;
            }
            vulnPing2({ ip: this.ipaddress3 })
                .then(response => {
                    // 展示返回的数据
                    this.pingResult3 = response.data;
                }).catch(error => {
                    // 处理异常
                });
        },
        onSubmit4() {
            if (!this.ipaddress4) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('留言内容不能为空');
                return;
            }
            secPing2({ ip: this.ipaddress4 })
                .then(response => {
                    // 展示返回的数据
                    this.pingResult4 = response.data;
                }).catch(error => {
                    // 处理异常
                });
        }

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

pre {
    white-space: pre-wrap;
}
</style>