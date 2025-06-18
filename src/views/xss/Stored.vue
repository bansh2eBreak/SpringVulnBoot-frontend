<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">XSS跨站脚本攻击 -- 持久型</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            XSS (Cross-Site Scripting)
                            跨站脚本攻击是一种Web安全漏洞，攻击者通过在Web页面中注入恶意代码，如JavaScript脚本，来攻击用户，利用Web应用程序对用户输入数据的信任，以盗取用户信息、会话信息或在用户浏览器上执行其他恶意操作。
                            <br />
                            <span style="color: red;">存储型 XSS</span> 是将恶意代码存储到 Web 应用程序的数据库或文件系统中，并在 Web
                            页面中展示，当用户访问这个页面时，恶意代码会被执行。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            XSS跨站攻击漏洞的危害在于，它允许攻击者在受害者不知情的情况下，向受害者的浏览器注入恶意脚本，从而窃取敏感信息、操控受害者行为、传播恶意软件，甚至破坏网站的正常运营，给个人和企业带来严重的安全威胁。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】外部输入拼接到response页面前进行编码处理
                            当响应“content-type”为“html”类型时，外部输入拼接到响应包中，需根据输出位置进行编码处理,需要对以下6个特殊字符进行HTML实体编码(&, &lt;,&gt;, ",
                            ',/)，也可参考或直接使用业界已有成熟第三方库如ESAPI。<br /><br />

                            【必须】设置正确的HTTP响应包类型
                            响应包的HTTP头“Content-Type”必须正确配置响应包的类型，禁止非HTML类型的响应包设置为“text/html”。此举会使浏览器在直接访问链接时，将非HTML格式的返回报文当做HTML解析，增加反射型XSS的触发几率。<br /><br />

                            【建议】设置安全的HTTP响应头
                            控制用户登录鉴权的Cookie字段 应当设置HttpOnly属性以防止被XSS漏洞/JavaScript操纵泄漏。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <!-- 给超链接配置下划线 -->
                            <a href="https://mp.weixin.qq.com/s/ADrr3zRMz7rCLv8lupEi6A?token=1868590521&lang=zh_CN"
                                target="_blank"
                                style="text-decoration: underline;">《XSS漏洞的危害和几种受欢迎的攻击方式》</a>：深入学习XSS漏洞原理及攻击技术。<br />
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 直接拼接输入内容 <div>
                                <el-button type="danger" round size="mini" @click="fetchDataAndFillTable1"
                                    >去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// Controller层
@PostMapping("/addMessage")
public Result addMessage(@RequestBody MessageBoard messageBoard) {
    messageBoardService.insertMessage(messageBoard);
    return Result.success();
}

// Service层
@Override
public void insertMessage(MessageBoard messageBoard) {
    messageBoardMapper.insertMessage(messageBoard);
}

// Dao层
@Insert("insert into MessageBoard(message) values(#{message})")
void insertMessage(MessageBoard messageBoard);

//前端代码
因默认Vue展示会自动将&lt;、&gt;这类字符进行实体编码，要编写xss漏洞需要通过使用v-html指令重新渲染数据：
&lt;el-table :data="tableData" style="width: 100%;" align="center"&gt;
    &lt;el-table-column prop="id" label="编号" width="180"&gt;
    &lt;/el-table-column&gt;
    &lt;el-table-column prop="message" label="留言内容" width="180"&gt;
        &lt;template slot-scope="scope"&gt;
            &lt;div v-html="scope.row.message"&gt;&lt;/div&gt;
        &lt;/template&gt;
    &lt;/el-table-column&gt;
&lt;/el-table&gt;
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 无需特殊配置，默认Vue方式 <div>
                                <el-button type="success" round size="mini" @click="fetchDataAndFillTable2"
                                   >去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">//前端代码
&lt;el-dialog title="留言板" :visible.sync="dialogFormVisible" class="center-dialog"&gt;
    &lt;el-form :inline="true" :model="formInline" class="demo-form-inline"&gt;
        &lt;el-form-item label="留言"&gt;
            &lt;el-input v-model="formInline.message" placeholder="请留言..."&gt;&lt;/el-input&gt;
        &lt;/el-form-item&gt;
        &lt;el-form-item&gt;
            &lt;el-button type="primary" @click="onSubmit"&gt;提交&lt;/el-button&gt;
        &lt;/el-form-item&gt;
        &lt;el-table :data="tableData" style="width: 100%;" align="center"&gt;
            &lt;el-table-column prop="id" label="编号" width="180"&gt;
            &lt;/el-table-column&gt;
            &lt;el-table-column prop="message" label="留言内容" width="180"&gt;
            &lt;/el-table-column&gt;
        &lt;/el-table&gt;
    &lt;/el-form&gt;
&lt;/el-dialog&gt;
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
        <!-- 打开嵌套表格的对话框1 -->
        <el-dialog title="留言板" :visible.sync="dialogFormVisible" class="center-dialog">
            <el-form :inline="true" :model="formInline" class="demo-form-inline">
                <el-form-item label="留言">
                    <el-input v-model="formInline.message" placeholder="请留言..."></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit">提交</el-button>
                </el-form-item>
                <el-table :data="tableData" style="width: 100%;" align="center">
                    <el-table-column prop="id" label="编号" width="180">
                    </el-table-column>
                    <el-table-column prop="message" label="留言内容" width="180">
                        <template slot-scope="scope">
                            <div v-html="scope.row.message"></div>
                        </template>
                    </el-table-column>
                </el-table>
            </el-form>
        </el-dialog>
        <!-- 打开嵌套表格的对话框2 -->
        <el-dialog title="留言板" :visible.sync="dialogFormVisible2" class="center-dialog">
            <el-form :inline="true" :model="formInline" class="demo-form-inline">
                <el-form-item label="留言">
                    <el-input v-model="formInline.message" placeholder="请留言..."></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit2">提交</el-button>
                </el-form-item>
                <el-table :data="tableData" style="width: 100%;" align="center">
                    <el-table-column prop="id" label="编号" width="180">
                    </el-table-column>
                    <el-table-column prop="message" label="留言内容" width="180">
                    </el-table-column>
                </el-table>
            </el-form>
        </el-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import { queryMessage, addMessage, addMessageSec } from '@/api/xss';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible: false,
            dialogFormVisible2: false,
            tableData: [],
            formInline: {
                message: ''
            }
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            queryMessage({})
                .then(response => {
                    this.dialogFormVisible = true; // 显示对话框
                    this.tableData = response.data;
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable2() {
            queryMessage({})
                .then(response => {
                    this.tableData = response.data;
                    this.dialogFormVisible2 = true; // 显示对话框
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        onSubmit() {
            if (!this.formInline.message) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('留言内容不能为空');
                return;
            }

            addMessage({
                "message": this.formInline.message
            }).then(response => {
                this.fetchDataAndFillTable1();  // 重新查询数据
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },
        onSubmit2() {
            if (!this.formInline.message) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('留言内容不能为空');
                return;
            }
            addMessageSec({
                "message": this.formInline.message
            }).then(response => {
                this.fetchDataAndFillTable2();  // 重新查询数据
            }).catch(error => {
                console.error('Error fetching data:', error);
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
</style>