<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">路径穿越漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            路径穿越漏洞，又称目录穿越漏洞，是一种常见的Web安全漏洞。攻击者利用该漏洞，可以通过在文件名或路径中插入特殊字符（如../），来访问Web服务器文件系统上受限制的文件或目录。简单来说，就是攻击者可以"穿越"到Web目录以外的地方，去访问其他文件。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            攻击者可以访问到Web服务器上的敏感文件，例如配置文件、数据库文件、源代码等，导致信息泄露。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】避免路径拼接 <br>
                            1. 文件目录避免外部参数拼接。<br>
                            2. 保存文件目录建议后台写死并对文件名进行校验（字符类型、长度）。<br>
                            3. 建议文件保存时，将文件名替换为随机字符串。<br><br>
                            如因业务需要不能满足1.2.3的要求，需判断请求文件名和文件路径参数中是否存在../或..\(windows)， 如存在应判定路径非法并拒绝请求。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <b>相关技术文档和参考资源：</b><br/><br/>
                            <b>官方文档：</b>
                            <ul>
                                <li><a href="https://owasp.org/www-community/attacks/Path_Traversal" target="_blank" style="text-decoration: underline;">OWASP Path Traversal 官方文档</a></li>
                                <li><a href="https://portswigger.net/web-security/file-path-traversal" target="_blank" style="text-decoration: underline;">PortSwigger 路径穿越漏洞详解</a></li>
                            </ul>
                            <br/>
                            <b>安全最佳实践：</b>
                            <ul>
                                <li><a href="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration" target="_blank" style="text-decoration: underline;">OWASP A06:2021 - 安全配置错误</a></li>
                                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP 文件上传安全检查清单</a></li>
                            </ul>
                            <br/>
                            <b>漏洞分析文章：</b>
                            <ul>
                                <li><a href="https://www.acunetix.com/blog/web-security-zone/directory-traversal/" target="_blank" style="text-decoration: underline;">路径穿越漏洞深度分析</a></li>
                                <li><a href="https://www.freebuf.com/articles/web/218442.html" target="_blank" style="text-decoration: underline;">FreeBuf | 路径穿越漏洞原理与实战</a></li>
                            </ul>
                            <br/>
                            <b>防护工具和检测：</b>
                            <ul>
                                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" style="text-decoration: underline;">OWASP 安全配置检查清单</a></li>
                                <li><a href="https://github.com/projectdiscovery/nuclei-templates/blob/main/vulnerabilities/path-traversal.yaml" target="_blank" style="text-decoration: underline;">Nuclei 路径穿越检测模板</a></li>
                            </ul>
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
                        <pre v-highlightjs><code class="java">@GetMapping("/vuln1")
public ResponseEntity&lt;byte[]&gt; vuln1(@RequestParam String filename) throws IOException {
    //System.out.println(System.getProperty("user.dir"));
    // 1. 构建文件路径（存在路径穿越漏洞！）
    File file = new File("images/" + filename);

    log.info("文件位置: {}", file.getAbsolutePath());

    // 2. 检查文件是否存在
    if (!file.exists()) {
        return ResponseEntity.notFound().build(); // 文件不存在，返回 404
    }

    // 3. 读取文件内容并返回
    FileInputStream fis = new FileInputStream(file);
    byte[] fileBytes = IOUtils.toByteArray(fis);
    fis.close();

    // 4. 获取内容类型
    String contentType;
    if (filename.toLowerCase().endsWith(".jpg") || filename.toLowerCase().endsWith(".jpeg")) {
        contentType = "image/jpeg";
    } else if (filename.toLowerCase().endsWith(".gif")) {
        contentType = "image/gif";
    } else if (filename.toLowerCase().endsWith(".png")) {
        contentType = "image/png";
    } else {
        contentType = "text/plain";
    }

    // 5. 设置 Content-Type 响应头并返回 ResponseEntity
    return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(contentType))
            .body(fileBytes);
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 校验文件名合法性 <el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">@RequestMapping("/pathtraversal")
public class PathTraversalController {

    @GetMapping("/sec1")
    public ResponseEntity&lt;byte[]&gt; sec1(@RequestParam String filename) throws IOException {

        // 1. 检查文件名是否合法
        if (!Security.checkFilename(filename)) {
            return ResponseEntity.badRequest().build(); // 文件名不合法，返回 400
        }

        // 2. 构建图片文件路径
        File file = new File("images/" + filename);
        log.info("文件位置: {}", file.getAbsolutePath());

        // 其他代码省略
        ......
    }
}

// 文件名检测安全函数
public static boolean checkFilename(String filename) {
    // 使用正则表达式限制文件名只能包含字母、数字、点号和下划线
    String regex = "^[a-zA-Z0-9_.-]+\\.(jpg|jpeg|png|gif)$";
    return filename.matches(regex);
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
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用 java.nio.file.Path 规范化路径
                            <el-button type="success" round size="mini"
                                @click="fetchDataAndFillTable3">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/sec2")
public ResponseEntity&lt;byte[]&gt; sec2(@RequestParam String filename) throws IOException {

    // 1. 构建安全的文件路径
    Path baseDir = Paths.get("images").toAbsolutePath().normalize();
    Path filePath = baseDir.resolve(filename).normalize();

    // 2. 检查路径是否在允许的目录范围内
    if (!filePath.startsWith(baseDir)) {
        return ResponseEntity.badRequest().body("Access denied".getBytes());
    }

    File file = filePath.toFile();
    log.info("文件位置: {}", file.getAbsolutePath());

    // 3. 检查文件是否存在
    if (!file.exists()) {
        return ResponseEntity.notFound().build(); // 文件不存在，返回 404
    }

    // 4. 读取文件内容并返回
    FileInputStream fis = new FileInputStream(file);
    byte[] imageBytes = IOUtils.toByteArray(fis);
    fis.close();

    // 5. 获取图片类型 (根据实际情况修改)
    String contentType; // 默认图片类型
    if (filename.toLowerCase().endsWith(".jpg") || filename.toLowerCase().endsWith(".jpeg")) {
        contentType = "image/jpeg";
    } else if (filename.toLowerCase().endsWith(".gif")) {
        contentType = "image/gif";
    } else if (filename.toLowerCase().endsWith(".png")) {
        contentType = "image/png";
    } else {
        contentType = "text/plain";
    }

    // 6. 设置 Content-Type 响应头并返回 ResponseEntity
    return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(contentType))
            .body(imageBytes);
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 -->
        <el-dialog title="路径穿越漏洞测试" :visible.sync="dialogFormVisible1" class="center-dialog">
            <el-form class="demo-form-inline">
                <el-form-item label="Payload1">
                    <el-input v-model="payload1"></el-input>
                </el-form-item>
                <el-form-item label="Payload1">
                    <el-input v-model="payload2"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit11">正常请求</el-button>
                    <el-button type="danger" @click="onSubmit12">恶意攻击</el-button>
                </el-form-item>
            </el-form>
            <div>
                <!-- 图片展示区 -->
                <img v-if="imageUrl" :src="imageUrl" alt="加载的图片" style="max-width: 500px; max-height: 1000px;">
                <!-- 文本展示区 -->
                <div v-else v-html="resp_text1"></div>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 -->
        <el-dialog title="路径穿越漏洞测试" :visible.sync="dialogFormVisible2" class="center-dialog">
            <el-form class="demo-form-inline">
                <el-form-item label="Payload1">
                    <el-input v-model="payload1"></el-input>
                </el-form-item>
                <el-form-item label="Payload1">
                    <el-input v-model="payload2"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit21">正常请求</el-button>
                    <el-button type="danger" @click="onSubmit22">恶意攻击</el-button>
                </el-form-item>
            </el-form>
            <div>
                <!-- 图片展示区 -->
                <img v-if="imageUrl" :src="imageUrl" alt="加载的图片" style="max-width: 500px; max-height: 1000px;">
                <!-- 文本展示区 -->
                <div v-else v-html="resp_text1"></div>
            </div>
        </el-dialog>
        <!-- 打开嵌套表格的对话框3 -->
        <el-dialog title="路径穿越漏洞测试" :visible.sync="dialogFormVisible3" class="center-dialog">
            <el-form class="demo-form-inline">
                <el-form-item label="Payload1">
                    <el-input v-model="payload1"></el-input>
                </el-form-item>
                <el-form-item label="Payload1">
                    <el-input v-model="payload2"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit31">正常请求</el-button>
                    <el-button type="danger" @click="onSubmit32">恶意攻击</el-button>
                </el-form-item>
            </el-form>
            <div>
                <!-- 图片展示区 -->
                <img v-if="imageUrl" :src="imageUrl" alt="加载的图片" style="max-width: 500px; max-height: 1000px;">
                <!-- 文本展示区 -->
                <div v-else v-html="resp_text1"></div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import { loadImageVuln1, loadTextVuln1, loadImageSec1, loadTextSec1, loadImageSec2, loadTextSec2 } from '@/api/pathtraversal';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false,
            payload1: 'springvulnboot_network.jpg',
            payload2: '../../../../../../etc/hosts',
            resp_text1: '',
            imageUrl: null // 用于存储图片 URL
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true; // 显示对话框
            this.resp_text1 = '';
            this.imageUrl = null;
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true; // 显示对话框
            this.resp_text1 = '';
            this.imageUrl = null;
        },
        fetchDataAndFillTable3() {
            this.dialogFormVisible3 = true; // 显示对话框
            this.resp_text1 = '';
            this.imageUrl = null;
        },
        onSubmit11() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            loadImageVuln1({ filename: this.payload1 }).then(response => {
                // console.log(response);
                const blob = new Blob([response.data]);
                this.imageUrl = URL.createObjectURL(blob);
                this.resp_text1 = ''; // 清空文本内容
            }).catch(error => {
                this.$message.error('加载图片失败');
                this.imageUrl = null;
            });
        },
        onSubmit12() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            loadTextVuln1({ filename: this.payload2 }).then(response => {
                console.log(response);
                this.resp_text1 = response; // 直接展示文本内容
                this.imageUrl = null;
            }).catch(error => {
                this.$message.error('加载文本失败');
                this.imageUrl = null;
            });
        },
        onSubmit21() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            loadImageSec1({ filename: this.payload1 }).then(response => {
                // console.log(response);
                const blob = new Blob([response.data]);
                this.imageUrl = URL.createObjectURL(blob);
                this.resp_text1 = ''; // 清空文本内容
            }).catch(error => {
                this.$message.error('加载图片失败');
                this.imageUrl = null;
            });
        },
        onSubmit22() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            loadTextSec1({ filename: this.payload2 }).then(response => {
                console.log(response);
                this.resp_text1 = response; // 直接展示文本内容
                this.imageUrl = null;
            }).catch(error => {
                // this.$message.error('文件名不合法');
                this.resp_text1 = "文件名不合法";
                this.imageUrl = null;
            });
        },
        onSubmit31() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            loadImageSec2({ filename: this.payload1 }).then(response => {
                // console.log(response);
                const blob = new Blob([response.data]);
                this.imageUrl = URL.createObjectURL(blob);
                this.resp_text1 = ''; // 清空文本内容
            }).catch(error => {
                this.$message.error('加载图片失败');
                this.imageUrl = null;
            });
        },
        onSubmit32() {
            if (!this.payload1 || !this.payload2) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('payload不能为空');
                return;
            }
            loadTextSec2({ filename: this.payload2 }).then(response => {
                this.resp_text1 = response; // 直接展示文本内容
                this.imageUrl = null;
            }).catch(error => {
                this.resp_text1 = "文件名不合法";
                this.imageUrl = null;
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