<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">文件上传漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            文件上传漏洞，是指攻击者通过上传恶意文件来获得对服务器的控制权的漏洞。<br>攻击者通常会利用Web应用程序的文件上传功能，将一个包含恶意代码的文件上传到服务器上。如果服务器没有正确地检查和限制上传的文件类型、大小、后缀名等信息，攻击者就可以上传一个包含恶意代码的文件，如php、jsp、asp等可执行脚本文件，然后通过访问上传的文件来执行恶意代码，从而获得对服务器的控制权。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            任意文件上传漏洞允许攻击者上传恶意文件到服务器，可能导致服务器被完全控制，数据泄露或被篡改，以及网站被挂马传播恶意软件。攻击者可以利用此漏洞执行任意代码，窃取敏感信息，甚至将服务器作为跳板进行其他网络攻击。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】文件类型限制 <br />
                            必须在服务器端采用白名单方式对上传或下载的文件类型、大小进行严格的限制。仅允许业务所需文件类型上传，避免上传.jsp、.jspx、.html、.exe等危险文件。
                            <br /><br />
                            【建议】其他<br />
                            对上传的文件回显相对路径或者不显示路径。<br />
                            设置目录权限限制，禁止上传目录的执行权限。<br />
                            建议使用OSS静态存储服务器来存储用户上传的文件。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://www.javasec.org/java-vuls/FileUpload.html" target="_blank"
                                style="text-decoration: underline;">《任意文件上传漏洞》</a><br />
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 无任何限制<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">@RestController
@Slf4j
@RequestMapping("/fileUpload")
public class FileUploadController {

    // 应用统一文件管理目录
    private static final String APP_FILE_DIR = "/app/file/";
    
    // 上传目录（与文件包含漏洞统一使用同一目录）
    private static final String UPLOAD_DIR = APP_FILE_DIR + "upload/";

    /**
     * 漏洞版本1：无任何验证的文件上传
     */
    @PostMapping("/vuln1")
    @ResponseBody
    public Result handleFileUploadVuln1(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // ⚠️ 漏洞：直接保存文件，无任何验证
            String filePath = UPLOAD_DIR + file.getOriginalFilename();
            File dest = new File(filePath);
            file.transferTo(dest);
            
            log.warn("⚠️ 文件上传成功（无验证，存在安全风险）: {}", filePath);
            return Result.success("文件上传成功: " + filePath);

        } catch (IOException e) {
            log.error("文件上传失败", e);
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 文件扩展名校验 <el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
 * 安全版本：限制上传文件后缀名（白名单）
 */
@PostMapping("/sec1")
@ResponseBody
public Result handleFileUploadSec1(@RequestParam("file") MultipartFile file) {
    if (file.isEmpty()) {
        return Result.error("请选择要上传的文件");
    }

    try {
        // ✅ 防御1：验证文件后缀名（白名单）
        String fileName = file.getOriginalFilename();
        if (fileName == null || !fileName.contains(".")) {
            return Result.error("文件名无效");
        }
        
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        List&lt;String&gt; ALLOWED_EXTENSIONS = Arrays.asList("jpg", "jpeg", "png", "gif");
        
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            log.warn("⚠️ 拒绝上传非白名单后缀的文件: {}", fileName);
            return Result.error("只允许上传图片文件（jpg、jpeg、png、gif）");
        }

        // 保存文件
        String filePath = UPLOAD_DIR + fileName;
        File dest = new File(filePath);
        file.transferTo(dest);
        
        log.info("✅ 安全上传成功（后缀白名单验证）: {}", filePath);
        return Result.success("文件上传成功: " + filePath);

    } catch (IOException e) {
        log.error("文件上传失败", e);
        return Result.error("文件上传失败: " + e.getMessage());
    }
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 文件类型校验（可绕过）<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable3">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">
/**
 * 漏洞版本2：仅验证 Content-Type（可绕过）
 * 
 * 漏洞说明：
 * 1. 前端可以修改 Content-Type 绕过（如演示所示）
 * 2. 使用 Burp Suite 抓包修改 Content-Type 绕过
 * 3. Content-Type 是客户端可控的，不能作为安全校验依据
 */
@PostMapping("/vuln2")
@ResponseBody
public Result handleFileUploadVuln2(@RequestParam("file") MultipartFile file) {
    if (file.isEmpty()) {
        return Result.error("请选择要上传的文件");
    }

    try {
        // ⚠️ 漏洞：仅验证 Content-Type（容易绕过）
        String contentType = file.getContentType();
        log.info("上传文件 Content-Type: {}", contentType);
        
        if (!"image/jpeg".equals(contentType) && !"image/png".equals(contentType)) {
            return Result.error("只允许上传图片文件");
        }

        // 保存文件
        String filePath = UPLOAD_DIR + file.getOriginalFilename();
        File dest = new File(filePath);
        file.transferTo(dest);
        
        log.warn("⚠️ 文件上传成功（仅验证 Content-Type，可绕过）: {}", filePath);
        return Result.success("文件上传成功: " + filePath);

    } catch (IOException e) {
        log.error("文件上传失败", e);
        return Result.error("文件上传失败: " + e.getMessage());
    }
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 其他</el-row>
                        <pre v-highlightjs><code class="java">文件上传漏洞其他加固方案：

1）文件重命名（推荐）：
   - 使用 UUID + 时间戳作为文件名，防止文件名截断攻击
   - 示例：UUID.randomUUID() + "_" + System.currentTimeMillis() + "." + extension

2）文件内容检测（推荐）：
   - 检查文件头魔术字节（Magic Number）验证真实文件类型
   - 使用 Apache Tika 等库进行深度内容检测
   - 示例：Tika.detect(inputStream)
   
3）上传目录防护（必须）：
   - 禁止上传目录具有执行权限（chmod 644）
   - 将上传目录设置在 Web 根目录之外（如本项目：/app/file/upload/）
   - 使用单独域名和服务器存储上传文件（推荐 OSS/S3）

4）其他建议：
   - 集成防病毒扫描（如 ClamAV）
   - 详细日志记录上传行为（文件名、大小、IP、时间）
   - 限制文件大小（防止 DoS 攻击）
   - 对上传成功的文件仅回显相对路径或文件 ID
   - 设置文件上传频率限制（防止恶意刷量）
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 -->
        <el-dialog title="上传文件" :visible.sync="dialogFormVisible1" class="center-dialog">
            <div>
                <input type="file" @change="onFileChange" />
                <button @click="uploadFile1">上传</button>

            </div>
            <div>
                <!-- 文本展示区，字体红色 -->
                <br />
                <p v-if="message" style="color: red;">{{ message }}</p>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 -->
        <el-dialog title="上传文件" :visible.sync="dialogFormVisible2" class="center-dialog">
            <div>
                <input type="file" @change="onFileChange" />
                <button @click="uploadFile2">上传</button>

            </div>
            <div>
                <!-- 文本展示区，字体红色 -->
                <br />
                <p v-if="message" style="color: red;">{{ message }}</p>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框3 -->
        <el-dialog title="上传文件" :visible.sync="dialogFormVisible3" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic; margin-bottom: 20px;">
                说明：强制修改文件类型为图片类型：image/png，从而绕过后端接口的文件限制！
            </div>
            <div style="margin-bottom: 20px;">
                <input type="file" @change="onFileChange" />
                <button @click="uploadFile3">上传</button>
            </div>
            <div>
                <!-- 文本展示区，字体红色 -->
                <br />
                <p v-if="message" style="color: red;">{{ message }}</p>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框4 -->
        <el-dialog title="上传文件" :visible.sync="dialogFormVisible4" class="center-dialog">
            <div>
                <input type="file" @change="onFileChange" />
                <button @click="uploadFile4">上传</button>
            </div>
            <div>
                <!-- 文本展示区，字体红色 -->
                <br />
                <p v-if="message" style="color: red;">{{ message }}</p>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import { fileuploadVuln1, fileuploadVuln2, fileuploadSec1, fileuploadSec2 } from '@/api/fileupload';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false,
            selectedFile: null,
            message: '',
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true; // 显示对话框
            this.message = ''; // 清空消息
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true; // 显示对话框
            this.message = ''; // 清空消息
        },
        fetchDataAndFillTable3() {
            this.dialogFormVisible3 = true; // 显示对话框
            this.message = ''; // 清空消息
        },
        onFileChange(event) {
            this.selectedFile = event.target.files[0];
        },
        async uploadFile1() {
            if (!this.selectedFile) {
                this.message = '请选择要上传的文件';
                return;
            }

            const formData = new FormData();
            formData.append('file', this.selectedFile);

            try {
                const response = await fileuploadVuln1(formData);
                console.log(response);
                if (response.code === 0) {
                    this.message = response.data;
                } else {
                    this.message = response.data;
                }
            } catch (error) {
                this.message = '文件上传时发生错误';
            }

        },
        async uploadFile2() {
            if (!this.selectedFile) {
                this.message = '请选择要上传的文件';
                return;
            }

            const formData = new FormData();
            formData.append('file', this.selectedFile);

            try {
                const response = await fileuploadSec1(formData);
                if (response.code === 0) {
                    this.message = response.data;
                } else {
                    this.message = response.data;
                }
            } catch (error) {
                this.message = '文件上传时发生错误';
            }

        },
        async uploadFile3() {
            if (!this.selectedFile) {
                this.message = '请选择要上传的文件';
                return;
            }

            const formData = new FormData();
            // 修改文件的 content-type
            const modifiedFile = new File([this.selectedFile], this.selectedFile.name, {
                type: 'image/png'
            });
            formData.append('file', modifiedFile);
            // console.log(formData.get('file').type);  

            try {
                const response = await fileuploadVuln2(formData);
                if (response.code === 0) {
                    this.message = response.data;
                } else {
                    this.message = response.data;
                }
            } catch (error) {
                this.message = '文件上传时发生错误';
            }
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