<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">文件上传漏洞</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            文件上传漏洞是指服务端未正确限制上传文件的类型、内容、大小或文件名，导致攻击者可以将不符合业务要求的文件写入服务器。<br><br>
                            本课展示三类常见根因：<strong>无校验上传</strong>会接受任意内容；<strong>仅校验 Content-Type</strong>会信任客户端伪造的图片声明；<strong>直接拼接原始文件名</strong>会导致路径穿越和文件覆盖。<br><br>
                            本靶场的上传目录不是 Web 可执行目录，因此上传 jsp、php 等文件本身不会被自动执行；但若该目录被 Web 服务映射并允许执行，或上传文件被后续文件包含、模板加载等功能处理，就可能进一步形成远程代码执行攻击链。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            • <strong>恶意文件落盘</strong>：非业务允许的文件被写入服务器，污染文件存储空间；<br>
                            • <strong>路径穿越与覆盖</strong>：攻击者利用 <code>../</code> 跳出上传目录，覆盖图片、附件、配置或其他已有文件；<br>
                            • <strong>远程代码执行链</strong>：若上传目录可执行，或上传文件会被文件包含、模板加载等功能处理，可能进一步形成 RCE；<br>
                            • <strong>资源与数据风险</strong>：大文件、畸形文件或同名覆盖可造成存储资源消耗、数据破坏和业务异常。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <span style="color: red;">【注意】仅后缀白名单不是完整防护</span><br />
                            <code>sec1</code> 仅限制扩展名，文本文件改名为 <code>.jpg</code> 仍可通过，且原始文件名仍可能带来覆盖风险。<br /><br />
                            <span style="color: red;">【必须】服务端验证真实图片内容</span><br />
                            <code>sec2</code> 限制 PNG/JPEG、文件大小和图片尺寸，检查魔术字节并使用 <code>ImageIO</code> 实际解析图片；客户端提供的文件名和 Content-Type 均不作为可信依据。<br /><br />
                            <span style="color: red;">【必须】安全保存与下载</span><br />
                            使用服务端生成的随机文件名，规范化并校验保存路径，将上传目录设为不可执行目录；下载时由服务端确定响应类型，设置 <code>attachment</code> 和 <code>nosniff</code>，且不返回物理绝对路径。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://www.javasec.org/java-vuls/FileUpload.html" target="_blank"
                                style="text-decoration: underline;">《任意文件上传漏洞》</a><br />
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" target="_blank"
                                style="text-decoration: underline;">《OWASP File Upload Cheat Sheet》</a><br />
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
                        <el-row type="flex" justify="space-between" align="middle">基础防护代码 - 文件扩展名校验（仍可绕过）<el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
 * 基础防护：仅后缀白名单校验
 * 仍无法验证真实图片内容，也不能作为最终安全方案。
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
 * 1. multipart 文件分段的 Content-Type 由客户端声明
 * 2. 前端或 Burp Suite 可把普通文件声明为 image/png
 * 3. Content-Type 不能证明文件内容是真实图片，不能作为唯一安全校验
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
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 完整安全图片上传 <el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable5">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">@PostMapping("/sec2")
public Result uploadSecureImage(@RequestParam MultipartFile file) {
    // ✅ 限制业务大小，验证 PNG/JPEG 魔术字节
    String format = detectImageFormat(file.getBytes());
    validateImageDimensions(file.getBytes());
    BufferedImage image = ImageIO.read(file.getInputStream());

    // ✅ 重新编码，并使用服务端生成的随机文件名
    Path target = uploadRoot.resolve(randomFileName(format)).normalize();
    ImageIO.write(image, format, target.toFile());
    return Result.success("真实图片校验通过");
}</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 原始文件名路径穿越与覆盖 <el-button
                                type="danger" round size="mini"
                                @click="fetchDataAndFillTable4">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
 * 漏洞版本3：直接拼接原始文件名
 * 例如文件名为 ../upload-guard.txt 时，
 * 可跳出 upload 目录并覆盖父目录中的文件。
 */
@PostMapping("/vuln3")
public Result handleFileUploadVuln3(@RequestParam("file") MultipartFile file) {
    // ❌ 原始文件名完全由客户端控制
    String filePath = UPLOAD_DIR + file.getOriginalFilename();
    file.transferTo(new File(filePath));
    return Result.success("文件上传成功");
}
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
            <div style="text-align: left; color: #e6a23c; font-style: italic; margin-bottom: 20px;">
                说明：该场景只校验文件扩展名。可选择任意文本文件并改名为 <code>.jpg</code> 测试：基础防护会接受，完整安全图片上传会拒绝。
            </div>
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
                说明：本次上传会将文件分段声明为 image/png；文件实际内容不会改变，因此可绕过仅校验 Content-Type 的后端接口。
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

        <!-- 原始文件名路径穿越与覆盖测试 -->
        <el-dialog title="原始文件名路径穿越与覆盖测试" :visible.sync="dialogFormVisible4" class="center-dialog">
            <div style="text-align: left; color: red; font-style: italic; margin-bottom: 20px;">
                说明：将提交给服务端的文件名设置为 <code>../upload-guard.txt</code>，可跳出上传目录并覆盖父目录中的测试文件。
            </div>
            <div class="target-file">
                <div>当前 /app/file/upload-guard.txt 内容：</div>
                <pre>{{ pathTraversalTargetContent }}</pre>
            </div>
            <div style="margin-bottom: 12px;">
                <input type="file" @change="onFileChange" />
            </div>
            <div style="margin-bottom: 12px;">
                <span>提交给服务端的文件名：</span>
                <el-input v-model.trim="customFilename" size="small" style="width: 240px;" />
            </div>
            <div>
                <el-button type="danger" @click="uploadFile4">上传并覆盖</el-button>
                <el-button @click="resetPathTraversal">重置测试数据</el-button>
            </div>
            <p v-if="pathTraversalMessage" style="color: red;">{{ pathTraversalMessage }}</p>
        </el-dialog>

        <el-dialog title="完整安全图片上传测试" :visible.sync="dialogFormVisible5" class="center-dialog">
            <div style="text-align: left; color: #606266; margin-bottom: 20px;">
                仅接受不超过 2MB、尺寸不超过 4096 × 4096 的真实 PNG 或 JPEG 图片。文件名和客户端声明的 Content-Type 不作为可信依据。
            </div>
            <div style="margin-bottom: 12px;">
                <input type="file" @change="onSecureFileChange" />
            </div>
            <div>
                <el-button type="success" @click="uploadFile5">安全上传</el-button>
            </div>
            <p v-if="secureImageMessage" style="color: red;">{{ secureImageMessage }}</p>
            <p v-if="secureImageDownloadUrl">
                <a :href="secureImageDownloadUrl" target="_blank">下载服务端重新编码后的图片</a>
            </p>
        </el-dialog>
    </div>
</template>

<script>
import { getBaseUrl } from '@/utils/request';
import {
    fileuploadVuln1,
    fileuploadVuln2,
    fileuploadVuln3,
    fileuploadSec1,
    fileuploadSec2,
    getPathTraversalTarget,
    resetPathTraversalTarget
} from '@/api/fileupload';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false,
            dialogFormVisible4: false,
            dialogFormVisible5: false,
            selectedFile: null,
            secureImageFile: null,
            message: '',
            customFilename: '../upload-guard.txt',
            pathTraversalTargetContent: '',
            pathTraversalMessage: '',
            secureImageMessage: '',
            secureImageDownloadUrl: '',
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
        async fetchDataAndFillTable4() {
            this.dialogFormVisible4 = true;
            this.selectedFile = null;
            this.customFilename = '../upload-guard.txt';
            this.pathTraversalMessage = '';
            await this.loadPathTraversalTarget();
        },
        fetchDataAndFillTable5() {
            this.dialogFormVisible5 = true;
            this.secureImageFile = null;
            this.secureImageMessage = '';
            this.secureImageDownloadUrl = '';
        },
        onFileChange(event) {
            this.selectedFile = event.target.files[0];
        },
        onSecureFileChange(event) {
            this.secureImageFile = event.target.files[0];
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
        },
        async loadPathTraversalTarget() {
            try {
                const response = await getPathTraversalTarget();
                this.pathTraversalTargetContent = response.data;
            } catch (error) {
                this.pathTraversalTargetContent = '读取测试文件失败';
            }
        },
        async uploadFile4() {
            if (!this.selectedFile) {
                this.pathTraversalMessage = '请选择要上传的文件';
                return;
            }
            if (!this.customFilename) {
                this.pathTraversalMessage = '请输入提交给服务端的文件名';
                return;
            }

            const formData = new FormData();
            formData.append('file', this.selectedFile, this.customFilename);
            try {
                const response = await fileuploadVuln3(formData);
                this.pathTraversalMessage = response.data;
                await this.loadPathTraversalTarget();
            } catch (error) {
                this.pathTraversalMessage = '文件上传时发生错误';
            }
        },
        async resetPathTraversal() {
            try {
                const response = await resetPathTraversalTarget();
                this.pathTraversalMessage = response.data;
                await this.loadPathTraversalTarget();
            } catch (error) {
                this.pathTraversalMessage = '重置测试文件失败';
            }
        },
        async uploadFile5() {
            if (!this.secureImageFile) {
                this.secureImageMessage = '请选择要上传的图片';
                return;
            }

            const formData = new FormData();
            formData.append('file', this.secureImageFile);
            try {
                const response = await fileuploadSec2(formData);
                this.secureImageMessage = response.data.message;
                this.secureImageDownloadUrl = getBaseUrl() + response.data.downloadUrl;
            } catch (error) {
                this.secureImageMessage = '图片未通过安全校验';
                this.secureImageDownloadUrl = '';
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

.target-file {
    background: #f5f7fa;
    margin-bottom: 15px;
    padding: 10px;
    text-align: left;
}

.target-file pre {
    margin-bottom: 0;
    white-space: pre-wrap;
}
</style>