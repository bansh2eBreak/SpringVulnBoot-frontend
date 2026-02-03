<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">文件包含漏洞 -- Groovy脚本包含（类似PHP include）</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            文件包含漏洞是指应用程序在包含文件时，<span style="color: red;">未对文件来源进行严格控制</span>，导致攻击者可以包含任意文件，甚至执行恶意代码。<br><br>
                            
                            <strong>Spring Boot 中的文件包含:</strong><br>
                            虽然 Spring Boot 默认不支持 JSP，但通过 Groovy 脚本引擎，可以实现和 PHP include 完全一样的效果：<br>
                            1. 攻击者上传恶意 Groovy 脚本（类似上传恶意 PHP）<br>
                            2. 通过文件包含漏洞加载该脚本（类似 <code>include($_GET['file'])</code>）<br>
                            3. Groovy 脚本被解析并执行（获得 Webshell）<br>
                            4. 实现命令执行、文件操作、反弹Shell等攻击
                        </div>
                    </el-tab-pane>
                    
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            1. <span style="color: red;">远程代码执行（RCE）</span>：攻击者可以执行任意系统命令<br>
                            2. <span style="color: red;">Webshell 植入</span>：获得持久化的服务器控制权<br>
                            3. 文件系统操作：读取、写入、删除任意文件<br>
                            4. 敏感信息泄露：读取配置文件、数据库密码、密钥等<br>
                            5. 反弹 Shell：建立反向连接，完全控制服务器<br>
                            6. 权限提升：利用系统漏洞提升到 root 权限<br>
                            7. 横向移动：在内网中进一步渗透攻击<br>
                            8. 数据窃取：导出数据库、窃取用户数据
                        </div>
                    </el-tab-pane>
                    
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】使用白名单验证文件名 <br />
                            只允许包含预定义的安全文件，严格限制文件名和路径。
                            <br /><br />
                            【必须】禁止动态执行用户上传的脚本 <br />
                            生产环境中绝对不要执行用户上传的 Groovy、JSP、PHP 等可执行脚本。
                            <br /><br />
                            【必须】文件上传严格验证 <br />
                            验证文件类型、大小、扩展名，禁止上传可执行文件（.groovy、.jsp、.php、.sh等）。
                            <br /><br />
                            【建议】使用沙箱环境<br />
                            如果必须执行脚本，使用 SecureASTCustomizer 等机制限制 Groovy 脚本权限。<br />
                            使用单独的域名和服务器存储上传文件，例如使用对象存储服务（如OSS）。
                            <br /><br />
                            【建议】最小权限原则<br />
                            应用程序使用受限的系统账户运行，不要使用 root 权限。<br />
                            禁止上传目录具有执行权限。
                        </div>
                    </el-tab-pane>
                    
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://groovy-lang.org/security.html" target="_blank" style="text-decoration: underline;">《Groovy 安全文档》</a><br />
                            <a href="https://owasp.org/www-project-top-ten/" target="_blank" style="text-decoration: underline;">《OWASP Top 10》</a><br />
                            <a href="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP 文件上传安全检查清单》</a><br />
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - Groovy 脚本包含<div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/groovy/vuln")
public void groovyIncludeVuln(
    @RequestParam String file,
    HttpServletRequest request,
    HttpServletResponse response) throws IOException {
    
    // 设置字符编码
    response.setContentType("text/html;charset=UTF-8");
    PrintWriter out = response.getWriter();
    
    try {
        // 漏洞：直接执行用户上传的Groovy脚本
        String scriptPath = UPLOAD_DIR + file;
        File scriptFile = new File(scriptPath);
        
        // 读取脚本内容
        String scriptContent = Files.readString(scriptFile.toPath());
        
        // ⚠️ 危险！直接执行（类似 PHP include）
        GroovyShell shell = new GroovyShell();
        
        // 将request、response、out绑定到脚本环境
        shell.setVariable("request", request);
        shell.setVariable("response", response);
        shell.setVariable("out", out);
        
        // 执行脚本 - 相当于 PHP 的 include($file);
        Object result = shell.evaluate(scriptContent);
        
    } catch (Exception e) {
        out.println("❌ 脚本执行失败: " + e.getMessage());
    }
}</code></pre>
                    </div>
                </el-col>
                
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 白名单验证 <el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/groovy/sec")
public void groovyIncludeSecure(
    @RequestParam String file,
    HttpServletRequest request,
    HttpServletResponse response) throws IOException {
    
    response.setContentType("text/html;charset=UTF-8");
    PrintWriter out = response.getWriter();
    
    try {
        // 防御1: 白名单验证
        Set&lt;String&gt; allowedScripts = Set.of(
            "utils.groovy", "helpers.groovy", "validators.groovy"
        );
        
        if (!allowedScripts.contains(file)) {
            out.println("❌ 拒绝执行非白名单脚本！");
            return; // ⚠️ 拦截恶意脚本
        }
        
        // 防御2: 禁止路径遍历
        if (file.contains("..") || file.contains("/") || file.contains("\\")) {
            out.println("❌ 检测到路径遍历攻击！");
            return;
        }
        
        // 防御3: 从固定目录读取（攻击者无法上传到这里）
        String scriptPath = SAFE_SCRIPTS_DIR + file; // /app/file/
        String scriptContent = Files.readString(Paths.get(scriptPath));
        
        // 防御4: 使用 Groovy 沙箱环境
        GroovyShell shell = new GroovyShell();
        shell.setVariable("request", request);
        shell.setVariable("response", response);
        shell.setVariable("out", out);
        
        // ✅ 只有白名单脚本能执行
        shell.evaluate(scriptContent);
        
    } catch (Exception e) {
        out.println("❌ 脚本执行失败: " + e.getMessage());
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 - 漏洞测试 -->
        <el-dialog :visible.sync="dialogFormVisible1" width="900px" :show-close="true" :close-on-click-modal="true">
            <div slot="title" style="text-align: center; font-size: 18px;">
                Groovy 文件包含漏洞测试
            </div>
            <div class="test-container">
                <!-- 说明 -->
                <div style="text-align: left; color: red; font-style: italic; margin-bottom: 20px; padding: 15px; background-color: #fef0f0; border-radius: 4px; border: 1px solid #fde2e2;">
                    <strong>测试说明：</strong><br>
                    1. 下载 Webshell 示例文件到本地<br>
                    2. 上传 Webshell 文件到服务器<br>
                    3. 输入文件名，触发文件包含<br>
                    4. 执行系统命令（如：whoami、id、ls 等）
                </div>

                <!-- 1. 下载 Webshell 示例 -->
                <div class="test-section">
                    <h3>1. 下载 Webshell 示例文件</h3>
                    <el-button type="primary" @click="downloadExampleFile('basic')">
                        下载示例 shell.groovy
                    </el-button>
                    <div v-if="downloadMessage.text" style="margin-top: 15px;">
                        <el-alert 
                            :title="downloadMessage.text" 
                            :type="downloadMessage.type" 
                            :closable="false"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 2. 上传 Webshell 文件 -->
                <div class="test-section">
                    <h3>2. 上传 Webshell 文件到服务器</h3>
                    <input type="file" @change="onFileChange" accept=".groovy,.txt" style="display: inline-block; margin-right: 10px;" />
                    <el-button type="success" @click="uploadFile" :disabled="!selectedFile">
                        上传文件
                    </el-button>
                    <div v-if="uploadMessage.text" style="margin-top: 15px;">
                        <el-alert 
                            :title="uploadMessage.text" 
                            :type="uploadMessage.type" 
                            :closable="false"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 3. 触发文件包含 -->
                <div class="test-section">
                    <h3>3. 触发文件包含 <span style="color: red; font-size: 14px; font-weight: normal;">(危险！直接执行类似 PHP include)</span></h3>
                    <p style="margin-bottom: 15px; color: #606266;">
                        `或者直接通过 <code style="background-color: #f5f5f5; padding: 2px 6px; border-radius: 3px; color: #e83e8c;">curl 'http://127.0.0.1:8080/fileInclusion/groovy/vuln?file=shell.groovy&cmd=whoami'</code> 来使用 webshell`
                    </p>
                    <el-input 
                        v-model="includeFilename" 
                        placeholder="例如: shell.groovy" 
                        style="width: 400px; margin-right: 10px;">
                    </el-input>
                    <el-button type="warning" @click="triggerInclude" :disabled="!includeFilename">
                        触发包含
                    </el-button>
                    <div v-if="includeMessage.text" style="margin-top: 15px;">
                        <el-alert 
                            :title="includeMessage.text" 
                            :type="includeMessage.type" 
                            :closable="false"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 4. 执行系统命令 -->
                <div class="test-section">
                    <h3>4. 执行系统命令 (Webshell)</h3>
                    <div style="margin-bottom: 15px;">
                        <el-input 
                            v-model="shellCommand" 
                            placeholder="例如: whoami" 
                            style="width: 400px; margin-right: 10px;">
                        </el-input>
                        <el-button type="danger" @click="executeCommand" :disabled="!includeFilename || !shellCommand">
                            执行命令
                        </el-button>
                    </div>
                    <div>
                        <span style="color: #909399; margin-right: 10px;">常用命令：</span>
                        <el-button size="mini" @click="shellCommand = 'whoami'">whoami</el-button>
                        <el-button size="mini" @click="shellCommand = 'id'">id</el-button>
                        <el-button size="mini" @click="shellCommand = 'pwd'">pwd</el-button>
                        <el-button size="mini" @click="shellCommand = 'ls -la'">ls -la</el-button>
                        <el-button size="mini" @click="shellCommand = 'uname -a'">uname -a</el-button>
                    </div>
                    <div v-if="executeMessage.text" style="margin-top: 15px;">
                        <el-alert 
                            :title="executeMessage.text" 
                            :type="executeMessage.type" 
                            :closable="false"
                            show-icon>
                        </el-alert>
                    </div>
                </div>

                <!-- 执行结果 -->
                <div v-if="executionResult" class="test-section">
                    <h3>执行结果</h3>
                    <div class="result-box">
                        <iframe
                            :srcdoc="executionResult"
                            style="width: 100%; min-height: 400px; border: 1px solid #dcdfe6; border-radius: 4px; background-color: #fff;"
                            sandbox="allow-same-origin allow-forms allow-top-navigation-by-user-activation">
                        </iframe>
                    </div>
                </div>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 - 安全测试 -->
        <el-dialog :visible.sync="dialogFormVisible2" width="900px" :show-close="true">
            <div slot="title" style="text-align: center; font-size: 18px;">
                安全版本测试 - 白名单验证（完整攻击流程演示）
            </div>
            <div class="test-container">
                <!-- 说明 -->
                <div style="text-align: left; color: green; font-style: italic; margin-bottom: 20px; padding: 15px; background-color: #f0f9ff; border-radius: 4px; border: 1px solid #b3d8ff;">
                    <strong>🔒 三层安全机制：</strong><br>
                    1️⃣ <strong>白名单验证：</strong>只允许执行预定义的脚本名称<br>
                    2️⃣ <strong>固定目录：</strong>从 <code>/app/file/</code> 根目录读取白名单脚本，不是用户上传目录<br>
                    3️⃣ <strong>权限隔离：</strong>攻击者只能写 <code>/app/file/upload/</code>，无法写 <code>/app/file/</code> 根目录<br><br>
                    <strong>白名单脚本：</strong>
                    <span style="color: #67c23a; font-weight: bold;">utils.groovy, helpers.groovy, validators.groovy</span><br>
                    <span style="color: #666; font-size: 12px;">（位于 /app/file/*.groovy，攻击者不可写）</span>
                </div>

                <!-- 1. 下载 Webshell -->
                <div class="test-section">
                    <h3>1. 下载示例 Webshell 文件</h3>
                    <el-button type="primary" @click="downloadExampleFileSecure('basic')">
                        下载 shell.groovy
                    </el-button>
                    <div v-if="downloadMessageSecure.text" class="result-box" :style="{ color: downloadMessageSecure.type === 'success' ? '#67c23a' : '#f56c6c' }">
                        {{ downloadMessageSecure.text }}
                    </div>
                </div>

                <!-- 2. 上传 Webshell -->
                <div class="test-section">
                    <h3>2. 上传 Webshell 文件（攻击者尝试）</h3>
                    <input type="file" @change="onFileChangeSecure" accept=".groovy" style="margin-right: 10px;" />
                    <el-button type="primary" @click="uploadFileSecure">上传</el-button>
                    <div v-if="uploadMessageSecure.text" class="result-box" :style="{ color: uploadMessageSecure.type === 'success' ? '#67c23a' : '#f56c6c' }">
                        {{ uploadMessageSecure.text }}
                    </div>
                </div>

                <!-- 3. 触发文件包含（被拦截） -->
                <div class="test-section">
                    <h3>3. 触发文件包含（尝试执行上传的脚本）</h3>
                    <p style="margin-bottom: 10px; color: #606266; font-size: 13px;">
                        攻击者尝试执行刚才上传的 <code>shell.groovy</code>，看看会发生什么...
                    </p>
                    <el-input 
                        v-model="secureIncludeFilename" 
                        placeholder="shell.groovy" 
                        style="width: 300px; margin-right: 10px;">
                    </el-input>
                    <el-button type="danger" @click="testSecureIncludeAttack">
                        尝试触发包含（模拟攻击）
                    </el-button>
                    <div v-if="includeMessageSecure.text" class="result-box" :style="{ color: includeMessageSecure.type === 'success' ? '#67c23a' : '#f56c6c' }">
                        {{ includeMessageSecure.text }}
                    </div>
                    <div v-if="secureAttackResult" class="result-box">
                        <iframe
                            :srcdoc="secureAttackResult"
                            style="width: 100%; min-height: 250px; border: 1px solid #dcdfe6; border-radius: 4px; background-color: #fff;"
                            sandbox="allow-same-origin allow-forms allow-top-navigation-by-user-activation">
                        </iframe>
                    </div>
                </div>

                <!-- 4. 测试白名单脚本 -->
                <div class="test-section">
                    <h3>4. 测试白名单脚本（正确使用方式）</h3>
                    <p style="margin-bottom: 10px; color: #606266; font-size: 13px;">
                        输入 <code>utils.groovy</code> 查看白名单脚本的正确执行（从 /app/file/ 读取）
                    </p>
                    <el-input 
                        v-model="secureWhitelistScript" 
                        placeholder="utils.groovy" 
                        style="width: 300px; margin-right: 10px;">
                    </el-input>
                    <el-button type="success" @click="testSecureWhitelist">
                        测试白名单脚本
                    </el-button>
                    <div v-if="whitelistMessageSecure.text" class="result-box" :style="{ color: whitelistMessageSecure.type === 'success' ? '#67c23a' : '#f56c6c' }">
                        {{ whitelistMessageSecure.text }}
                    </div>
                    <div v-if="secureWhitelistResult" class="result-box">
                        <iframe
                            :srcdoc="secureWhitelistResult"
                            style="width: 100%; min-height: 300px; border: 1px solid #dcdfe6; border-radius: 4px; background-color: #fff;"
                            sandbox="allow-same-origin allow-forms allow-top-navigation-by-user-activation">
                        </iframe>
                    </div>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import {
    uploadScript,
    groovyIncludeVuln,
    groovyIncludeSecure,
    downloadExample
} from '@/api/fileInclusion'

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            selectedFile: null,
            
            // 各区域独立的消息
            downloadMessage: { text: '', type: 'success' },
            uploadMessage: { text: '', type: 'success' },
            includeMessage: { text: '', type: 'success' },
            executeMessage: { text: '', type: 'success' },
            
            // 文件包含相关
            includeFilename: 'shell.groovy',
            
            // 命令执行相关
            shellCommand: 'whoami',
            executionResult: '',
            
            // 安全测试相关 - 独立的文件和消息
            selectedFileSecure: null,
            downloadMessageSecure: { text: '', type: 'success' },
            uploadMessageSecure: { text: '', type: 'success' },
            includeMessageSecure: { text: '', type: 'success' },
            whitelistMessageSecure: { text: '', type: 'success' },
            secureIncludeFilename: 'shell.groovy',
            secureWhitelistScript: 'utils.groovy',
            secureAttackResult: '',
            secureWhitelistResult: ''
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        
        // 显示漏洞测试对话框
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true;
            // 清空所有消息
            this.downloadMessage = { text: '', type: 'success' };
            this.uploadMessage = { text: '', type: 'success' };
            this.includeMessage = { text: '', type: 'success' };
            this.executeMessage = { text: '', type: 'success' };
            this.executionResult = '';
        },
        
        // 显示安全测试对话框
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true;
            // 清空所有安全测试消息
            this.downloadMessageSecure = { text: '', type: 'success' };
            this.uploadMessageSecure = { text: '', type: 'success' };
            this.includeMessageSecure = { text: '', type: 'success' };
            this.whitelistMessageSecure = { text: '', type: 'success' };
            this.secureAttackResult = '';
            this.secureWhitelistResult = '';
        },
        
        // 下载示例文件
        downloadExampleFile(type) {
            downloadExample(type);
            this.downloadMessage = { text: '示例文件下载成功', type: 'success' };
        },
        
        // 文件选择
        onFileChange(event) {
            this.selectedFile = event.target.files[0];
        },
        
        // 上传文件
        async uploadFile() {
            if (!this.selectedFile) {
                this.uploadMessage = { text: '请选择要上传的文件', type: 'error' };
                return;
            }

            const formData = new FormData();
            formData.append('file', this.selectedFile);

            try {
                const response = await uploadScript(formData);
                if (response.code === 0) {
                    this.uploadMessage = { text: `上传成功: ${response.data.filename}`, type: 'success' };
                    this.includeFilename = response.data.filename;
                } else {
                    this.uploadMessage = { text: `上传失败: ${response.msg}`, type: 'error' };
                }
            } catch (error) {
                this.uploadMessage = { text: '文件上传时发生错误: ' + error.message, type: 'error' };
            }
        },
        
        // 触发文件包含
        async triggerInclude() {
            if (!this.includeFilename) {
                this.includeMessage = { text: '请输入文件名', type: 'error' };
                return;
            }

            try {
                const response = await groovyIncludeVuln({
                    file: this.includeFilename
                });

                const html = await response.text();
                this.executionResult = html;
                this.includeMessage = { text: '文件包含成功！脚本已执行', type: 'success' };

            } catch (error) {
                this.includeMessage = { text: '包含失败: ' + error.message, type: 'error' };
            }
        },
        
        // 执行命令
        async executeCommand() {
            if (!this.includeFilename) {
                this.executeMessage = { text: '请先上传并包含Webshell文件', type: 'error' };
                return;
            }

            if (!this.shellCommand) {
                this.executeMessage = { text: '请输入要执行的命令', type: 'error' };
                return;
            }

            try {
                const response = await groovyIncludeVuln({
                    file: this.includeFilename,
                    cmd: this.shellCommand
                });

                const html = await response.text();
                this.executionResult = html;
                this.executeMessage = { text: '命令执行成功', type: 'success' };

            } catch (error) {
                this.executeMessage = { text: '命令执行失败: ' + error.message, type: 'error' };
            }
        },
        
        // ========== 安全版本独立方法 ==========
        
        // 下载示例文件（安全版本）
        downloadExampleFileSecure(type) {
            downloadExample(type);
            this.downloadMessageSecure = { text: '示例文件下载成功', type: 'success' };
        },
        
        // 文件选择（安全版本）
        onFileChangeSecure(event) {
            this.selectedFileSecure = event.target.files[0];
        },
        
        // 上传文件（安全版本）
        async uploadFileSecure() {
            if (!this.selectedFileSecure) {
                this.uploadMessageSecure = { text: '请选择要上传的文件', type: 'error' };
                return;
            }

            const formData = new FormData();
            formData.append('file', this.selectedFileSecure);

            try {
                const response = await uploadScript(formData);
                if (response.code === 0) {
                    this.uploadMessageSecure = { text: `上传成功: ${response.data.filename}`, type: 'success' };
                    this.secureIncludeFilename = response.data.filename;
                } else {
                    this.uploadMessageSecure = { text: `上传失败: ${response.msg}`, type: 'error' };
                }
            } catch (error) {
                this.uploadMessageSecure = { text: '文件上传时发生错误: ' + error.message, type: 'error' };
            }
        },
        
        // 测试安全接口 - 模拟攻击（会被拦截）
        async testSecureIncludeAttack() {
            if (!this.secureIncludeFilename) {
                this.includeMessageSecure = { text: '请输入文件名', type: 'error' };
                return;
            }

            try {
                this.includeMessageSecure = { text: '正在尝试触发文件包含...', type: 'success' };
                
                const response = await groovyIncludeSecure({
                    file: this.secureIncludeFilename
                });

                const html = await response.text();
                this.secureAttackResult = html;
                
                // 判断是否被拦截
                if (html.includes('拒绝执行') || html.includes('安全防护')) {
                    this.includeMessageSecure = { text: '✅ 攻击被成功拦截！（非白名单脚本）', type: 'success' };
                } else {
                    this.includeMessageSecure = { text: '触发完成', type: 'success' };
                }

            } catch (error) {
                this.includeMessageSecure = { text: '请求失败: ' + error.message, type: 'error' };
            }
        },
        
        // 测试白名单脚本（正确使用）
        async testSecureWhitelist() {
            if (!this.secureWhitelistScript) {
                this.whitelistMessageSecure = { text: '请输入脚本名称', type: 'error' };
                return;
            }

            try {
                this.whitelistMessageSecure = { text: '正在执行白名单脚本...', type: 'success' };
                
                const response = await groovyIncludeSecure({
                    file: this.secureWhitelistScript
                });

                const html = await response.text();
                this.secureWhitelistResult = html;
                
                // 判断执行结果
                if (html.includes('安全脚本执行成功') || html.includes('✅')) {
                    this.whitelistMessageSecure = { text: '✅ 白名单脚本执行成功（从 /app/file/ 读取）', type: 'success' };
                } else if (html.includes('拒绝执行') || html.includes('安全防护')) {
                    this.whitelistMessageSecure = { text: '❌ 脚本被拦截（非白名单）', type: 'error' };
                } else {
                    this.whitelistMessageSecure = { text: '执行完成', type: 'success' };
                }

            } catch (error) {
                this.whitelistMessageSecure = { text: '请求失败: ' + error.message, type: 'error' };
            }
        }
    }
};
</script>

<style>
.vuln-info {
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
    /* 设置字体大小为 12px */
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

.bg-purple {
    background: #d3dce6;
}

.grid-content {
    border-radius: 4px;
    height: 100%;
    padding: 10px;
}

.grid-flex {
    display: flex;
    align-items: stretch;
    /* 让子元素在交叉轴方向（垂直方向）拉伸以匹配高度 */
}

.center-dialog {
    text-align: center;
    margin: 0 auto;
}

/* 测试对话框样式 */
.test-container {
    max-width: 100%;
    margin: 0 auto;
}

.test-section {
    margin-bottom: 30px;
    padding: 20px;
    border: 1px solid #e4e7ed;
    border-radius: 8px;
    background-color: #fafafa;
}

.test-section h3 {
    margin-top: 0;
    margin-bottom: 15px;
    color: #409EFF;
    font-size: 16px;
}

.result-box {
    margin-top: 15px;
    padding: 15px;
    border: 1px solid #dcdfe6;
    border-radius: 4px;
    background-color: #fff;
}
</style>
