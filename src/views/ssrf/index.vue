<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">SSRF服务器端请求伪造漏洞 -- Server-Side Request Forgery</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              SSRF（Server-Side Request Forgery）是一种由攻击者构造请求，由服务端发起请求的安全漏洞。一般情况下，SSRF攻击的目标是外网无法访问的内部系统。SSRF形成的原因大都是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 探测内网信息：攻击者可以通过SSRF漏洞探测内网主机和端口信息<br/>
              2. 攻击内网服务：攻击者可以通过SSRF漏洞攻击内网中的其他服务<br/>
              3. 读取本地文件：攻击者可以通过file://协议读取服务器上的敏感文件<br/>
              4. 访问云服务元数据：攻击者可以访问云服务提供商的元数据服务
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】限制请求的协议<br/>
              1. 只允许http和https协议<br/>
              2. 禁止使用file://、gopher://、dict://等危险协议<br/>
              <br/>
              【必须】限制请求的IP<br/>
              1. 禁止访问内网IP（127.0.0.1、192.168.0.0/16、10.0.0.0/8、172.16.0.0/12）<br/>
              2. 禁止访问云服务元数据IP（169.254.169.254）<br/>
              <br/>
              【建议】使用白名单<br/>
              1. 只允许访问指定的域名<br/>
              2. 使用正则表达式严格匹配URL
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" target="_blank" style="text-decoration: underline;">《OWASP SSRF》</a><br/>
              <a href="https://portswigger.net/web-security/ssrf" target="_blank" style="text-decoration: underline;">《PortSwigger SSRF》</a>
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
              漏洞代码 - 图片预览SSRF
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * 存在SSRF漏洞的图片预览功能
 */
@GetMapping("/vuln1")
public Result previewImage(@RequestParam String url) {
    try {
        // 直接使用用户输入的URL获取图片，没有进行任何过滤
        URL imageUrl = new URL(url);
        URLConnection connection = imageUrl.openConnection();
        byte[] imageBytes = connection.getInputStream().readAllBytes();
        String base64Image = Base64.getEncoder().encodeToString(imageBytes);
        return Result.success(base64Image);
    } catch (IOException e) {
        return Result.error("图片预览失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 图片预览SSRF防护
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * 安全的图片预览功能
 */
@GetMapping("/sec1")
public Result previewImageSec(@RequestParam String url) {
    try {
        // 检查URL是否合法
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return Result.error("只允许http和https协议");
        }

        // 检查是否是内网IP
        URL imageUrl = new URL(url);
        String host = imageUrl.getHost();
        if (isInternalIP(host)) {
            return Result.error("不允许访问内网IP");
        }

        // 获取图片
        URLConnection connection = imageUrl.openConnection();
        byte[] imageBytes = connection.getInputStream().readAllBytes();
        String base64Image = Base64.getEncoder().encodeToString(imageBytes);
        return Result.success(base64Image);
    } catch (IOException e) {
        return Result.error("图片预览失败: " + e.getMessage());
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 漏洞测试对话框 -->
    <el-dialog title="SSRF漏洞测试" :visible.sync="vulnDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，以下是一些常见的SSRF测试payload：<br>
        1. file:///etc/passwd - 读取系统文件<br>
        2. http://127.0.0.1:8080 - 探测内网服务<br>
        3. http://169.254.169.254/latest/meta-data/ - 访问云服务元数据<br>
        4. dict://127.0.0.1:6379/info - 探测Redis服务<br>
        5. gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*1%0d%0a$4%0d%0aquit%0d%0a - 攻击Redis服务
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="正常URL">
          <el-input v-model="vulnForm.normalUrl" type="textarea" placeholder="请输入正常的图片URL，如：https://example.com/image.jpg"></el-input>
        </el-form-item>
        <el-form-item label="恶意URL">
          <el-input v-model="vulnForm.maliciousUrl" type="textarea" placeholder="请输入恶意URL，如：file:///etc/passwd"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="previewImage('vuln', 'normal')">正常测试</el-button>
          <el-button type="danger" @click="previewImage('vuln', 'malicious')">恶意测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="vulnForm.content" class="preview-content">
        <!-- 如果是正常图片URL，显示图片 -->
        <img v-if="vulnForm.isImage" 
             :src="vulnForm.content" 
             alt="预览图片" 
             class="preview-image"
             @error="handleImageError">
        <!-- 如果是其他内容，显示文本 -->
        <div v-else class="preview-text">
          <pre>{{ vulnForm.content }}</pre>
        </div>
      </div>
    </el-dialog>

    <!-- 安全代码测试对话框 -->
    <el-dialog title="SSRF安全防护测试" :visible.sync="secDialogVisible" class="center-dialog">
      <div style="text-align: left; color: red; font-style: italic;">
        注意，以下是一些会被安全防护拦截的payload：<br>
        1. file:///etc/passwd - 协议限制（只允许http/https）<br>
        2. http://127.0.0.1:8080 - IP限制（禁止访问内网IP）<br>
        3. http://169.254.169.254/latest/meta-data/ - IP限制（禁止访问云服务元数据）<br>
        4. dict://127.0.0.1:6379/info - 协议限制（只允许http/https）<br>
        5. gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*1%0d%0a$4%0d%0aquit%0d%0a - 协议限制（只允许http/https）
      </div>
      <el-form class="demo-form-inline">
        <el-form-item label="正常URL">
          <el-input v-model="secForm.normalUrl" type="textarea" placeholder="请输入正常的图片URL，如：https://example.com/image.jpg"></el-input>
        </el-form-item>
        <el-form-item label="恶意URL">
          <el-input v-model="secForm.maliciousUrl" type="textarea" placeholder="请输入恶意URL，如：file:///etc/passwd"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="previewImage('sec', 'normal')">正常测试</el-button>
          <el-button type="danger" @click="previewImage('sec', 'malicious')">恶意测试</el-button>
        </el-form-item>
      </el-form>
      <div v-if="secForm.content" class="preview-content">
        <!-- 如果是正常图片URL，显示图片 -->
        <img v-if="secForm.isImage" 
             :src="secForm.content" 
             alt="预览图片" 
             class="preview-image"
             @error="handleImageError">
        <!-- 如果是其他内容，显示文本 -->
        <div v-else class="preview-text">
          <pre>{{ secForm.content }}</pre>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { previewImageVuln, previewImageSec } from '@/api/ssrf'

export default {
  name: 'SSRF',
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false,
      // 定义默认URL常量
      defaultNormalUrl: 'https://img1.baidu.com/it/u=3200425930,2413475553&fm=253&fmt=auto&app=120&f=JPEG?w=800&h=800?imageView2/1/w/80/h/80',
      defaultMaliciousUrl: 'file:///etc/passwd',
      vulnForm: {
        normalUrl: '',
        maliciousUrl: '',
        content: '',
        isImage: false
      },
      secForm: {
        normalUrl: '',
        maliciousUrl: '',
        content: '',
        isImage: false
      }
    }
  },
  methods: {
    handleClick(tab, event) {
      console.log(tab, event)
    },
    showVulnDialog() {
      // 重置为默认值
      this.vulnForm.normalUrl = this.defaultNormalUrl
      this.vulnForm.maliciousUrl = this.defaultMaliciousUrl
      this.vulnForm.content = ''
      this.vulnForm.isImage = false
      this.vulnDialogVisible = true
    },
    showSecDialog() {
      // 重置为默认值
      this.secForm.normalUrl = this.defaultNormalUrl
      this.secForm.maliciousUrl = this.defaultMaliciousUrl
      this.secForm.content = ''
      this.secForm.isImage = false
      this.secDialogVisible = true
    },
    /**
     * SSRF 漏洞测试接口调用
     * type: 'vuln' 表示漏洞弹框，'sec' 表示安全弹框
     * mode: 'normal' | 'malicious'，分别表示正常测试和恶意测试
     */
    async previewImage(type, mode) {
      let url = ''
      if (type === 'vuln') {
        url = mode === 'normal' ? this.vulnForm.normalUrl : this.vulnForm.maliciousUrl
      } else {
        url = mode === 'normal' ? this.secForm.normalUrl : this.secForm.maliciousUrl
      }
      if (!url) {
        this.$message.error('请输入URL')
        return
      }
      try {
        let res
        if (type === 'vuln') {
          res = await previewImageVuln(url)
        } else {
          res = await previewImageSec(url)
        }
        if (res && res.code === 0) {
          // 一律先按图片展示，加载失败再降级为文本
          const imgSrc = `data:image/jpeg;base64,${res.data}`
          if (type === 'vuln') {
            this.vulnForm.content = imgSrc
            this.vulnForm.isImage = true
          } else {
            this.secForm.content = imgSrc
            this.secForm.isImage = true
          }
        } else {
          if (type === 'vuln') {
            this.vulnForm.content = res.msg || '请求失败'
            this.vulnForm.isImage = false
          } else {
            this.secForm.content = res.msg || '请求失败'
            this.secForm.isImage = false
          }
        }
      } catch (e) {
        if (type === 'vuln') {
          this.vulnForm.content = e.message || '请求异常'
          this.vulnForm.isImage = false
        } else {
          this.secForm.content = e.message || '请求异常'
          this.secForm.isImage = false
        }
      }
    },
    handleImageError(e) {
      // 降级为文本显示
      if (this.vulnDialogVisible) {
        this.vulnForm.isImage = false
        let decoded = ''
        try {
          decoded = atob(this.vulnForm.content.replace(/^data:image\/\w+;base64,/, ''))
        } catch (e) {
          decoded = this.vulnForm.content
        }
        this.vulnForm.content = decoded
      }
      if (this.secDialogVisible) {
        this.secForm.isImage = false
        let decoded = ''
        try {
          decoded = atob(this.secForm.content.replace(/^data:image\/\w+;base64,/, ''))
        } catch (e) {
          decoded = this.secForm.content
        }
        this.secForm.content = decoded
      }
      e.target.style.display = 'none'
    }
  }
}
</script>

<style>
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

.preview-content {
    margin-top: 20px;
    text-align: center;
}

.preview-image {
    max-width: 100%;
    max-height: 300px;
    border: 1px solid #dcdfe6;
    border-radius: 4px;
}

.preview-text {
    text-align: left;
    background-color: #f5f7fa;
    padding: 10px;
    border-radius: 4px;
    max-height: 300px;
    overflow: auto;
}

.preview-text pre {
    margin: 0;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-family: Consolas, Monaco, 'Andale Mono', monospace;
    font-size: 12px;
    line-height: 1.5;
}
</style> 