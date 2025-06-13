<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">列目录漏洞（Directory Listing Vulnerability）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              列目录漏洞是指Web服务器错误配置，允许用户直接访问某个目录时，服务器会返回该目录下所有文件和子目录的列表。攻击者可以利用该漏洞获取敏感文件、源码、配置等信息，带来安全隐患。<br/>
              <br/>
              常见原因：<br/>
              1. Nginx/Apache等Web服务器未关闭autoindex或Indexes功能。<br/>
              2. 目录下没有默认首页（如index.html），服务器自动列出目录内容。<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 泄露敏感文件（如源码、配置、备份文件等）<br/>
              2. 揭示目录结构，便于进一步攻击<br/>
              3. 可能暴露未公开的接口或资源<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="错误配置" name="third">
            <div class="vuln-detail">
              <b>典型Nginx错误配置：</b>
              <pre v-highlightjs><code class="nginx">location /static/ {
    alias /usr/share/nginx/html/static/;
    autoindex on;
}</code></pre>
              <span style="color: red;">此配置会导致/static/目录及其子目录可被任意用户遍历，存在严重安全风险！</span>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全配置" name="fourth">
            <div class="vuln-detail">
              <b>安全的Nginx配置：</b>
              <pre v-highlightjs><code class="nginx">location /static/ {
    alias /usr/share/nginx/html/static/;
    autoindex off;
}</code></pre>
              <span style="color: green;">关闭autoindex，禁止目录列举，防止敏感信息泄露。</span>
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
              漏洞代码 - Nginx错误配置
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="nginx">location /static/ {
    alias /usr/share/nginx/html/static/;
    autoindex on;
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - Nginx安全配置
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="nginx">location /static/ {
    alias /usr/share/nginx/html/static/;
    autoindex off;
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>
    <!-- 漏洞测试对话框 -->
    <el-dialog title="列目录漏洞测试 - /static/" :visible.sync="vulnDialogVisible" class="center-dialog" width="60%">
      <div style="text-align: left; color: red; font-style: italic;">
        下面展示的是Nginx开启autoindex后，/static/目录的内容：
      </div>
      <div v-if="loading" style="text-align:center;padding:20px;">
        <el-spinner /> 加载中...
      </div>
      <div v-else class="preview-content">
        <div v-html="dirListHtml" class="preview-text"></div>
      </div>
    </el-dialog>
    <!-- 安全代码测试对话框 -->
    <el-dialog title="安全配置测试 - /static/" :visible.sync="secDialogVisible" class="center-dialog" width="60%">
      <div style="text-align: left; color: green; font-style: italic;">
        关闭autoindex后，访问/static/目录将返回403 Forbidden，无法列出目录内容。
      </div>
      <div class="preview-content">
        <div class="preview-text">
          <el-alert title="403 Forbidden" type="error" show-icon />
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
export default {
  name: 'DirListVuln',
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false,
      dirListHtml: '',
      loading: false
    }
  },
  methods: {
    handleClick(tab, event) {},
    showVulnDialog(path = '/static/') {
      this.vulnDialogVisible = true;
      this.loading = true;
      this.dirListHtml = '';
      fetch(path)
        .then(r => r.text())
        .then(html => {
          this.dirListHtml = html;
          this.loading = false;
          this.$nextTick(() => {
            // 绑定弹窗内所有a标签的点击事件，实现多级目录浏览
            const links = document.querySelectorAll('.preview-text a');
            links.forEach(link => {
              link.onclick = (e) => {
                const href = link.getAttribute('href');
                // 只处理/static/开头的相对目录
                if (href && href.startsWith('/static/')) {
                  e.preventDefault();
                  this.showVulnDialog(href);
                }
              };
            });
          });
        })
        .catch(() => {
          this.dirListHtml = '<div style="color:red;">获取目录失败</div>';
          this.loading = false;
        });
    },
    showSecDialog() {
      this.secDialogVisible = true;
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