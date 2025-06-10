<template>
  <div class="dashboard-container">
    <!-- 项目介绍部分 -->
    <div class="section project-intro">
      <h2 class="section-title">项目介绍</h2>
      <div class="content-box">
        <p>基于 Vue + SpringBoot 开发的安全靶场，一个专为安全爱好者、渗透测试代码审计人员打造的前后端分离的演练平台。<br />
          本项目包含了常见的Web安全漏洞类型，如SQL注入、XSS、SSRF、命令注入、文件上传、路径穿越、身份认证漏洞、三方组件漏洞、URL跳转、业务逻辑漏洞、配置不当等，每个漏洞都提供了详细的代码说明和复现环境。</p>
      </div>
    </div>

    <!-- 项目架构部分 -->
    <div class="section project-architecture">
      <h2 class="section-title">项目架构</h2>
      <div class="content-box">
        <!-- 文件结构说明 -->
        <div class="file-structure">
          <h3><i class="el-icon-folder"></i> 文件结构</h3>
          <div class="structure-content">
            <div class="structure-item">
              <h4>前端部分 (SpringVulnBoot-Frontend)</h4>
              <ul>
                <li><code>src/</code> - 源代码目录
                  <ul class="sub-list">
                    <li><code>api/</code> - API接口定义</li>
                    <li><code>assets/</code> - 静态资源</li>
                    <li><code>components/</code> - 公共组件</li>
                    <li><code>icons/</code> - 图标资源</li>
                    <li><code>layout/</code> - 布局组件</li>
                    <li><code>router/</code> - 路由配置</li>
                    <li><code>store/</code> - Vuex状态管理</li>
                    <li><code>styles/</code> - 全局样式</li>
                    <li><code>utils/</code> - 工具函数</li>
                    <li><code>views/</code> - 页面组件
                      <ul class="sub-list">
                        <li><code>dashboard/</code> - 首页</li>
                        <li><code>login/</code> - 登录页</li>
                        <li><code>sqli/</code> - SQL注入漏洞</li>
                        <li><code>xss/</code> - XSS漏洞</li>
                        <li><code>ssrf/</code> - SSRF漏洞</li>
                        <li><code>cmdexec/</code> - 命令执行漏洞</li>
                        <li><code>accessControl/</code> - 权限漏洞</li>
                        <li><code>authentication/</code> - 认证漏洞</li>
                        <li><code>fileupload/</code> - 文件上传漏洞</li>
                        <li><code>pathtraversal/</code> - 路径穿越漏洞</li>
                        <li><code>openUrl/</code> - URL跳转漏洞</li>
                        <li><code>components/</code> - 组件漏洞</li>
                        <li><code>tree/</code> - 树形结构</li>
                        <li><code>404.vue</code> - 404页面</li>
                      </ul>
                    </li>
                    <li><code>App.vue</code> - 根组件</li>
                    <li><code>main.js</code> - 入口文件</li>
                    <li><code>permission.js</code> - 权限控制</li>
                    <li><code>settings.js</code> - 项目配置</li>
                  </ul>
                </li>
                <li><code>public/</code> - 静态资源
                  <ul class="sub-list">
                    <li><code>favicon.ico</code> - 网站图标</li>
                    <li><code>index.html</code> - HTML模板</li>
                  </ul>
                </li>
                <li><code>build/</code> - 构建配置</li>
                <li><code>mock/</code> - 模拟数据</li>
                <li><code>tests/</code> - 测试文件</li>
                <li><code>package.json</code> - 项目依赖配置</li>
                <li><code>vue.config.js</code> - Vue项目配置</li>
                <li><code>babel.config.js</code> - Babel配置</li>
                <li><code>jest.config.js</code> - Jest测试配置</li>
                <li><code>jsconfig.json</code> - JavaScript配置</li>
                <li><code>postcss.config.js</code> - PostCSS配置</li>
                <li><code>.eslintrc.js</code> - ESLint配置</li>
                <li><code>.editorconfig</code> - 编辑器配置</li>
                <li><code>nginx.conf</code> - Nginx配置</li>
                <li><code>Dockerfile</code> - Docker配置</li>
              </ul>
            </div>
            <div class="structure-item">
              <h4>后端部分 (SpringVulnBoot-Backend)</h4>
              <ul>
                <li><code>src/main/java/</code> - Java源代码
                  <ul class="sub-list">
                    <li><code>icu/secnotes/</code> - 主包
                      <ul class="sub-list">
                        <li><code>config/</code> - 配置类</li>
                        <li><code>controller/</code> - 控制器
                          <ul class="sub-list">
                            <li><code>SQLI/</code> - SQL注入漏洞</li>
                            <li><code>XSS/</code> - 跨站脚本漏洞</li>
                            <li><code>SSRF/</code> - 服务器端请求伪造</li>
                            <li><code>RCE/</code> - 远程命令执行</li>
                            <li><code>AccessControll/</code> - 权限漏洞</li>
                            <li><code>Authentication/</code> - 身份认证漏洞</li>
                            <li><code>FileUpload/</code> - 文件上传漏洞</li>
                            <li><code>PathTraversal/</code> - 路径穿越漏洞</li>
                            <li><code>Redirect/</code> - URL重定向漏洞</li>
                            <li><code>Components/</code> - 组件漏洞</li>
                            <li><code>LoginController.java</code> - 登录控制器</li>
                          </ul>
                        </li>
                        <li><code>service/</code> - 服务层
                          <ul class="sub-list">
                            <li><code>impl/</code> - 服务实现</li>
                          </ul>
                        </li>
                        <li><code>mapper/</code> - MyBatis映射接口</li>
                        <li><code>pojo/</code> - 实体类</li>
                        <li><code>utils/</code> - 工具类</li>
                        <li><code>exception/</code> - 异常处理</li>
                        <li><code>interceptor/</code> - 拦截器</li>
                        <li><code>SpringVulnBootApplication.java</code> - 启动类</li>
                      </ul>
                    </li>
                  </ul>
                </li>
                <li><code>src/main/resources/</code> - 配置文件
                  <ul class="sub-list">
                    <li><code>application.yml</code> - 主配置文件</li>
                    <li><code>log4j2.xml</code> - 日志配置</li>
                    <li><code>ESAPI.properties</code> - ESAPI安全配置</li>
                    <li><code>banner.txt</code> - 启动Banner配置</li>
                    <li><code>static/</code> - 静态资源</li>
                    <li><code>templates/</code> - 模板文件</li>
                    <li><code>mapper/</code> - MyBatis映射文件</li>
                  </ul>
                </li>
                <li><code>src/test/</code> - 测试代码</li>
                <li><code>pom.xml</code> - Maven配置文件</li>
                <li><code>Dockerfile</code> - Docker配置</li>
                <li><code>docker-compose.yml</code> - Docker编排配置</li>
                <li><code>db.sql</code> - 数据库脚本</li>
              </ul>
            </div>
          </div>
        </div>

        <!-- 架构图展示 -->
        <div class="architecture-diagram">
          <h3><i class="el-icon-s-platform"></i> 系统架构图</h3>
          <div class="diagram-container">
            <img 
              src="@/assets/springvulnboot_network.jpg" 
              alt="系统架构图"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- GitHub关注部分 -->
    <div class="section github-section">
      <h2 class="section-title">支持我们</h2>
      <div class="content-box">
        <p>如果您觉得这个项目对您有帮助，欢迎：</p>
        <ul class="support-list">
          <li><i class="el-icon-star-on"></i> 给项目点个Star</li>
          <li><i class="el-icon-view"></i> 关注项目更新</li>
          <li><i class="el-icon-chat-dot-round"></i> 提出宝贵建议</li>
          <li><i class="el-icon-share"></i> 分享给更多朋友</li>
        </ul>
        <div class="github-link">
          <a href="https://github.com/bansh2eBreak/SpringVulnBoot-backend" target="_blank" class="github-button">
            <i class="el-icon-star-on"></i> Star on GitHub
          </a>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Dashboard'
}
</script>

<style scoped>
.dashboard-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.section {
  margin-bottom: 40px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 12px 0 rgba(0,0,0,0.1);
  padding: 20px;
}

.section-title {
  font-size: 24px;
  color: #303133;
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 2px solid #409EFF;
}

.content-box {
  color: #606266;
  line-height: 1.8;
}

.architecture-item {
  margin-bottom: 20px;
  padding: 15px;
  background: #f5f7fa;
  border-radius: 4px;
}

.architecture-item h3 {
  color: #303133;
  margin-bottom: 10px;
  display: flex;
  align-items: center;
}

.architecture-item h3 i {
  margin-right: 8px;
  color: #409EFF;
}

.support-list {
  list-style: none;
  padding: 0;
  margin: 20px 0;
}

.support-list li {
  margin: 10px 0;
  display: flex;
  align-items: center;
}

.support-list li i {
  color: #409EFF;
  margin-right: 8px;
}

.github-link {
  text-align: center;
  margin-top: 20px;
}

.github-button {
  display: inline-block;
  padding: 10px 20px;
  background: #409EFF;
  color: white;
  text-decoration: none;
  border-radius: 4px;
  transition: background-color 0.3s;
}

.github-button:hover {
  background: #66b1ff;
}

.github-button i {
  margin-right: 5px;
}

.file-structure {
  margin-bottom: 30px;
}

.structure-content {
  display: flex;
  gap: 20px;
  margin-top: 15px;
}

.structure-item {
  flex: 1;
  background: #f5f7fa;
  padding: 20px;
  border-radius: 4px;
  max-height: 800px;
  overflow-y: auto;
}

.structure-item::-webkit-scrollbar {
  width: 6px;
}

.structure-item::-webkit-scrollbar-thumb {
  background: #c0c4cc;
  border-radius: 3px;
}

.structure-item::-webkit-scrollbar-track {
  background: #f5f7fa;
}

.structure-item h4 {
  color: #303133;
  margin-bottom: 10px;
  font-size: 16px;
}

.structure-item ul {
  list-style: none;
  padding-left: 0;
}

.structure-item li {
  margin: 8px 0;
  color: #606266;
  position: relative;
}

.structure-item code {
  background: #e4e7ed;
  padding: 2px 6px;
  border-radius: 3px;
  color: #409EFF;
}

/* 第一层子列表（src下的直接子目录） */
.structure-item > ul > li > ul.sub-list {
  padding-left: 40px;
  margin: 5px 0;
  position: relative;
}

.structure-item > ul > li > ul.sub-list::before {
  content: '';
  position: absolute;
  left: 20px;
  top: 0;
  bottom: 0;
  width: 1px;
  background: #dcdfe6;
}

.structure-item > ul > li > ul.sub-list li {
  margin: 3px 0;
  font-size: 13px;
  color: #606266;
  position: relative;
  padding-left: 4px;
}

.structure-item > ul > li > ul.sub-list li::before {
  content: '';
  position: absolute;
  left: -20px;
  top: 50%;
  width: 12px;
  height: 1px;
  background: #dcdfe6;
}

/* 第二层子列表（views下的子目录） */
.sub-list .sub-list {
  padding-left: 24px;
  margin-left: 4px;
}

.sub-list .sub-list::before {
  left: 8px;
}

.sub-list .sub-list li::before {
  left: -12px;
  width: 6px;
}

/* 第三层子列表 */
.sub-list .sub-list .sub-list {
  padding-left: 20px;
  margin-left: 4px;
}

.sub-list .sub-list .sub-list::before {
  left: 4px;
}

.sub-list .sub-list .sub-list li::before {
  left: -8px;
  width: 4px;
}

/* 调整文件说明的缩进 */
.structure-item li > code + span {
  margin-left: 8px;
}

/* 调整子列表中的文件说明缩进 */
.sub-list li > code + span {
  margin-left: 6px;
}

.system-description {
  margin-top: 30px;
}

.description-content {
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.description-item {
  background: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
}

.description-item h4 {
  color: #303133;
  margin-bottom: 10px;
  font-size: 16px;
  display: flex;
  align-items: center;
}

.description-item h4 i {
  margin-right: 8px;
  color: #409EFF;
}

.description-item p {
  color: #606266;
  line-height: 1.6;
  margin: 0;
}

.architecture-diagram {
  margin-top: 30px;
}

.diagram-container {
  background: #fff;
  box-shadow: 0 2px 12px 0 rgba(0,0,0,0.1);
  overflow: hidden;
  padding: 0;
  width: 100%;
  text-align: center;
}

.diagram-container img {
  width: 100%;
  height: auto;
  display: block;
  border-radius: 0;
  box-shadow: none;
  background: #fff;
  padding: 0;
  margin: 0 auto;
}

.diagram-legend {
  display: flex;
  justify-content: center;
  gap: 20px;
  margin-top: 15px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 5px;
}

.legend-color {
  width: 16px;
  height: 16px;
  border-radius: 3px;
}

@media (max-width: 768px) {
  .structure-content {
    flex-direction: column;
  }
  
  .diagram-legend {
    flex-wrap: wrap;
  }
}
</style>