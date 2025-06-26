<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">Actuator端点暴露漏洞（Spring Boot Actuator Endpoint Exposure）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              Spring Boot Actuator端点暴露漏洞是指由于配置不当，导致Spring Boot Actuator的敏感端点被未授权访问。攻击者可以通过这些端点获取应用配置、环境变量、系统信息等敏感数据，甚至可能执行危险操作。<br/>
              <br/>
              常见原因：<br/>
              1. 生产环境中未正确配置Actuator端点的访问控制<br/>
              2. 启用了过多的敏感端点（如/env、/configprops、/heapdump等）<br/>
              3. 未使用Spring Security保护Actuator端点<br/>
              4. 配置了错误的端点暴露策略<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 敏感信息泄露（环境变量、配置信息、数据库连接等）<br/>
              2. 系统信息暴露（版本信息、依赖信息、运行状态等）<br/>
              3. 可能被用于进一步攻击（如获取数据库密码、API密钥等）<br/>
              4. 拒绝服务攻击（如/heapdump端点可能消耗大量资源）<br/>
              5. 应用架构信息泄露，便于攻击者制定攻击策略<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】限制Actuator端点暴露范围
              生产环境中只暴露必要的端点（如health、info），明确排除敏感端点（如env、configprops、heapdump、threaddump），避免敏感信息泄露。
              <br />
              <br />
              【必须】配置端点详细信息显示策略
              设置health端点的show-details为when-authorized，env端点的show-values为never，避免在未授权情况下显示敏感信息。
              <br />
              <br />
              【必须】使用Spring Security保护Actuator端点
              配置访问控制，只允许管理员角色访问敏感端点，对健康检查等基础端点设置适当的访问权限。
              <br />
              <br />
              【建议】自定义端点路径
              修改Actuator的base-path，避免使用默认的/actuator路径，增加攻击者发现端点的难度。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <b>相关技术文档和参考资源：</b>
              <br/><br/>
              <b>官方文档：</b>
              <ul>
                <li><a href="https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html" target="_blank" style="text-decoration: underline;">Spring Boot Actuator官方文档</a></li>
                <li><a href="https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints" target="_blank" style="text-decoration: underline;">Actuator端点配置指南</a></li>
              </ul>
              <br/>
              <b>安全最佳实践：</b>
              <ul>
                <li><a href="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration" target="_blank" style="text-decoration: underline;">OWASP A06:2021 - 安全配置错误</a></li>
                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Spring_Boot_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP Spring Boot安全配置检查清单</a></li>
              </ul>
              <br/>
              <b>漏洞分析文章：</b>
              <ul>
                <li><a href="https://www.veracode.com/blog/secure-development/spring-boot-actuator-endpoints-security" target="_blank" style="text-decoration: underline;">Spring Boot Actuator端点安全分析</a></li>
                <li><a href="https://www.baeldung.com/spring-boot-actuator-security" target="_blank" style="text-decoration: underline;">Spring Boot Actuator安全配置教程</a></li>
              </ul>
              <br/>
              <b>工具和检测：</b>
              <ul>
                <li><a href="https://github.com/spring-projects/spring-boot/tree/main/spring-boot-project/spring-boot-actuator" target="_blank" style="text-decoration: underline;">Spring Boot Actuator源码</a></li>
                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" style="text-decoration: underline;">OWASP安全配置检查清单</a></li>
              </ul>
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
              危险配置 - 暴露所有端点
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="yaml"># Actuator配置 - 启用所有端点
management:
  endpoints:
    web:
      exposure:
        include: "*"  # 启用所有端点
      base-path: /actuator
  endpoint:
    health:
      show-details: always
    env:
      show-values: always</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全配置 - 限制端点暴露
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="yaml">management:
  endpoints:
    web:
      exposure:
        include: health,info
        exclude: env,configprops
      base-path: /actuator
  endpoint:
    health:
      show-details: when-authorized
    env:
      show-values: never</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全配置 - 增加Actuator授权
              <el-button type="success" round size="mini" @click="showAuthDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="yaml">@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // 创建管理员用户，用于访问Actuator端点
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(admin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // 禁用CSRF，因为这是API服务
            .authorizeRequests(authz -> authz
                // 允许所有非Actuator端点的请求
                .antMatchers("/actuator/**").hasRole("ADMIN")
                .anyRequest().permitAll()
            )
            .httpBasic(httpBasic -> httpBasic
                .realmName("Spring Boot Actuator")
            );

        return http.build();
    }
} </code></pre>
          </div>
        </el-col>
      </el-row>
    </div>
    <!-- 漏洞测试对话框 -->
    <el-dialog title="Actuator端点暴露测试" :visible.sync="vulnDialogVisible" class="center-dialog" width="60%">
      <div style="text-align: left; color: red; font-style: italic;">
        下面展示的是Spring Boot Actuator暴露的敏感端点信息：
      </div>
      <div v-if="loading" style="text-align:center;padding:20px;">
        <el-spinner /> 加载中...
      </div>
      <div v-else class="preview-content">
        <el-tabs v-model="endpointTab" type="card">
          <el-tab-pane label="环境变量" name="env">
            <div v-html="envData" class="preview-text"></div>
          </el-tab-pane>
          <el-tab-pane label="配置属性" name="configprops">
            <div v-html="configPropsData" class="preview-text"></div>
          </el-tab-pane>
          <el-tab-pane label="健康检查" name="health">
            <div v-html="healthData" class="preview-text"></div>
          </el-tab-pane>
          <el-tab-pane label="应用指标" name="metrics">
            <div v-html="metricsData" class="preview-text"></div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>
    <!-- 安全代码测试对话框 -->
    <el-dialog title="安全配置测试" :visible.sync="secDialogVisible" class="center-dialog" width="60%">
      <div style="text-align: left; color: green; font-style: italic;">
        安全配置后，敏感端点将被限制访问或返回有限信息。
      </div>
      <div class="preview-content">
        <div class="preview-text">
          <el-alert title="敏感端点已被保护" type="success" show-icon />
          <br/>
          <p>可访问的端点：</p>
          <ul>
            <li>/actuator/health - 健康检查（有限信息）</li>
            <li>/actuator/info - 应用信息</li>
          </ul>
          <p>被保护的端点：</p>
          <ul>
            <li>/actuator/env - 环境变量（已禁用）</li>
            <li>/actuator/configprops - 配置属性（已禁用）</li>
            <li>/actuator/heapdump - 堆转储（已禁用）</li>
          </ul>
        </div>
      </div>
    </el-dialog>
    <el-dialog title="安全配置-Actuator授权测试" :visible.sync="authDialogVisible" class="center-dialog" width="60%">
      <div style="text-align: left; color: #409EFF; font-style: italic;">
        现在Actuator端点已开启认证，未登录用户无法访问。<br/>
        <br/>
        <b>测试方法：</b>
        <pre>
# 未认证访问（会被拒绝）
curl http://localhost:8080/actuator/health

# 使用admin/admin123认证访问（可访问）
curl -u admin:admin123 http://localhost:8080/actuator/health
        </pre>
        <el-alert title="只有拥有ADMIN角色的用户才能访问/actuator端点" type="info" show-icon />
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { getEnvInfo, getConfigProps, getHealthInfo, getMetricsInfo } from '@/api/actuator'

export default {
  name: 'ActuatorVuln',
  data() {
    return {
      activeName: 'first',
      endpointTab: 'env',
      vulnDialogVisible: false,
      secDialogVisible: false,
      authDialogVisible: false,
      loading: false,
      envData: '',
      configPropsData: '',
      healthData: '',
      metricsData: ''
    }
  },
  methods: {
    handleClick(tab, event) {},
    showVulnDialog() {
      this.vulnDialogVisible = true;
      this.loading = true;
      this.loadEndpointData();
    },
    showSecDialog() {
      this.secDialogVisible = true;
    },
    showAuthDialog() {
      this.authDialogVisible = true;
    },
    loadEndpointData() {
      // 加载环境变量数据
      getEnvInfo()
        .then(data => {
          this.envData = this.formatJson(data);
        })
        .catch(() => {
          this.envData = '<div style="color:red;">获取环境变量失败</div>';
        });

      // 加载配置属性数据
      getConfigProps()
        .then(data => {
          this.configPropsData = this.formatJson(data);
        })
        .catch(() => {
          this.configPropsData = '<div style="color:red;">获取配置属性失败</div>';
        });

      // 加载健康检查数据
      getHealthInfo()
        .then(data => {
          this.healthData = this.formatJson(data);
        })
        .catch(() => {
          this.healthData = '<div style="color:red;">获取健康检查失败</div>';
        });

      // 加载应用指标数据
      getMetricsInfo()
        .then(data => {
          this.metricsData = this.formatJson(data);
        })
        .catch(() => {
          this.metricsData = '<div style="color:red;">获取应用指标失败</div>';
        });

      this.loading = false;
    },
    formatJson(data) {
      return '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
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
    max-height: 400px;
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