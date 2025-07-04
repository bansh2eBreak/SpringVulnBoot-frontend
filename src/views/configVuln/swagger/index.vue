<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">Swagger未授权访问漏洞（Swagger UI Unauthorized Exposure）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              Swagger UI 未授权访问漏洞是指由于未对Swagger接口文档页面进行访问控制，导致攻击者可直接访问 <code>/swagger-ui.html</code>，查看和调试所有后端接口，造成敏感信息泄露和接口被滥用。<br/>
              <br/>
              常见原因：<br/>
              1. 生产环境未禁用Swagger相关依赖和配置<br/>
              2. 未对Swagger UI页面加认证保护<br/>
              3. 配置不当导致Swagger接口文档对外暴露<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              1. 敏感接口信息泄露（所有API、参数、响应等）<br/>
              2. 可直接调试后端接口，造成数据泄露或被恶意操作<br/>
              3. 攻击者可利用Swagger UI进行接口Fuzz和漏洞挖掘<br/>
              4. 影响系统安全合规性<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              【必须】生产环境禁用Swagger相关依赖和配置<br/>
              【必须】为Swagger UI页面加认证保护，仅授权用户可访问<br/>
              【建议】仅在开发/测试环境开放Swagger UI<br/>
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <b>相关技术文档和参考资源：</b><br/><br/>
              <b>官方文档：</b>
              <ul>
                <li><a href="https://springdoc.org/" target="_blank" style="text-decoration: underline;">SpringDoc官方文档</a></li>
                <li><a href="https://swagger.io/docs/" target="_blank" style="text-decoration: underline;">Swagger官方文档</a></li>
              </ul>
              <br/>
              <b>安全最佳实践：</b>
              <ul>
                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Spring_Boot_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP Spring Boot安全配置检查清单</a></li>
                <li><a href="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration" target="_blank" style="text-decoration: underline;">OWASP A06:2021 - 安全配置错误</a></li>
              </ul>
              <br/>
              <b>漏洞分析文章：</b>
              <ul>
                <li><a href="https://www.cnblogs.com/zhangjianbing/p/16807341.html" target="_blank" style="text-decoration: underline;">Spring Boot Swagger安全风险分析</a></li>
                <li><a href="https://www.freebuf.com/vuls/329181.html" target="_blank" style="text-decoration: underline;">Swagger UI未授权访问漏洞分析</a></li>
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
              漏洞代码 - Swagger未授权暴露
              <el-button type="danger" round size="mini" @click="openSwagger">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// SpringDoc OpenAPI 配置类及Swagger认证配置

<font color="red">说明：当前环境swagger ui加了认证，账号密码是：admin/admin123，请使用该账号密码访问swagger ui. 
如需测试未授权访问，可通过修改SecurityConfig代码来实现！</font>

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("SpringVulnBoot API文档")
                        .description("安全漏洞靶场的Swagger API文档")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Security Team")
                                .url("https://github.com/bansh2eBreak/SpringVulnBoot-backend"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                                
                // JWT认证，APIKEY类型，header为authorization，原样传递token
                .addSecurityItem(new SecurityRequirement().addList("JWT"))
                .schemaRequirement("JWT", new SecurityScheme()
                        .name("authorization")
                        .type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.HEADER));
    }
    
} 

// WebConfig配置类
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Autowired
    private LoginCheckInterceptor loginCheckInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(loginCheckInterceptor).addPathPatterns("/**").excludePathPatterns("/login").excludePathPatterns("/openUrl/**")
                .excludePathPatterns("/swagger-ui/**")
                .excludePathPatterns("/swagger-ui.html")
                .excludePathPatterns("/v3/api-docs/**");
    }

}

// application.yml 配置
springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    url: /v3/api-docs
    path: /swagger-ui.html
    disable-swagger-default-url: true
</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - Swagger加认证
              <el-button type="success" round size="mini" @click="openSwaggerAuth">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">// 为Swagger UI加认证
@Configuration
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
                .antMatchers("/swagger-ui.html", "/swagger-ui/**",
                "/v3/api-docs", "/v3/api-docs/**").hasRole("ADMIN")
                .anyRequest().permitAll()
            )
            .httpBasic(httpBasic -> httpBasic
                .realmName("Spring Boot Actuator")
            );

        return http.build();
    }
    
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
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 禁用Swagger
            </el-row>
            <pre v-highlightjs><code class="yaml"># 生产环境禁用Swagger

# 1. 不引入下面springdoc-openapi依赖
&lt;dependency&gt;
    &lt;groupId&gt;org.springdoc&lt;/groupId&gt;
    &lt;artifactId&gt;springdoc-openapi-ui&lt;/artifactId&gt;
    &lt;version&gt;1.7.0&lt;/version&gt;
&lt;/dependency&gt;

# 2. 通过配置禁用
springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    enabled: false
    url: /v3/api-docs
    path: /swagger-ui.html
    disable-swagger-default-url: true


</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>



  </div>
</template>

<script>


export default {
  name: 'SwaggerVuln',
  data() {
    return {
      activeName: 'first'
    }
  },
  methods: {
    handleClick(tab, event) {},
    openSwagger() {
      window.open('http://localhost:8080/swagger-ui.html', '_blank');
    },
    openSwaggerAuth() {
      window.open('http://localhost:8080/swagger-ui.html', '_blank');
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