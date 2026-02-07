<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">Mass Assignment（批量赋值）漏洞</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              Mass Assignment（批量赋值）漏洞是指应用程序在处理用户输入时，直接使用实体类（Entity）接收前端参数，
              导致所有对象属性都可以被前端传入的参数覆盖。攻击者可以通过添加额外的参数来修改不应被修改的敏感字段。
              <br /><br />
              <span style="color: red;">典型场景：</span>
              <br />
              • 用户修改头像：正常功能只允许修改头像，但攻击者注入 role=admin 参数提权
              <br />
              • 用户注册：注入 isAdmin=true、verified=true 参数绕过验证
              <br />
              • 订单修改：注入 price=0.01、discount=99 参数篡改价格
              <br /><br />
              <span style="color: red;">真实案例：</span>
              <br />
              • GitHub（2012年）：攻击者通过 Mass Assignment 漏洞上传公钥到任意组织
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              Mass Assignment 漏洞的危害包括：
              <br /><br />
              • 权限提升：普通用户可以将自己提升为管理员
              <br />
              • 数据篡改：修改不应被修改的敏感字段（如价格、余额等）
              <br />
              • 业务逻辑绕过：绕过验证流程、审核流程等
              <br />
              • 账户接管：修改邮箱、手机号等关键信息
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】使用 DTO（Data Transfer Object）代替实体类</span>
              <br />
              这是 OWASP 推荐的主要防御方法。创建专门的 DTO 类，只包含允许用户修改的字段。
              <br /><br />
              <span style="color: red;">【建议】字段白名单验证</span>
              <br />
              明确定义哪些字段可以被用户修改，敏感字段从数据库查询原值。
              <br /><br />
              <span style="color: red;">【可选】使用框架的绑定白名单功能</span>
              <br />
              Spring MVC: @InitBinder + WebDataBinder.setAllowedFields()
              <br />
              Spring MVC: @InitBinder + WebDataBinder.setDisallowedFields()
              <br />
              Laravel: $fillable 或 $guarded 属性
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a
                href="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
                target="_blank"
                style="text-decoration: underline;"
              >《OWASP Mass Assignment Cheat Sheet》</a>：了解 Mass Assignment 漏洞的详细防护指南。
              <br />
              <a
                href="https://cwe.mitre.org/data/definitions/915.html"
                target="_blank"
                style="text-decoration: underline;"
              >《CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes》</a>：CWE 官方定义。
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>

    <!-- 漏洞演示 -->
    <div class="code-demo">
      <el-row :gutter="20" class="grid-flex">
        <!-- 漏洞版本 -->
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - 直接使用实体类接收参数（通用更新接口）
              <div>
                <el-button type="danger" round size="mini" @click="openVulnDialog">
                  去测试
                </el-button>
              </div>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 【漏洞版本】修改用户头像
 * ⚠️ 漏洞点：通用方法被滥用 + 直接使用实体类接收参数
 * 
 * 漏洞成因：
 * 1. updateAdmin() 是为"管理员后台"设计的通用更新方法
 * 2. 开发者为了方便，将它复用到了"用户修改头像"功能
 * 3. Controller 直接使用 Admin 实体类接收参数
 * 4. 结果：用户可以注入 role 参数提权
 */
@PostMapping("/updateProfileVuln")
public Result updateProfileVuln(@RequestBody Admin admin, 
                                 HttpServletRequest request) {
    // 从 token 中获取用户 ID（确保只能修改自己的信息）
    String token = request.getHeader("Authorization");
    String userId = JwtUtils.parseJwt(token).get("id").toString();
    
    // ⚠️ 漏洞点：直接使用 Admin 对象接收前端参数
    // 攻击者可以在请求中添加 role 参数，修改自己的角色
    admin.setId(Integer.parseInt(userId)); // 强制设置为当前登录用户 ID
    
    boolean success = loginService.updateAdmin(admin);
    
    if (success) {
        // 查询更新后的用户信息，返回给前端
        Admin updatedUser = loginService.getAdminById(userId);
        
        // ⚠️ 返回包中包含 role 字段
        // 攻击者看到返回包有 role 字段，就会尝试在请求中注入
        Map&lt;String, Object&gt; responseData = new HashMap&lt;&gt;();
        responseData.put("id", updatedUser.getId());
        responseData.put("username", updatedUser.getUsername());
        responseData.put("name", updatedUser.getName());
        responseData.put("avatar", updatedUser.getAvatar());
        responseData.put("role", updatedUser.getRole());  // 暴露敏感字段
        
        return Result.success(responseData);
    }
    return Result.error("修改失败");
}</code></pre>
          </div>
        </el-col>

        <!-- 安全版本 -->
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 使用 DTO 限制可修改字段
              <div>
                <el-button type="success" round size="mini" @click="openSecDialog">
                  去测试
                </el-button>
              </div>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 安全的 DTO 类（使用"字段白名单"策略）
 */
@Data
public class UpdateAvatarDTO {
    private String avatar;  // 只允许修改：头像
    // ⚠️ 注意：role 字段不在 DTO 中
    // 即使攻击者发送 role 参数，也不会被绑定
}

/**
 * 【安全版本】修改用户头像
 * ✅ 安全点：使用 DTO 接收参数（OWASP 推荐方法）
 */
@PostMapping("/updateProfileSec")
public Result updateProfileSec(@RequestBody UpdateAvatarDTO dto,
                                HttpServletRequest request) {
    String token = request.getHeader("Authorization");
    String userId = JwtUtils.parseJwt(token).get("id").toString();
    
    // ✅ 关键：只设置需要修改的字段
    // Mapper 使用动态 SQL，只有非空字段才会被更新
    // name、role 等字段为 null，保持数据库原值不变
    Admin admin = new Admin();
    admin.setId(Integer.parseInt(userId));
    admin.setAvatar(dto.getAvatar());  // 只接收 DTO 中的 avatar
    
    boolean success = loginService.updateAdmin(admin);
    
    if (success) {
        // 查询更新后的用户信息，返回给前端
        Admin updatedUser = loginService.getAdminById(userId);
        
        // 构造返回数据
        Map&lt;String, Object&gt; responseData = new HashMap&lt;&gt;();
        responseData.put("id", updatedUser.getId());
        responseData.put("username", updatedUser.getUsername());
        responseData.put("name", updatedUser.getName());
        responseData.put("avatar", updatedUser.getAvatar());
        responseData.put("role", updatedUser.getRole());
        
        return Result.success(responseData);
    }
    return Result.error("修改失败");
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 漏洞测试对话框 -->
    <el-dialog :visible.sync="dialogVulnVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">
        Mass Assignment 漏洞测试
      </div>
      <div class="test-container">
        <!-- 测试说明 -->
        <el-alert
          title="测试步骤说明"
          type="warning"
          :closable="false"
          style="margin-bottom: 20px;">
          <div style="line-height: 1.8;">
            <strong>推荐使用 guest 账号测试提权效果：</strong><br/>
            1️⃣ 使用 <span style="color: #E6A23C; font-weight: bold;">guest / guest</span> 账号登录系统<br/>
            2️⃣ 在下方"攻击测试"中选择 <span style="color: #F56C6C; font-weight: bold;">admin（提权为管理员）</span><br/>
            3️⃣ 点击"发起攻击"按钮，提交恶意请求<br/>
            4️⃣ <span style="color: #67C23A; font-weight: bold;">刷新页面</span>，查看左侧菜单是否增加了管理员专属菜单
          </div>
        </el-alert>
        
        <!-- 1. 正常修改资料 -->
        <div class="test-section">
          <h3>1. 正常修改用户头像</h3>
          <el-form :model="vulnForm" label-width="100px">
            <el-form-item label="头像 URL">
              <el-input v-model="vulnForm.avatar" placeholder="输入新的头像地址" style="width: 400px;"></el-input>
            </el-form-item>
          </el-form>
        </div>

        <!-- 2. 攻击测试 -->
        <div class="test-section">
          <h3>2. 攻击测试 <span style="color: red; font-size: 14px; font-weight: normal;">(注入 role 参数提权)</span></h3>
          <el-form :model="vulnForm" label-width="100px">
            <el-form-item label="注入 role">
              <el-select v-model="vulnForm.role" placeholder="选择要注入的角色" style="width: 300px;">
                <el-option label="不注入（正常修改资料）" value=""></el-option>
                <el-option label="admin（提权为管理员）" value="admin"></el-option>
                <el-option label="guest（降权为访客）" value="guest"></el-option>
              </el-select>
            </el-form-item>
          </el-form>
          <div class="attack-buttons">
            <el-button type="danger" @click="testVulnVersion">
              发起攻击
            </el-button>
          </div>
          <div v-if="vulnResult" class="result-box">
            <el-alert
              :title="vulnResult.title"
              :description="vulnResult.message"
              :type="vulnResult.type"
              show-icon>
            </el-alert>
          </div>
        </div>
      </div>
    </el-dialog>

    <!-- 安全版本测试对话框 -->
    <el-dialog :visible.sync="dialogSecVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">
        安全版本测试 - 使用 DTO
      </div>
      <div class="test-container">
        <!-- 测试说明 -->
        <el-alert
          title="测试步骤说明"
          type="success"
          :closable="false"
          style="margin-bottom: 20px;">
          <div style="line-height: 1.8;">
            <strong>验证 DTO 防御效果：</strong><br/>
            1️⃣ 使用 <span style="color: #67C23A; font-weight: bold;">guest / guest</span> 账号登录系统<br/>
            2️⃣ 在下方"攻击测试"中选择 <span style="color: #F56C6C; font-weight: bold;">admin（尝试提权为管理员）</span><br/>
            3️⃣ 点击"发起测试"按钮，尝试发送恶意请求<br/>
            4️⃣ 观察提示信息：<span style="color: #67C23A; font-weight: bold;">攻击被阻止，角色未被修改</span>（DTO 防御成功）
          </div>
        </el-alert>
        
        <!-- 1. 正常修改资料 -->
        <div class="test-section">
          <h3>1. 正常修改用户头像</h3>
          <el-form :model="secForm" label-width="100px">
            <el-form-item label="头像 URL">
              <el-input v-model="secForm.avatar" placeholder="输入新的头像地址" style="width: 400px;"></el-input>
            </el-form-item>
          </el-form>
        </div>

        <!-- 2. 攻击测试 -->
        <div class="test-section">
          <h3>2. 攻击测试 <span style="color: red; font-size: 14px; font-weight: normal;">(尝试注入 role 参数提权)</span></h3>
          <el-form :model="secForm" label-width="100px">
            <el-form-item label="注入 role">
              <el-select v-model="secForm.role" placeholder="选择要注入的角色" style="width: 400px;">
                <el-option label="不注入（正常修改头像）" value=""></el-option>
                <el-option label="admin（尝试提权为管理员）" value="admin"></el-option>
                <el-option label="guest（尝试降权为访客）" value="guest"></el-option>
              </el-select>
            </el-form-item>
          </el-form>
          <div class="attack-buttons">
            <el-button type="success" @click="testSecVersion">
              发起测试
            </el-button>
          </div>
          <div v-if="secResult" class="result-box">
            <el-alert
              :title="secResult.title"
              :description="secResult.message"
              :type="secResult.type"
              show-icon>
            </el-alert>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { updateProfileVuln, updateProfileSec } from '@/api/massAssignment'

export default {
  name: 'MassAssignment',
  data() {
    return {
      activeName: 'first',
      dialogVulnVisible: false,
      dialogSecVisible: false,
      vulnForm: {
        avatar: 'https://cube.elemecdn.com/0/88/03b0d39583f48206768a7534e55bcpng.png',
        role: ''
      },
      secForm: {
        avatar: 'https://cube.elemecdn.com/0/88/03b0d39583f48206768a7534e55bcpng.png',
        role: ''
      },
      vulnResult: null,
      secResult: null
    }
  },
  methods: {
    handleClick(tab, event) {
      console.log(tab, event)
    },
    // 打开漏洞测试对话框
    openVulnDialog() {
      this.vulnResult = null
      this.vulnForm.role = '' // 重置 role 选择
      this.dialogVulnVisible = true
    },
    // 打开安全测试对话框
    openSecDialog() {
      this.secResult = null
      this.secForm.role = '' // 重置 role 选择
      this.dialogSecVisible = true
    },
    // 测试漏洞版本
    testVulnVersion() {
      const payload = {
        avatar: this.vulnForm.avatar
      }
      
      // 如果选择了注入 role
      if (this.vulnForm.role) {
        payload.role = this.vulnForm.role
      }

      updateProfileVuln(payload).then(res => {
        if (res.code === 0) {
          // 获取返回的用户数据
          const userData = res.data
          
          // 如果注入了 role，显示攻击成功
          if (this.vulnForm.role) {
            this.vulnResult = {
              type: 'success',
              title: '✅ 攻击成功',
              message: `你已通过注入 role=${this.vulnForm.role} 参数修改了角色！\n当前角色：${userData.role}\n刷新页面即可看到权限变化。`
            }
          } else {
            this.vulnResult = {
              type: 'success',
              title: '✅ 修改成功',
              message: `头像修改成功（未注入 role 参数）\n当前角色：${userData.role}`
            }
          }
        } else {
          this.vulnResult = {
            type: 'error',
            title: '❌ 修改失败',
            message: res.msg || '修改失败'
          }
        }
      }).catch(() => {
        this.vulnResult = {
          type: 'error',
          title: '❌ 请求失败',
          message: '网络请求失败，请检查后端服务'
        }
      })
    },
    // 测试安全版本
    testSecVersion() {
      // 构造请求数据
      const payload = {
        avatar: this.secForm.avatar
      }
      
      // 如果选择了注入 role，尝试发送（但后端 DTO 不会接收）
      if (this.secForm.role) {
        payload.role = this.secForm.role
      }
      
      updateProfileSec(payload).then(res => {
        if (res.code === 0) {
          // 获取返回的用户数据
          const userData = res.data
          
          // 判断是否尝试了注入
          if (this.secForm.role) {
            this.secResult = {
              type: 'success',
              title: '✅ 攻击失败（防御成功）',
              message: `你尝试注入 role=${this.secForm.role} 参数，但被 DTO 阻止了！\n后端只接收 avatar 字段，role 参数被忽略。\n当前角色：${userData.role}（未被修改）`
            }
          } else {
            this.secResult = {
              type: 'success',
              title: '✅ 修改成功',
              message: `头像修改成功！使用 DTO 限制字段，role 字段未被修改（安全）\n当前角色：${userData.role}`
            }
          }
        } else {
          this.secResult = {
            type: 'error',
            title: '❌ 修改失败',
            message: res.msg || '修改失败'
          }
        }
      }).catch(() => {
        this.secResult = {
          type: 'error',
          title: '❌ 请求失败',
          message: '网络请求失败，请检查后端服务'
        }
      })
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

.test-container {
    padding: 20px;
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

.attack-buttons {
    margin-top: 15px;
    margin-bottom: 15px;
}

.attack-buttons .el-button {
    margin-right: 10px;
}

.result-box {
    margin-top: 15px;
}
</style>
