<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">身份认证漏洞 -- SMS-Based authentication</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            短信验证码是目前最常用的双因素认证手段之一，但如果实现不当，会导致各种安全问题。<br>
                            常见的短信验证码漏洞包括：验证码绕过、验证码暴力破解、验证码泄露、短信轰炸等。这些漏洞可能导致账户被非法接管，用户隐私泄露，甚至造成经济损失。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            <p>短信验证码漏洞可能导致的危害：</p>
                            <ul>
                                <li>账户被非法接管</li>
                                <li>敏感信息泄露</li>
                                <li>用户财产损失</li>
                                <li>平台信誉受损</li>
                                <li>短信轰炸造成用户骚扰</li>
                            </ul>
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】验证码安全实现<br />
                            1. 验证码必须在服务端生成和验证<br />
                            2. 验证码具有一定复杂度，至少4位数字或6位字母数字组合<br />
                            3. 验证码具有时效性，一般5-10分钟内有效<br />
                            4. 验证码使用后立即失效，防止重复使用<br />
                            5. 限制验证码验证失败次数，防止暴力破解<br />
                            6. 限制短信发送频率，防止短信轰炸<br />
                            7. 严禁将短信验证码通过任何形式返回给前端用户
                            <br /><br />
                            【建议】其他安全措施<br />
                            1. 使用图形验证码防止短信轰炸<br />
                            2. 加密存储验证码<br />
                            3. 记录完整的验证码请求和验证日志
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
            <!-- gutter 属性用于设置栅格布局中列与列之间的间距；
             span 属性用于指定 <el-col> 元素所占据的栅格数，在 Element UI 中，栅格系统被分为24列（即24栅格），通过指定 span 属性的值，可以控制每个 <el-col> 元素在布局中所占据的栅格数 -->
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 验证码直接返回前端
                            <el-button type="danger" round size="mini"
                                @click="openDialog('smsLeakDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">// 发送短信接口:接口直接将验证码返回给前端

@PostMapping("/sendVuln1")
public Result sendVuln1(@RequestBody SmsCode smsCode) {
    // 生成四位随机数作为验证码
    smsCode.setCode(String.valueOf((int) ((Math.random() * 9 + 1) * 1000)));
    // 设置验证码的创建时间为当前时间
    smsCode.setCreateTime(LocalDateTime.now());
    // 设置验证码的过期时间为当前时间加5分钟
    smsCode.setExpireTime(LocalDateTime.now().plusMinutes(5));
    // 验证的使用状态和重试次数默认是0，所以生成验证码的时候可以不设置
    smsCodeService.generateCode(smsCode);
    return Result.success("短信验证码已发送，" + smsCode.getCode());
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 验证码不返回
                            <el-button type="success" round size="mini"
                                @click="openDialog('smsSafeDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">// 发送短信接口:验证码不返回给前端

@PostMapping("/sendSafe1")
public Result sendSafe1(@RequestBody SmsCode smsCode) {
    // 生成四位随机数作为验证码
    smsCode.setCode(String.valueOf((int) ((Math.random() * 9 + 1) * 1000)));
    // 设置验证码的创建时间为当前时间
    smsCode.setCreateTime(LocalDateTime.now());
    // 设置验证码的过期时间为当前时间加5分钟
    smsCode.setExpireTime(LocalDateTime.now().plusMinutes(5));
    // 验证的使用状态和重试次数默认是0，所以生成验证码的时候可以不设置
    smsCodeService.generateCode(smsCode);
    return Result.success("短信验证码已发送");
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 短信轰炸
                            <el-button type="danger" round size="mini"
                                @click="openDialog('smsSpamDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">// 发送短信接口:短信轰炸

@PostMapping("/sendSafe1")
public Result sendSafe1(@RequestBody SmsCode smsCode) {
    // 生成四位随机数作为验证码
    smsCode.setCode(String.valueOf((int) ((Math.random() * 9 + 1) * 1000)));
    // 设置验证码的创建时间为当前时间
    smsCode.setCreateTime(LocalDateTime.now());
    // 设置验证码的过期时间为当前时间加5分钟
    smsCode.setExpireTime(LocalDateTime.now().plusMinutes(5));
    // 验证的使用状态和重试次数默认是0，所以生成验证码的时候可以不设置
    smsCodeService.generateCode(smsCode);
    return Result.success("短信验证码已发送");
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 防短信轰炸<el-button type="success"
                                round size="mini" @click="openDialog('smsSpamSafeDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">// 发送短信接口:图形验证码防短信轰炸

@PostMapping("/sendSafe2")
public Result sendSafe2(@RequestParam String phone, @RequestParam String captcha, HttpServletRequest request) {
    //获取服务端生成的验证码
    HttpSession session = request.getSession();
    // 从 Session 中获取验证码
    String sessionCaptcha = (String) request.getSession().getAttribute("captcha");
    // 校验验证码
    if (sessionCaptcha == null || !sessionCaptcha.equalsIgnoreCase(captcha)) {
        return Result.success("图形验证码错误");
    }

    // 清除验证码
    session.removeAttribute("captcha");

    // 生成四位随机数作为验证码
    String smsCode = String.valueOf((int) ((Math.random() * 9 + 1) * 1000));
    // 设置验证码的创建时间为当前时间
    LocalDateTime createTime = LocalDateTime.now();
    // 设置验证码的过期时间为当前时间加5分钟
    LocalDateTime expireTime = LocalDateTime.now().plusMinutes(5);

    // 验证的使用状态和重试次数默认是0，所以生成验证码的时候可以不设置
    smsCodeService.generateCodeByPhoneAndCode(phone, smsCode, createTime, expireTime);
    return Result.success("短信验证码已发送");
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 暴力破解短信验证码
                            <el-button type="danger" round size="mini"
                                @click="openDialog('bruteSmsDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">// 验证短信接口:验证码未限制校验次数，可以暴力破解验证码

@PostMapping("/verifyVuln1")
public Result verifyVuln1(@RequestBody SmsCode smsCode) {
    SmsCode code = smsCodeService.verifyCode(smsCode.getPhone(), smsCode.getCode());
    if (code != null) {
        // 设置验证码为已使用
        smsCodeService.updateSmsCodeUsed(smsCode);
        return Result.success();
    } else {
        return Result.error("验证码错误");
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 防暴力破解
                            <el-button type="success" round size="mini"
                                @click="openDialog('bruteSmsSafeDialog')">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">// 验证短信接口:验证码校验次数限制，防止暴力破解
@PostMapping("/verifySafe1")
public Result verifySafe1(@RequestBody SmsCode smsCode) {
    SmsCode code = smsCodeService.verifyCode(smsCode.getPhone(), smsCode.getCode());
    if (code != null) {
        // 设置验证码为已使用
        smsCodeService.updateSmsCodeUsed(smsCode);
        return Result.success();
    } else {
        // 更新验证码的重试次数
        smsCodeService.updateSmsCodeRetryCount(smsCode.getPhone());
        // 做一个判断，如果验证码的重试次数小于5，返回验证码错误，否则返回错误次数过多
        if (smsCodeService.selectRetryCount(smsCode.getPhone()) &lt; 5) {
            return Result.error("验证码错误");
        } else {
            return Result.error("错误次数过多，请重新获取短信验证码");
        }
    }
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 验证码泄露测试对话框 -->
        <el-dialog title="验证码泄露测试" :visible.sync="smsLeakDialog" class="center-dialog">
            <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
                说明：该接口会泄露短信验证码信息，可被恶意利用！
            </div>
            <div style="margin-bottom: 20px;">
                <el-input v-model="phone" placeholder="请输入手机号" style="width: 200px; margin-right: 20px;"></el-input>
                <el-button type="primary" @click="sendSmsLeak">发送短信</el-button>
            </div>
            <div>
                <p v-if="leakMessage" style="color: red;">{{ leakMessage }}</p>
            </div>
        </el-dialog>

        <!-- 验证码泄露加固测试对话框 -->
        <el-dialog title="验证码泄露测试" :visible.sync="smsSafeDialog" class="center-dialog">
            <div style="text-align: center; color: black; font-style: italic; margin-bottom: 20px;">
                说明：该接口不会泄露短信验证码信息
            </div>
            <div style="margin-bottom: 20px;">
                <el-input v-model="phone" placeholder="请输入手机号" style="width: 200px; margin-right: 20px;"></el-input>
                <el-button type="primary" @click="sendSmsSafe">发送短信</el-button>
            </div>
            <div>
                <p v-if="leakMessage" style="color: red;">{{ leakMessage }}</p>
            </div>
        </el-dialog>

        <!-- 短信轰炸测试对话框 -->
        <el-dialog title="短信发送测试（无限制）" :visible.sync="smsSpamDialog" class="center-dialog">
            <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
                说明：该接口无发送频率限制，可被恶意利用进行短信轰炸！
            </div>
            <div style="margin-bottom: 20px;">
                <el-input v-model="phone" placeholder="请输入手机号" style="width: 200px; margin-right: 20px;"></el-input>
                <el-button type="primary" @click="BruteSendSmsCode">短信轰炸</el-button>
            </div>

            <div>
                <p v-if="leakMessage" style="color: red;">{{ leakMessage }}</p>
            </div>
        </el-dialog>

        <!-- 图形验证码防短信轰炸测试对话框 -->
        <el-dialog title="短信发送测试（图形验证码限制）" :visible.sync="smsSpamSafeDialog" class="center-dialog">
            <div style="text-align: center; color: black; font-style: italic; margin-bottom: 20px;">
                说明：该接口增加了图形验证码人机交互，防短信轰炸！
            </div>
            <div style="margin-bottom: 20px;">
                <el-form :inline="true" class="demo-form-inline">
                    <el-form-item label="手机号" label-width="100px">
                        <el-input v-model="phone" placeholder="请输入手机号"></el-input>
                    </el-form-item>
                    <br />
                    <el-form-item label="图形验证码" label-width="100px">
                        <div style="display: flex; align-items: center;">
                            <el-input v-model="captcha" style="flex: 1;" placeholder="请输入图形验证码"></el-input>
                            <img :src="captchaImageUrl" @click="refreshCaptcha"
                                style="cursor: pointer; margin-left: 10px;" />
                        </div>
                    </el-form-item>
                    <br />
                    <el-form-item>
                        <el-button type="danger" @click="BlockBruteSendSmsCode">短信轰炸</el-button>
                    </el-form-item>
                    <el-form-item>
                        <el-button type="primary" @click="SingleSendSmsCode">正常发送</el-button>
                    </el-form-item>
                </el-form>
            </div>

            <div>
                <p v-if="leakMessage" style="color: red;">{{ leakMessage }}</p>
            </div>
        </el-dialog>

        <!-- 暴力破解短信对话框 -->
        <el-dialog title="短信验证码暴力破解" :visible.sync="bruteSmsDialog" class="center-dialog">
            <div style="text-align: center; color: red; font-style: italic; margin-bottom: 20px;">
                说明：该短信验证码校验接口未限制错误次数，可暴力破解！
            </div>
            <div style="margin-bottom: 20px;">
                <el-input v-model="phone" placeholder="请输入手机号" style="width: 200px;"></el-input>
                <el-button type="primary" @click="sendSmsLeak" style="margin-left: 10px;">发送短信</el-button>
                <el-button type="danger" @click="BruteVerifySmsCode" style="margin-left: 10px;">暴力破解</el-button>
            </div>

            <div>
                <p v-if="leakMessage" style="color: red;">{{ leakMessage }}</p>
            </div>
            <div>
                <p v-if="bruteForceMessage" style="color: red;">{{ bruteForceMessage }}</p>
            </div>
        </el-dialog>

        <!-- 防暴力破解短信对话框 -->
        <el-dialog title="防暴力破解短信对话框 " :visible.sync="bruteSmsSafeDialog" class="center-dialog">
            <div style="text-align: center; color: black; font-style: italic; margin-bottom: 20px;">
                说明：该短信验证码校验接口增加了错误次数限制，最多错误验证5次！
            </div>
            <div style="margin-bottom: 20px;">
                <el-input v-model="phone" placeholder="请输入手机号" style="width: 200px;"></el-input>
                <el-button type="primary" @click="sendSmsLeak" style="margin-left: 10px;">发送短信</el-button>
                <el-button type="danger" @click="BruteVerifySafeSmsCode" style="margin-left: 10px;">暴力破解</el-button>
            </div>

            <div>
                <p v-if="leakMessage" style="color: red;">{{ leakMessage }}</p>
            </div>
            <div>
                <p v-if="bruteForceMessage" style="color: red;">{{ bruteForceMessage }}</p>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import { sendSafe1, sendVuln1, verifyVuln1, verifySafe1, sendSafe2 } from '@/api/smsAuth';

export default {
    data() {
        return {
            activeName: 'first',
            // 对话框显示控制
            smsLeakDialog: false,
            smsSafeDialog: false,
            smsSpamDialog: false,
            smsSpamSafeDialog: false,
            bruteSmsDialog: false,
            bruteSmsSafeDialog: false,
            captcha: '',
            captchaImageUrl: '',

            // 表单数据
            phone: '',
            smsCode: '',

            // 提示消息
            message: '',
            leakMessage: '',
            bruteForceMessage: '',
        };
    },
    created() {
        this.refreshCaptcha();
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        // 调用后端接口获取验证码
        refreshCaptcha() {
            this.captchaImageUrl = 'http://127.0.0.1:8080/authentication/passwordBased/captcha?t=' + new Date().getTime();
        },
        // 打开对话框
        openDialog(dialogName) {
            this[dialogName] = true;
            this.clearMessages();
        },
        // 清除所有提示消息
        clearMessages() {
            this.message = '';
            this.leakMessage = '';
            this.bruteForceMessage = '';
            this.phone = '';
            this.smsCode = ''
        },
        // 查询验证码（泄露接口）
        sendSmsLeak() {
            if (!this.phone) {
                this.leakMessage = '手机号不能为空';
                return;
            }

            // 强化前端校验（使用与后端相同的正则）
            const phoneRegex = /^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\d{8}$/;

            if (!phoneRegex.test(this.phone)) {
                this.leakMessage = '手机号格式错误'
                return;
            }
            // 调用封装的sendVuln1发送请求，获取短信验证码
            sendVuln1({
                "phone": this.phone
            }).then(response => {
                console.log(response.data)
                this.leakMessage = response.data
            }).catch(error => {
                console.error('Error fetching data:', error)
                this.leakMessage = response.data
            })
        },

        // 查询验证码（安全接口）
        sendSmsSafe() {
            if (!this.phone) {
                this.leakMessage = '手机号不能为空';
                return;
            }

            // 强化前端校验（使用与后端相同的正则）
            const phoneRegex = /^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\d{8}$/;

            if (!phoneRegex.test(this.phone)) {
                this.leakMessage = '手机号格式错误'
                return;
            }
            // 调用封装的sendVuln1发送请求，获取短信验证码
            sendSafe1({
                "phone": this.phone
            }).then(response => {
                console.log(response.data)
                this.leakMessage = response.data
            }).catch(error => {
                console.error('Error fetching data:', error)
            })
        },
        // 短信轰炸
        async BruteSendSmsCode() {
            if (!this.phone) {
                this.leakMessage = '手机号不能为空';
                return;
            }

            // 强化前端校验（使用与后端相同的正则）
            const phoneRegex = /^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\d{8}$/;

            if (!phoneRegex.test(this.phone)) {
                this.leakMessage = '手机号格式错误'
                return;
            }

            for (let i = 1; i <= 50; i++) {
                this.leakMessage = `短信轰炸中，第${i}次`;

                try {
                    await sendSafe1({
                        "phone": this.phone
                    });

                    // 等待100ms再发送下一条,避免请求过于频繁
                    await new Promise(resolve => setTimeout(resolve, 100));

                } catch (error) {
                    console.error('Error fetching data:', error);
                }
            }

            this.message = '短信轰炸完成';
        },

        // 图形验证码防短信轰炸
        async BlockBruteSendSmsCode() {
            if (!this.phone) {
                this.leakMessage = '手机号不能为空';
                return;
            }

            // 强化前端校验（使用与后端相同的正则）
            const phoneRegex = /^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\d{8}$/;

            if (!phoneRegex.test(this.phone)) {
                this.leakMessage = '手机号格式错误'
                return;
            }

            for (let i = 1; i <= 50; i++) {
                this.leakMessage = `短信轰炸中，第${i}次`;

                try {
                    const response = await sendSafe2({
                        "phone": this.phone,
                        "captcha": this.captcha
                    });

                    this.leakMessage = "第" + i + "次尝试，" + response.data;

                    // 等待100ms再发送下一条,避免请求过于频繁
                    await new Promise(resolve => setTimeout(resolve, 100));

                } catch (error) {
                    console.error('Error fetching data:', error);
                }
            }

            this.message = '短信轰炸完成';
        },

        // 单次使用图形验证码登录
        SingleSendSmsCode() {
            if (!this.phone) {
                this.leakMessage = '手机号不能为空';
                return;
            }

            // 强化前端校验（使用与后端相同的正则）
            const phoneRegex = /^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\d{8}$/;

            if (!phoneRegex.test(this.phone)) {
                this.leakMessage = '手机号格式错误'
                return;
            }

            sendSafe2({
                "phone": this.phone,
                "captcha": this.captcha
            }).then(response => {
                this.leakMessage = response.data;
                // 登录成功后刷新验证码
                this.refreshCaptcha();
            }).catch(error => {
                console.error('Error fetching data:', error);
            })
        },

        // 暴力破解短信验证码
        async BruteVerifySmsCode() {
            if (!this.phone) {
                this.leakMessage = '手机号不能为空';
                return;
            }

            // 强化前端校验（使用与后端相同的正则）
            const phoneRegex = /^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\d{8}$/;

            if (!phoneRegex.test(this.phone)) {
                this.leakMessage = '手机号格式错误'
                return;
            }

            this.bruteForceMessage = '开始暴力破解验证码...';

            for (let i = 0; i <= 9999; i++) {
                // 将数字格式化为4位字符串,不足4位前面补0
                const code = i.toString().padStart(4, '0');

                this.bruteForceMessage = `正在尝试验证码: ${code}`;

                try {
                    const response = await verifyVuln1({
                        "phone": this.phone,
                        "code": code
                    });

                    // 如果验证成功
                    if (response.code == 0) {
                        this.bruteForceMessage = `验证码破解成功，正确验证码为: ${code}`;
                        return;
                    }

                    // 每100次请求暂停100ms,避免请求过于频繁
                    // if (i % 100 === 0) {
                    //     await new Promise(resolve => setTimeout(resolve, 100));
                    // }

                } catch (error) {
                    console.error('验证失败:', error);
                    continue;
                }
            }

            this.bruteForceMessage = '验证码破解失败，已尝试所有可能的组合';
        },

        // 防暴力破解短信验证码
        async BruteVerifySafeSmsCode() {
            if (!this.phone) {
                this.leakMessage = '手机号不能为空';
                return;
            }

            // 强化前端校验（使用与后端相同的正则）
            const phoneRegex = /^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\d{8}$/;

            if (!phoneRegex.test(this.phone)) {
                this.leakMessage = '手机号格式错误'
                return;
            }

            this.bruteForceMessage = '开始暴力破解验证码...';

            for (let i = 0; i <= 9999; i++) {
                // 将数字格式化为4位字符串,不足4位前面补0
                const code = i.toString().padStart(4, '0');

                this.bruteForceMessage = `正在尝试验证码: ${code}`;

                try {
                    const response = await verifySafe1({
                        "phone": this.phone,
                        "code": code
                    });

                    // 如果验证成功
                    if (response.code == 0) {
                        this.bruteForceMessage = `验证码破解成功，正确验证码为: ${code}`;
                        return;
                    }

                    if (response.data.includes('错误次数过多')) {
                        this.bruteForceMessage = '错误次数过多，暴力破解终止，请重新获取短信验证码';
                        return;
                    }

                    // 增加延迟，方便看效果
                    await new Promise(resolve => setTimeout(resolve, 500));

                } catch (error) {
                    console.error('验证失败:', error);
                    continue;
                }
            }

            this.bruteForceMessage = '验证码破解失败，已尝试所有可能的组合';
        },


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
</style>