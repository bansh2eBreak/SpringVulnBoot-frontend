<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">身份认证漏洞 -- 2FA-Based authentication</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            虽然2fa双因素身份认证可以提高账户的安全性，但是如果实现不当，也可能导致漏洞。例如仅仅是前端页面需要验证2fa，其实后端接口并不强制校验2fa，导致可以绕过2fa登录；还有一种场景是通过其他漏洞可以越权拿到其他用户的2fa串，从而非法绑定其他账号的2fa进行非法登录。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            2fa相关漏洞会导致系统的身份认证的安全性大大降低，可能导致用户账户遭受未经授权的访问和信息泄露，进而导致个人隐私泄露、财产损失等严重后果。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】后端必须严格校验2FA
                            后端需要对每一次前端提交的2FA进行严格的校验，确保2FA的安全性；
                            <br />
                            【必须】确保2FA共享密钥的安全性
                            防止2FA共享密钥泄露，确保2FA共享密钥的安全性；
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 暴力破解（password-based
                            authentication） <div>
                                <el-button type="danger" round size="mini"
                                    @click="fetchDataAndFillTable1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">
/**
 * 用户登录，存在暴力破解漏洞
 *
 * @param user
 * @return
 */
@PostMapping("/vuln1")
public Result passwordLoginVuln(@RequestBody User user) {
    User u = userService.passwordLogin(user);

    if (u != null) {
        // 登录成功
        log.info("{} 登录成功！", u.getUsername());
        return Result.success(u.getUsername() + " 登录成功！");
    } else {
        // 登录失败
        log.error("登录失败，账号密码是：{},{}", user.getUsername(), user.getPassword());
        return Result.error("登录失败，账号或密码错误！");
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 单IP限制暴力破解 <el-button
                                type="success" round size="mini"
                                @click="fetchDataAndFillTable2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">    /**
     * 防止暴力破解的用户登录
     */
    @PostMapping("/sec")
    public Result passwordLoginSec(@RequestBody User user, HttpServletRequest request) {
        //1. 获取用户登录ip
        String ip = request.getRemoteAddr();

        //2. 判断最近5分钟内登录失败次数是否超过5次
        if (userLoginLogService.countUserLoginLogByIp(ip) >= 5) {
            log.error("登录失败次数过多，账号：{}", user.getUsername());
            return Result.success("登录失败次数过多，请稍后再试！");
        }

        //3. 登录
        User u = userService.passwordLogin(user);

        if (u != null) {
            // 登录成功，清除登录失败记录
            userLoginLogService.deleteUserLoginLogByIp(ip);
            log.info("{} 登录成功！", u.getUsername());
            return Result.success(u.getUsername() + " 登录成功！");
        } else {
            // 登录失败，记录登录失败日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now());
            log.error("登录失败，账号密码是：{},{}", user.getUsername(), user.getPassword());
            return Result.success("登录失败，账号或密码错误！");
        }
    }
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 -
                            绕过单IP限制暴力破解<el-button type="danger" round size="mini"
                                @click="fetchDataAndFillTable3">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">/**
 * 防止暴力破解的用户登录，可以伪造IP绕过
 */
@PostMapping("/vuln2")
public Result passwordLoginVuln2(@RequestBody User user, HttpServletRequest request) {
    //1. 获取用户登录ip
    String ip = (request.getHeader("X-Forwarded-For") != null) ? request.getHeader("X-Forwarded-For") : request.getRemoteAddr();

    //2. 判断最近5分钟内登录失败次数是否超过5次
    if (userLoginLogService.countUserLoginLogByIp(ip) >= 5) {
        log.error("登录失败次数过多，账号：{}", user.getUsername());
        return Result.success("登录失败次数过多，请稍后再试！");
    }

    //3. 登录
    User u = userService.passwordLogin(user);

    if (u != null) {
        // 登录成功，清除登录失败记录
        userLoginLogService.deleteUserLoginLogByIp(ip);
        log.info("{} 登录成功！", u.getUsername());
        return Result.success(u.getUsername() + " 登录成功！");
    } else {
        // 登录失败，记录登录失败日志
        userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now());
        log.error("登录失败，账号密码是：{},{}", user.getUsername(), user.getPassword());
        return Result.success("登录失败，账号或密码错误！");
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 -
                            暴力破解（HTTP Basic authentication）<el-button type="danger" round size="mini"
                                @click="fetchDataAndFillTable4">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">
// 前端代码
for (let i = 0; i &lt; passwords.length; i++) {
    const password = passwords[i];
    // 延迟 500 毫秒
    await new Promise(resolve => setTimeout(resolve, 100));
    try {
        const response = await httpBasicLogin({
            token: 'Basic ' + btoa(`${this.username1}:${password}`)
        }).then(response => {
            // this.resp_text1.push(response.data);
            this.resp_text1 = response.data;
        }).catch(error => {
            console.error('Error fetching data:', error);
        });
    } catch (error) {
        console.error('尝试登录失败:', error);
    }
}

// 后端代码
@PostMapping("/httpBasicLogin")
public Result httpBasicLogin(HttpServletRequest request, HttpServletResponse response) {
    String USERNAME = "zhangsan"; // 硬编码用户名
    String PASSWORD = "123"; // 硬编码密码

    // 处理HTTP Basic Auth登录
    String token = request.getHeader("token");
    if (token == null || !token.startsWith("Basic ")) {
        log.info("HTTP Basic Auth登录，token缺失或者token格式错误");
        return Result.success("HTTP Basic Auth登录，token缺失或者token格式错误");
    }

    String[] credentials = Security.decodeBasicAuth(token);
    if (credentials == null || credentials.length != 2) {
        return Result.success("HTTP Basic Auth登录，token解析失败");
    }

    String username = credentials[0];
    String password = credentials[1];

    if (!USERNAME.equals(username) || !PASSWORD.equals(password)) {
        log.info("HTTP Basic Auth登录，账号密码错误，token：{}" , token);
        return Result.success("HTTP Basic Auth登录失败，账号：" + username + "，密码：" + password);
    }

    log.info("HTTP Basic Auth登录，放行，token：{}" , token);
    return Result.success("HTTP Basic Auth登录成功，账号：" + username + "，密码：" + password);
}</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 打开嵌套表格的对话框1 -->
        <el-dialog title="用户登录" :visible.sync="dialogFormVisible1" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="账号">
                    <el-input v-model="username1"></el-input>
                </el-form-item>
                <el-form-item label="密码">
                    <el-input v-model="password1"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" @click="onSubmit11">暴力破解</el-button>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit12">正常登录</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框2 -->
        <el-dialog title="用户登录" :visible.sync="dialogFormVisible2" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="账号">
                    <el-input v-model="username1"></el-input>
                </el-form-item>
                <el-form-item label="密码">
                    <el-input v-model="password1"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" @click="onSubmit21">暴力破解</el-button>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit22">正常登录</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框3 -->
        <el-dialog title="用户登录" :visible.sync="dialogFormVisible3" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="账号">
                    <el-input v-model="username1"></el-input>
                </el-form-item>
                <el-form-item label="密码">
                    <el-input v-model="password1"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" @click="onSubmit31">暴力破解</el-button>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit32">正常登录</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>

        <!-- 打开嵌套表格的对话框4 -->
        <el-dialog title="用户登录" :visible.sync="dialogFormVisible4" class="center-dialog">
            <el-form :inline="true" class="demo-form-inline">
                <el-form-item label="账号">
                    <el-input v-model="username1"></el-input>
                </el-form-item>
                <el-form-item label="密码">
                    <el-input v-model="password1"></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button type="danger" @click="onSubmit41">暴力破解</el-button>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="onSubmit42">正常登录</el-button>
                </el-form-item>
            </el-form>
            <div>
                <template>
                    <div v-html="resp_text1"></div>
                </template>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import { vuln1, vuln2, sec, httpBasicLogin, captcha, sec2, vuln3 } from '@/api/authentication';

export default {
    data() {
        return {
            activeName: 'first',
            dialogFormVisible1: false,
            dialogFormVisible2: false,
            dialogFormVisible3: false,
            dialogFormVisible4: false,
            username1: 'zhangsan',
            password1: '123',
            captcha: '',
            resp_text1: '',
            captchaImageUrl: ''
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
        fetchDataAndFillTable1() {
            this.dialogFormVisible1 = true; // 显示对话框
            this.resp_text1 = '';
        },
        fetchDataAndFillTable2() {
            this.dialogFormVisible2 = true; // 显示对话框
            this.resp_text1 = '';
        },
        fetchDataAndFillTable3() {
            this.dialogFormVisible3 = true; // 显示对话框
            this.resp_text1 = '';
        },
        fetchDataAndFillTable4() {
            this.dialogFormVisible4 = true; // 显示对话框
            this.resp_text1 = '';
        },
        async onSubmit11() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }

            // 假设我们有一个密码列表
            const passwords = [
                "password1", "password2", "password3", "password4", "password5",
                "password6", "password7", "password8", "password9", "password10", "123"
            ];

            // 使用 for 循环遍历密码列表
            for (let i = 0; i < passwords.length; i++) {
                const password = passwords[i];
                // 延迟 500 毫秒
                await new Promise(resolve => setTimeout(resolve, 100));
                try {
                    const response = await vuln1({
                        "username": this.username1,
                        "password": password
                    }).then(response => {
                        // this.resp_text1.push(response.data);
                        this.resp_text1 = response.data;
                    }).catch(error => {
                        console.error('Error fetching data:', error);
                    });
                } catch (error) {
                    console.error('尝试登录失败:', error);
                }
            }
        },
        onSubmit12() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }
            vuln1({
                "username": this.username1,
                "password": this.password1
            }).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = response.data;
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },
        async onSubmit21() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }

            // 假设我们有一个密码列表
            const passwords = [
                "password1", "password2", "password3", "password4", "password5",
                "password6", "password7", "password8", "password9", "password10", "123"
            ];

            // 使用 for 循环遍历密码列表
            for (let i = 0; i < passwords.length; i++) {
                const password = passwords[i];
                // 延迟 500 毫秒
                await new Promise(resolve => setTimeout(resolve, 100));
                try {
                    const response = await sec({
                        "username": this.username1,
                        "password": password
                    }).then(response => {
                        // this.resp_text1.push(response.data);
                        this.resp_text1 = response.data;
                    }).catch(error => {
                        console.error('Error fetching data:', error);
                    });
                } catch (error) {
                    console.error('尝试登录失败:', error);
                }
            }
        },
        onSubmit22() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }
            sec({
                "username": this.username1,
                "password": this.password1
            }).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = response.data;
                console.log(response.data);
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },
        async onSubmit31() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }

            // 假设我们有一个密码列表
            const passwords = [
                "password1", "password2", "password3", "password4", "password5",
                "password6", "password7", "password8", "password9", "password10", "123"
            ];

            // 生成随机 IP 地址的函数
            function generateRandomIP() {
                const part1 = Math.floor(Math.random() * 255);
                const part2 = Math.floor(Math.random() * 255);
                const part3 = Math.floor(Math.random() * 255);
                const part4 = Math.floor(Math.random() * 255);
                return `${part1}.${part2}.${part3}.${part4}`;
            }

            // 使用 for 循环遍历密码列表
            for (let i = 0; i < passwords.length; i++) {
                const password = passwords[i];
                // 延迟 500 毫秒
                await new Promise(resolve => setTimeout(resolve, 100));
                try {
                    const randomIP = generateRandomIP();
                    console.log("随机 IP 地址:", randomIP);
                    const response = await vuln2({
                        "username": this.username1,
                        "password": password
                    }, {
                        "X-Forwarded-For": randomIP
                    }).then(response => {
                        // this.resp_text1.push(response.data);
                        this.resp_text1 = response.data;
                    }).catch(error => {
                        console.error('Error fetching data:', error);
                    });
                } catch (error) {
                    console.error('尝试登录失败:', error);
                }
            }
        },
        onSubmit32() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }
            vuln2({
                "username": this.username1,
                "password": this.password1
            }).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
        },
        async onSubmit41() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }

            // 假设我们有一个密码列表
            const passwords = [
                "password1", "password2", "password3", "password4", "password5",
                "password6", "password7", "password8", "password9", "password10", "123"
            ];

            // 使用 for 循环遍历密码列表
            for (let i = 0; i < passwords.length; i++) {
                const password = passwords[i];
                // 延迟 500 毫秒
                await new Promise(resolve => setTimeout(resolve, 100));
                try {
                    const response = await httpBasicLogin({
                        token: 'Basic ' + btoa(`${this.username1}:${password}`)
                    }).then(response => {
                        // this.resp_text1.push(response.data);
                        this.resp_text1 = response.data;
                    }).catch(error => {
                        console.error('Error fetching data:', error);
                    });
                } catch (error) {
                    console.error('尝试登录失败:', error);
                }
            }
        },
        onSubmit42() {
            if (!this.username1 || !this.password1) {
                // 如果提交内容为空，显示错误提示
                this.$message.error('账号密码不能为空');
                return;
            }
            httpBasicLogin({
                token: 'Basic ' + btoa(`${this.username1}:${this.password1}`)
            }).then(response => {
                // this.resp_text1.push(response.data);
                this.resp_text1 = response.data;
            }).catch(error => {
                console.error('Error fetching data:', error);
            });
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