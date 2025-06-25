<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">任意URL跳转</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            URL跳转漏洞是一种Web应用程序安全漏洞，攻击者利用该漏洞构造恶意URL，诱使用户点击，从而将用户重定向到恶意网站，用以进行钓鱼攻击、恶意软件传播等。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            URL跳转漏洞的危害在于攻击者可以利用漏洞构造恶意URL，诱导用户点击后将其重定向至恶意网站，可能导致用户信息泄露、恶意软件传播、钓鱼攻击等安全风险。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】避免不可信域名的302跳转
                            如果对外部传入域名进行302跳转，必须设置可信域名列表并对传入域名进行校验。
                            <br />
                            <br />
                            为避免校验被绕过，应避免直接对URL进行字符串匹配。应通过通过URL解析函数进行解析，获取host或者domain后和白名单进行比较。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <!-- 给超链接配置下划线 -->
                            <a href="https://xz.aliyun.com/t/5189?time__1311=n4%2BxnieWqCqYqqGwx05DK3hxIrxjh0L2qY5uQx"
                                target="_blank" style="text-decoration: underline;">《浅析渗透实战中url跳转漏洞》</a>
                            <br />
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 直接返回未经校验的url给前端<div>
                                <el-button type="danger" round size="mini" @click="handleButtonClick1">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// 后端代码
@RestController
@Slf4j
@RequestMapping("/openUrl/")
public class RedirectController {
    @GetMapping("/redirect")
    public String redirect(String url) {
        log.info("重定向到: " + url);
        return url;
    }
}

// 前端代码
handleButtonClick1() {
    axios.get("http://127.0.0.1:8080/openUrl/redirect?url=https://www.baidu.com").then(response => {
        window.location.href = response.data;
    });
},
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 白名单校验1（可绕过） <el-button
                                type="danger" round size="mini" @click="handleButtonClick2">去测试</el-button></el-row>
                        <pre v-highlightjs><code class="java">// 后端校验逻辑（不严谨）：url.contains("google.com")
// 绕过Poc：http://127.0.0.1:8080/openUrl/secRedirect1?url=https://www.baidu.com/s?wd=google.com
@GetMapping("/secRedirect1")
public void secRedirect1(String url, HttpServletResponse response) throws IOException {
    log.info("重定向到: " + url);
    if (url.contains("google.com")) {
        response.sendRedirect(url);
    } else {
        // 处理 URL 为空的情况，例如跳转到默认页面
        response.sendRedirect("http://localhost:9528/?#/dashboard");
    }
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - response.sendRedirect方式
                            <div><el-button type="danger" round size="mini" @click="handleButtonClick3">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// 后端代码
@GetMapping("/redirect2")
public void redirect2(String url, HttpServletResponse response) throws IOException {
    log.info("重定向到: " + url);
    if (url != null && !url.isEmpty() && (url.startsWith("http") || url.startsWith("https"))) {
        response.sendRedirect(url);
    } else {
        // 处理 URL 为空的情况，例如跳转到默认页面
        response.sendRedirect("http://localhost/?#/dashboard");
    }
}

// 前端不需要特殊处理</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 白名单校验2
                            <div><el-button type="success" round size="mini" @click="handleButtonClick4">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// 后端校验逻辑（严谨）："https://www.google.com".equals(url)
@GetMapping("/secRedirect")
public void secRedirect(String url, HttpServletResponse response) throws IOException {
    log.info("重定向到: " + url);
    if ("https://www.google.com".equals(url)) {
        response.sendRedirect(url);
    } else {
        // 处理 URL 为空的情况，例如跳转到默认页面
        response.sendRedirect("http://localhost:9528/?#/dashboard");
    }
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
    </div>
</template>

<script>
import axios from 'axios';
import { redirect, redirect2 } from '@/api/openUrl';

export default {
    data() {
        return {
            activeName: 'first'
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        handleButtonClick1() {
            // 向http://127.0.0.1:8080/openUrl/redirect?url=https://www.baidu.com发起get请求，并获取返回结果，然后重定向到返回结果对应的url
            axios.get("http://127.0.0.1:8080/openUrl/redirect?url=https://www.baidu.com").then(response => {
                // window.location.href = response.data;
                window.open(response.data, "_blank");
            });
        },
        handleButtonClick2() {
            window.open("http://127.0.0.1:8080/openUrl/secRedirect1?url=https://www.baidu.com/s?wd=google.com", "_blank");
        },
        handleButtonClick3() {
            window.open("http://127.0.0.1:8080/openUrl/redirect2?url=https://www.baidu.com", "_blank");
        },
        handleButtonClick4() {
            window.open("http://127.0.0.1:8080/openUrl/secRedirect2?url=https://www.baidu.com?k=google.com", "_blank");
        },
        fetchDataAndFillTable1() {
            redirect({ url: 'https://www.baidu.com' })
                .then(response => {
                    console.log(response.data);
                    window.open(response.data, "_blank");
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable3() {
            redirect2({ url: 'https://juejin.cn/' })
                .then(response => {
                    // 浏览器跨域问题导致浏览器302跳转会遇到CORS错误
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        }
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
</style>