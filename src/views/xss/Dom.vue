<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">XSS跨站脚本攻击 -- DOM型</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>DOM型XSS (Document Object Model XSS)</strong> 是一种特殊的XSS攻击类型，其特点是恶意代码不经过服务器处理，直接在客户端（浏览器）的JavaScript中执行，通过操作DOM元素来触发攻击。<br/><br/>
                            
                            <span style="color: red;">主要特征：</span><br/>
                            • 攻击载荷不经过服务器处理<br/>
                            • 直接在客户端JavaScript中执行<br/>
                            • 通过操作DOM元素触发攻击<br/>
                            • 常见触发点：location.hash、URL参数、document.referrer等<br/><br/>
                            
                            <span style="color: red;">典型场景：</span><br/>
                            • 直接使用location.hash操作DOM<br/>
                            • 使用document.referrer显示来源页面<br/>
                            • 通过URL参数动态生成页面内容
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            1. <strong>窃取敏感信息</strong>：攻击者可以窃取用户的Cookie、会话信息、个人数据等<br/>
                            2. <strong>会话劫持</strong>：通过窃取的会话信息冒充用户身份<br/>
                            3. <strong>恶意重定向</strong>：将用户重定向到钓鱼网站或恶意网站<br/>
                            4. <strong>键盘记录</strong>：记录用户的键盘输入，获取密码等敏感信息<br/>
                            5. <strong>浏览器指纹收集</strong>：收集用户的浏览器特征信息<br/>
                            6. <strong>社会工程学攻击</strong>：通过伪造页面内容进行诈骗
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】避免使用危险的DOM操作方法
                            禁止使用innerHTML、outerHTML、document.write()等危险方法直接插入用户输入内容。应使用textContent、innerText等安全方法。<br /><br />

                            【必须】对客户端输入源进行验证和编码
                            对所有来自客户端的数据进行严格的验证和HTML实体编码，包括URL参数、hash片段、referrer等。<br /><br />

                            【建议】使用安全的框架API
                            使用Vue.js的默认文本插值{{ }}而不是v-html指令，使用React的JSX而不是dangerouslySetInnerHTML。<br /><br />

                            【建议】实施内容安全策略(CSP)
                            设置严格的Content Security Policy，限制脚本执行来源，防止恶意脚本注入。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <b>相关技术文档和参考资源：</b><br/><br/>
                            <b>官方文档：</b>
                            <ul>
                                <li><a href="https://owasp.org/www-community/attacks/DOM_Based_XSS" target="_blank" style="text-decoration: underline;">OWASP DOM型XSS官方文档</a></li>
                                <li><a href="https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model" target="_blank" style="text-decoration: underline;">MDN DOM API文档</a></li>
                            </ul>
                            <br/>
                            <b>安全最佳实践：</b>
                            <ul>
                                <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">OWASP DOM型XSS防护检查清单</a></li>
                                <li><a href="https://content-security-policy.com/" target="_blank" style="text-decoration: underline;">内容安全策略(CSP)指南</a></li>
                            </ul>
                            <br/>
                            <b>工具和库：</b>
                            <ul>
                                <li><a href="https://github.com/cure53/DOMPurify" target="_blank" style="text-decoration: underline;">DOMPurify - DOM清理库</a></li>
                                <li><a href="https://github.com/OWASP/CheatSheetSeries" target="_blank" style="text-decoration: underline;">OWASP安全配置检查清单</a></li>
                            </ul>
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 使用URL参数 <div>
                                <el-button type="danger" round size="mini" @click="showAttackUrls"
                                    >查看攻击URL示例</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="javascript">// 危险示例：使用URL参数
mounted() {
    this.loadUrlParamContent();
    this.updateBaseUrl();
},

loadUrlParamContent() {
    const urlParams = new URLSearchParams(window.location.search);
    let payload = urlParams.get('payload') || '';

    console.log("hi payload: " + payload);
    
    // 如果search为空，尝试从hash后面获取参数
    if (!payload) {
        const fullUrl = window.location.href;
        const hashIndex = fullUrl.indexOf('#');
        if (hashIndex !== -1) {
            const afterHash = fullUrl.substring(hashIndex + 1);
            const queryIndex = afterHash.indexOf('?');
            if (queryIndex !== -1) {
                const searchParams = afterHash.substring(queryIndex);
                const params = new URLSearchParams(searchParams);
                payload = params.get('payload') || '';
            }
        }
    }
    
    // 更新当前URL参数显示
    this.currentUrlParams = payload || '无参数';
    
    // 安全内容（Vue插值）
    this.safeContent = payload;
    
    // 危险操作：直接修改DOM
    this.$nextTick(() => {
        const domElement = document.getElementById('vulnerable-dom');
        if (domElement && payload) {
            domElement.innerHTML = payload; // 直接插入HTML，可能执行脚本
        }
    });
}

// 攻击URL示例：
http://127.0.0.1:9528/#/xss/dom?payload=&lt;img src=x onerror=alert('XSS')&gt;
http://127.0.0.1:9528/#/xss/dom?payload=&lt;svg onload=alert('XSS')&gt;&lt;/svg&gt;
http://127.0.0.1:9528/#/xss/dom?payload=&lt;img src=x onmouseover=alert('XSS')&gt;
http://127.0.0.1:9528/#/xss/dom?payload=&lt;iframe src=javascript:alert('XSS')&gt;&lt;/iframe&gt;
</code></pre>
                    
                    <!-- 真实的DOM型XSS演示区域 -->
                    <div class="xss-demo-area">
                        <el-card class="box-card">
                            <div slot="header" class="clearfix">
                                <span>🔴 漏洞代码演示</span>
                            </div>
                            
                            <div class="demo-section">
                                <p>从URL参数获取payload并直接修改DOM：</p>
                                <div id="vulnerable-dom" class="vulnerable-area">
                                    <!-- 这里会被JavaScript直接修改DOM -->
                                    <p>等待URL参数中的payload...</p>
                                </div>
                                <div class="url-info">
                                    <strong>当前URL参数：</strong>
                                    <code>{{ currentUrlParams }}</code>
                                </div>
                            </div>
                        </el-card>
                    </div>
                </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 使用Vue默认插值</el-row>
                        <pre v-highlightjs><code class="javascript">// 安全代码：使用Vue默认插值
mounted() {
    this.loadUrlParamContent();
    this.updateBaseUrl();
},

loadUrlParamContent() {
    const urlParams = new URLSearchParams(window.location.search);
    let payload = urlParams.get('payload') || '';

    console.log("hi payload: " + payload);
    
    // 如果search为空，尝试从hash后面获取参数
    if (!payload) {
        const fullUrl = window.location.href;
        const hashIndex = fullUrl.indexOf('#');
        if (hashIndex !== -1) {
            const afterHash = fullUrl.substring(hashIndex + 1);
            const queryIndex = afterHash.indexOf('?');
            if (queryIndex !== -1) {
                const searchParams = afterHash.substring(queryIndex);
                const params = new URLSearchParams(searchParams);
                payload = params.get('payload') || '';
            }
        }
    }
    
    // 更新当前URL参数显示
    this.currentUrlParams = payload || '无参数';
    
    // 安全内容（Vue插值）
    this.safeContent = payload;
}

// 模板中使用安全插值
&lt;div&gt;{{ safeContent }}&lt;/div&gt;
</code></pre>
                    
                    <!-- 安全代码演示区域 -->
                    <div class="xss-demo-area">
                        <el-card class="box-card">
                            <div slot="header" class="clearfix">
                                <span>🟢 安全代码演示</span>
                            </div>
                            
                            <div class="demo-section">
                                <p>使用Vue默认插值，自动转义：</p>
                                <div class="safe-area">
                                    <p>安全显示：{{ safeContent }}</p>
                                </div>
                                <div class="url-info">
                                    <strong>当前URL参数：</strong>
                                    <code>{{ currentUrlParams }}</code>
                                </div>
                            </div>
                        </el-card>
                    </div>
                </div>
                </el-col>
            </el-row>
        </div>
        
        <!-- 攻击URL对话框 -->
        <el-dialog title="攻击URL示例" :visible.sync="attackUrlDialogVisible" class="center-dialog">
            <div class="attack-urls">
                <h4>点击"去测试"按钮在新标签页中打开对应的攻击URL：</h4>
                <div class="url-item">
                    <strong>onerror事件：</strong>
                    <el-input 
                        :value="baseUrl + '?payload=<img src=x onerror=alert(\'XSS\')>'" 
                        readonly>
                        <el-button slot="append" type="danger" @click="openAttackUrl(baseUrl + '?payload=<img src=x onerror=alert(\'XSS\')>')">
                            去测试
                        </el-button>
                    </el-input>
                </div>
                <div class="url-item">
                    <strong>SVG onload事件：</strong>
                    <el-input 
                        :value="baseUrl + '?payload=<svg onload=alert(\'XSS\')></svg>'" 
                        readonly>
                        <el-button slot="append" type="danger" @click="openAttackUrl(baseUrl + '?payload=<svg onload=alert(\'XSS\')></svg>')">
                            去测试
                        </el-button>
                    </el-input>
                </div>
                <div class="url-item">
                    <strong>onmouseover事件：</strong>
                    <el-input 
                        :value="baseUrl + '?payload=<img src=x onmouseover=alert(\'XSS\')>'"
                        readonly>
                        <el-button slot="append" type="danger" @click="openAttackUrl(baseUrl + '?payload=<img src=x onmouseover=alert(\'XSS\')>')">
                            去测试
                        </el-button>
                    </el-input>
                </div>
                <div class="url-item">
                    <strong>iframe javascript协议：</strong>
                    <el-input 
                        :value="baseUrl + '?payload=<iframe src=javascript:alert(\'XSS\')></iframe>'" 
                        readonly>
                        <el-button slot="append" type="danger" @click="openAttackUrl(baseUrl + '?payload=<iframe src=javascript:alert(\'XSS\')></iframe>')">
                            去测试
                        </el-button>
                    </el-input>
                </div>
            </div>
        </el-dialog>
    </div>
</template>

<script>
export default {
    name: 'DomXss',
    data() {
        return {
            activeName: 'first',
            attackUrlDialogVisible: false,
            safeContent: '',
            currentUrlParams: '',
            baseUrl: ''
        }
    },
    mounted() {
        this.loadUrlParamContent();
        this.updateBaseUrl();
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        
        updateBaseUrl() {
            // 获取当前页面URL（不包含参数）
            this.baseUrl = window.location.origin + window.location.pathname + '#/xss/dom';
        },
        
        loadUrlParamContent() {
            const urlParams = new URLSearchParams(window.location.search);
            let payload = urlParams.get('payload') || '';

            console.log("hi payload: " + payload);
            
            // 如果search为空，尝试从hash后面获取参数
            if (!payload) {
                const fullUrl = window.location.href;
                const hashIndex = fullUrl.indexOf('#');
                if (hashIndex !== -1) {
                    const afterHash = fullUrl.substring(hashIndex + 1);
                    const queryIndex = afterHash.indexOf('?');
                    if (queryIndex !== -1) {
                        const searchParams = afterHash.substring(queryIndex);
                        const params = new URLSearchParams(searchParams);
                        payload = params.get('payload') || '';
                    }
                }
            }
            
            // 更新当前URL参数显示
            this.currentUrlParams = payload || '无参数';
            
            // 安全内容（Vue插值）
            this.safeContent = payload;
            
            // 危险操作：直接修改DOM
            this.$nextTick(() => {
                const domElement = document.getElementById('vulnerable-dom');
                if (domElement && payload) {
                    domElement.innerHTML = payload; // 直接插入HTML，可能执行脚本
                }
            });
        },
        
        showAttackUrls() {
            this.attackUrlDialogVisible = true;
        },
        
        // 在新标签页打开攻击URL
        openAttackUrl(url) {
            window.open(url, '_blank');
            this.$message.success('已在新标签页中打开攻击URL');
        },
        
        copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                this.$message.success('URL已复制到剪贴板');
            }).catch(() => {
                // 降级方案
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                this.$message.success('URL已复制到剪贴板');
            });
        },
        

    }
}
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

.xss-demo-area {
    margin: 20px;
    border-top: 1px solid #ccc;
    padding-top: 20px;
}

.demo-section {
    padding: 15px;
    border: 1px solid #e4e7ed;
    border-radius: 4px;
    margin-bottom: 15px;
}

.vulnerable-area {
    background-color: #fef0f0;
    border: 2px solid #f56c6c;
    border-radius: 4px;
    padding: 15px;
    min-height: 80px;
    margin: 10px 0;
}

.safe-area {
    background-color: #f0f9ff;
    border: 2px solid #67c23a;
    border-radius: 4px;
    padding: 15px;
    min-height: 80px;
    margin: 10px 0;
}

.url-info {
    background-color: #f5f7fa;
    padding: 8px;
    border-radius: 4px;
    font-size: 12px;
    margin-top: 10px;
}

.attack-urls {
    text-align: left;
}

.url-item {
    margin-bottom: 15px;
}

.url-item strong {
    display: block;
    margin-bottom: 5px;
    color: #409EFF;
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

code {
    background-color: #f5f5f5;
    padding: 2px 4px;
    border-radius: 3px;
    font-family: monospace;
    color: #E6A23C;
}
</style> 