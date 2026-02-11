<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- ORDER BY 注入</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            <strong>ORDER BY 注入</strong>是一种特殊的 SQL 注入类型，发生在<span style="color: red;">排序参数可控</span>的场景中。
                            它最大的特点是<span style="color: red;">无法使用预编译</span>防御，因为 ORDER BY 子句不支持参数化查询，只能通过白名单等方式防护。
                            <br /><br />
                            <strong>核心特点：</strong><br />
                            1. <strong>无法使用预编译</strong>：ORDER BY 子句不支持参数化（PreparedStatement），必须使用字符串拼接<br />
                            2. <strong>容易被忽视</strong>：开发者往往只关注 WHERE 条件的注入，忽略排序参数<br />
                            3. <strong>常见场景</strong>：列表页面的排序功能（按价格、时间、名称排序等）<br />
                            4. <strong>利用方式多样</strong>：可用于盲注、条件注入等
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            虽然 ORDER BY 注入看起来危害较小，但攻击者仍可以利用它进行多种攻击：<br /><br />
                            <strong>1. 布尔盲注</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 利用 CASE WHEN 或 IF() 判断条件真假<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 通过观察排序结果变化推断数据<br /><br />
                            <strong>2. 时间盲注</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 利用 SLEEP() 函数进行延时注入<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 逐字符猜解敏感数据<br /><br />
                            <strong>3. 条件注入</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 注入 AND 条件改变查询结果<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 可能导致信息泄露<br /><br />
                            <strong>4. 数据库信息探测</strong><br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 获取数据库版本、表结构等信息<br />
                            &nbsp;&nbsp;&nbsp;&nbsp;- 为后续攻击做准备
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            <strong>【必须】白名单校验（推荐）</strong><br />
                            只允许预定义的字段名，拒绝其他所有输入。<br /><br />

                            <strong>【必须】枚举类型限制</strong><br />
                            使用枚举定义可选的排序字段，编译期类型安全。<br /><br />

                            <strong>【禁止】预编译 PreparedStatement</strong><br />
                            ORDER BY 子句<span style="color: red;">不支持</span>预编译参数，使用 <code>#{}</code> 会报错！<br />
                            • ❌ 错误：<code>ORDER BY #{orderBy}</code> → 语法错误<br />
                            • ⚠️ 危险：<code>ORDER BY ${orderBy}</code> → 存在注入风险<br /><br />

                            <strong>【建议】默认排序</strong><br />
                            如果参数校验失败，使用默认排序字段（如 id），不要抛出异常。<br /><br />

                            <strong>【建议】日志监控</strong><br />
                            记录所有排序参数的访问日志，及时发现异常请求。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://mp.weixin.qq.com/s/XFIWgvJRyhZsGGLhTYMjnQ" target="_blank"
                                style="text-decoration: underline;">《写点不一样的 ORDER BY 参数注入》</a> - 深入学习 ORDER BY 注入原理<br />
                            <a href="https://www.sqlinjection.net/advanced/order-by-injection/" target="_blank"
                                style="text-decoration: underline;">《Advanced SQL Injection - ORDER BY》</a> - 高级 ORDER BY 注入技巧
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <!-- 漏洞代码 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            漏洞代码 - MyBatis ${}
                            <div>
                                <el-button type="danger" round size="mini" @click="openAttackDialog">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// Controller 层
@GetMapping("/vuln")
public Result orderByVuln(
        @RequestParam(defaultValue = "id") String orderBy,
        @RequestParam(defaultValue = "1") Integer page,
        @RequestParam(defaultValue = "5") Integer pageSize) {
    
    // ⚠️ 直接传递给 Service，没有任何校验
    return Result.success(userService.pageOrderByVuln(orderBy, page, pageSize));
}

// MyBatis Mapper 层
@Select("select * from user order by ${orderBy} limit #{start}, #{pageSize}")
List&lt;User&gt; pageOrderBy(@Param("orderBy") String orderBy, 
                       @Param("start") int start, 
                       @Param("pageSize") int pageSize);

// ⚠️ 使用 ${} 直接拼接，存在注入风险！

// 攻击示例：
// 1. CASE WHEN 盲注
orderBy = (CASE WHEN (SELECT COUNT(*) FROM user)>0 THEN id ELSE username END)

// 2. IF() 盲注
orderBy = IF((SELECT COUNT(*) FROM user)>0, id, username)

// 3. SLEEP() 时间盲注
orderBy = IF((SELECT COUNT(*) FROM user)>0, (SELECT SLEEP(2)), id)
</code></pre>
                    </div>
                </el-col>
                
                <!-- 安全代码1：白名单 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - 白名单校验
                            <div>
                                <el-button type="success" round size="mini" @click="openSec1Dialog">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/sec1")
public Result orderBySecWhitelist(
        @RequestParam(defaultValue = "id") String orderBy,
        @RequestParam(defaultValue = "1") Integer page,
        @RequestParam(defaultValue = "5") Integer pageSize) {
    
    // ✅ 白名单校验
    Set&lt;String&gt; allowedFields = new HashSet&lt;&gt;(
        Arrays.asList("id", "username", "name")
    );
    
    if (!allowedFields.contains(orderBy.toLowerCase())) {
        return Result.error("非法的排序字段");
    }
    
    // 校验通过，执行查询
    return Result.success(userService.pageOrderByVuln(orderBy, page, pageSize));
}

// 优点：
// ✅ 简单有效，易于理解
// ✅ 完全阻止非法字段
// ✅ 性能开销极小

// 缺点：
// ⚠️ 需要维护白名单
// ⚠️ 新增字段需要更新代码
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex" style="margin-top: 20px;">
                <el-col :span="12"></el-col>
                <!-- 安全代码2：枚举 -->
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">
                            安全代码 - 枚举类型限制
                            <div>
                                <el-button type="success" round size="mini" @click="openSec2Dialog">去测试</el-button>
                            </div>
                        </el-row>
                        <pre v-highlightjs><code class="java">// 定义枚举
public enum OrderByField {
    ID("id"),
    USERNAME("username"),
    NAME("name");
    
    private final String fieldName;
    
    OrderByField(String fieldName) {
        this.fieldName = fieldName;
    }
    
    public String getFieldName() {
        return fieldName;
    }
}

// Controller 使用枚举
@GetMapping("/sec2")
public Result orderBySecEnum(
        @RequestParam(defaultValue = "ID") OrderByField orderBy,
        @RequestParam(defaultValue = "1") Integer page,
        @RequestParam(defaultValue = "5") Integer pageSize) {
    
    // ✅ Spring 自动校验枚举，非法值直接报错
    return Result.success(
        userService.pageOrderByVuln(orderBy.getFieldName(), page, pageSize)
    );
}

// 优点：
// ✅ 编译期类型安全
// ✅ 自动参数校验
// ✅ 代码更优雅

// 缺点：
// ⚠️ 需要定义枚举类
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>

        <!-- 测试对话框 -->
        <el-dialog title="ORDER BY 注入测试" :visible.sync="attackDialogVisible" width="50%" center>
            <el-form label-width="120px">
                <el-form-item label="测试类型">
                    <el-select v-model="selectedAttackType" placeholder="请选择测试类型" style="width: 100%;">
                        <el-option label="正常排序 - id" value="normalId"></el-option>
                        <el-option label="正常排序 - username" value="normalUsername"></el-option>
                        <el-option label="正常排序 - name" value="normalName"></el-option>
                        <el-option label="CASE WHEN 盲注" value="caseWhen"></el-option>
                        <el-option label="IF() 盲注" value="if"></el-option>
                        <el-option label="SLEEP() 时间盲注" value="sleep"></el-option>
                    </el-select>
                </el-form-item>
                
                <el-form-item label="orderBy 参数">
                    <el-input v-model="attackPayload" type="textarea" :rows="3" placeholder="ORDER BY 注入 Payload"></el-input>
                </el-form-item>
                
                <el-form-item label="说明">
                    <div style="color: #909399; font-size: 13px;">
                        {{ attackDescription }}
                    </div>
                </el-form-item>
                
                <el-form-item>
                    <el-button type="primary" @click="executeAttack" :loading="attackLoading">执行测试</el-button>
                    <el-button @click="resetAttackDialog">重置</el-button>
                </el-form-item>
            </el-form>
            
            <!-- 查询结果区域 -->
            <div v-if="attackResultVisible" style="margin-top: 20px; border-top: 1px solid #EBEEF5; padding-top: 20px;">
                <el-table :data="attackTableData" border style="width: 100%; margin: 0 auto;" max-height="350">
                    <el-table-column prop="id" label="ID" align="center"></el-table-column>
                    <el-table-column prop="username" label="用户名" align="center"></el-table-column>
                    <el-table-column prop="name" label="姓名" align="center"></el-table-column>
                </el-table>
            </div>
        </el-dialog>

        <!-- 白名单校验测试对话框 -->
        <el-dialog title="白名单校验测试" :visible.sync="sec1DialogVisible" width="50%" center>
            <el-form label-width="120px">
                <el-form-item label="测试类型">
                    <el-select v-model="sec1PayloadType" placeholder="请选择测试类型" style="width: 100%;">
                        <el-option label="正常排序 - id" value="sec1Normal1"></el-option>
                        <el-option label="正常排序 - username" value="sec1Normal2"></el-option>
                        <el-option label="正常排序 - name" value="sec1Normal3"></el-option>
                        <el-option label="CASE WHEN 盲注" value="sec1Attack1"></el-option>
                        <el-option label="IF() 盲注" value="sec1Attack2"></el-option>
                        <el-option label="SLEEP() 时间盲注" value="sec1Attack3"></el-option>
                    </el-select>
                </el-form-item>
                
                <el-form-item label="orderBy 参数">
                    <el-input v-model="sec1Payload" type="textarea" :rows="3" placeholder="ORDER BY 参数"></el-input>
                </el-form-item>
                
                <el-form-item label="说明">
                    <div style="color: #909399; font-size: 13px;">
                        {{ sec1Description }}
                    </div>
                </el-form-item>
                
                <el-form-item>
                    <el-button type="primary" @click="executeSec1Test" :loading="sec1Loading">执行测试</el-button>
                    <el-button @click="resetSec1Dialog">重置</el-button>
                </el-form-item>
            </el-form>
            
            <!-- 查询结果区域 -->
            <div v-if="sec1ResultVisible" style="margin-top: 20px; border-top: 1px solid #EBEEF5; padding-top: 20px;">
                <div v-if="!sec1Success" style="margin-bottom: 15px; color: #F56C6C; font-size: 13px;">
                    {{ sec1ErrorMsg }}
                </div>
                
                <el-table v-if="sec1Success" :data="sec1TableData" border style="width: 100%; margin: 0 auto;" max-height="350">
                    <el-table-column prop="id" label="ID" align="center"></el-table-column>
                    <el-table-column prop="username" label="用户名" align="center"></el-table-column>
                    <el-table-column prop="name" label="姓名" align="center"></el-table-column>
                </el-table>
            </div>
        </el-dialog>

        <!-- 枚举类型限制测试对话框 -->
        <el-dialog title="枚举类型限制测试" :visible.sync="sec2DialogVisible" width="50%" center>
            <el-form label-width="120px">
                <el-form-item label="测试类型">
                    <el-select v-model="sec2PayloadType" placeholder="请选择测试类型" style="width: 100%;">
                        <el-option label="正常排序 - ID" value="sec2Normal1"></el-option>
                        <el-option label="正常排序 - USERNAME" value="sec2Normal2"></el-option>
                        <el-option label="正常排序 - NAME" value="sec2Normal3"></el-option>
                        <el-option label="小写字段注入 - id" value="sec2Attack1"></el-option>
                        <el-option label="CASE WHEN 盲注" value="sec2Attack2"></el-option>
                        <el-option label="IF() 盲注" value="sec2Attack3"></el-option>
                        <el-option label="SLEEP() 时间盲注" value="sec2Attack4"></el-option>
                    </el-select>
                </el-form-item>
                
                <el-form-item label="orderBy 参数">
                    <el-input v-model="sec2Payload" type="textarea" :rows="3" placeholder="ORDER BY 参数"></el-input>
                </el-form-item>
                
                <el-form-item label="说明">
                    <div style="color: #909399; font-size: 13px;">
                        {{ sec2Description }}
                    </div>
                </el-form-item>
                
                <el-form-item>
                    <el-button type="primary" @click="executeSec2Test" :loading="sec2Loading">执行测试</el-button>
                    <el-button @click="resetSec2Dialog">重置</el-button>
                </el-form-item>
            </el-form>
            
            <!-- 查询结果区域 -->
            <div v-if="sec2ResultVisible" style="margin-top: 20px; border-top: 1px solid #EBEEF5; padding-top: 20px;">
                <div v-if="!sec2Success" style="margin-bottom: 15px; color: #F56C6C; font-size: 13px;">
                    {{ sec2ErrorMsg }}
                </div>
                
                <el-table v-if="sec2Success" :data="sec2TableData" border style="width: 100%; margin: 0 auto;" max-height="350">
                    <el-table-column prop="id" label="ID" align="center"></el-table-column>
                    <el-table-column prop="username" label="用户名" align="center"></el-table-column>
                    <el-table-column prop="name" label="姓名" align="center"></el-table-column>
                </el-table>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { orderByVuln, orderBySec1, orderBySec2 } from '@/api/sqli';

export default {
    data() {
        return {
            activeName: 'first',
            attackDialogVisible: false,
            selectedAttackType: 'normalId',
            attackPayload: '',
            attackPayloads: {
                normalId: 'id',
                normalUsername: 'username',
                normalName: 'name',
                caseWhen: '(CASE WHEN (SELECT COUNT(*) FROM user)>0 THEN id ELSE username END)',
                if: 'IF((SELECT COUNT(*) FROM user)>0, id, username)',
                sleep: 'IF((SELECT COUNT(*) FROM user)>0, (SELECT SLEEP(2)), id)'
            },
            attackLoading: false,
            attackResultVisible: false,
            attackTableData: [],
            attackSuccess: false,
            attackDuration: 0,
            pocUrl: '',
            sec1DialogVisible: false,
            sec1PayloadType: 'sec1Normal1',
            sec1Payload: 'id',
            sec1Payloads: {
                sec1Normal1: 'id',
                sec1Normal2: 'username',
                sec1Normal3: 'name',
                sec1Attack1: '(CASE WHEN (SELECT COUNT(*) FROM user)>0 THEN id ELSE username END)',
                sec1Attack2: 'IF((SELECT COUNT(*) FROM user)>0, id, username)',
                sec1Attack3: 'IF((SELECT COUNT(*) FROM user)>0, (SELECT SLEEP(2)), id)'
            },
            sec1Loading: false,
            sec1ResultVisible: false,
            sec1TableData: [],
            sec1Success: false,
            sec1ErrorMsg: '',
            sec2DialogVisible: false,
            sec2PayloadType: 'sec2Normal1',
            sec2Payload: 'ID',
            sec2Payloads: {
                sec2Normal1: 'ID',
                sec2Normal2: 'USERNAME',
                sec2Normal3: 'NAME',
                sec2Attack1: 'id',
                sec2Attack2: '(CASE WHEN (SELECT COUNT(*) FROM user)>0 THEN id ELSE username END)',
                sec2Attack3: 'IF((SELECT COUNT(*) FROM user)>0, id, username)',
                sec2Attack4: 'IF((SELECT COUNT(*) FROM user)>0, (SELECT SLEEP(2)), id)'
            },
            sec2Loading: false,
            sec2ResultVisible: false,
            sec2TableData: [],
            sec2Success: false,
            sec2ErrorMsg: ''
        };
    },
    computed: {
        attackDescription() {
            const descriptions = {
                normalId: '正常排序：按 ID 字段排序，展示 ORDER BY 的基本功能',
                normalUsername: '正常排序：按用户名字段排序，数据将按用户名顺序展示',
                normalName: '正常排序：按姓名字段排序，数据将按姓名顺序展示',
                caseWhen: '利用 CASE WHEN 进行布尔盲注，根据条件真假返回不同的排序结果',
                if: '利用 IF() 函数进行布尔盲注，根据条件真假返回不同的排序字段',
                sleep: '利用 SLEEP() 函数进行时间盲注（⚠️注意：因ORDER BY对每行计算，实际延时 = 表记录数×2秒 ≈ 24秒）'
            };
            return descriptions[this.selectedAttackType] || '';
        },
        sec1Description() {
            const descriptions = {
                sec1Normal1: '正常字段 id，在白名单中，校验将通过',
                sec1Normal2: '正常字段 username，在白名单中，校验将通过',
                sec1Normal3: '正常字段 name，在白名单中，校验将通过',
                sec1Attack1: '尝试注入 CASE WHEN 盲注，不在白名单中，将被拦截',
                sec1Attack2: '尝试注入 IF() 盲注，不在白名单中，将被拦截',
                sec1Attack3: '尝试注入 SLEEP() 时间盲注，不在白名单中，将被拦截'
            };
            return descriptions[this.sec1PayloadType] || '';
        },
        sec2Description() {
            const descriptions = {
                sec2Normal1: '有效枚举值 ID，校验将通过',
                sec2Normal2: '有效枚举值 USERNAME，校验将通过',
                sec2Normal3: '有效枚举值 NAME，校验将通过',
                sec2Attack1: '小写 id，不是有效枚举值，将被拦截',
                sec2Attack2: '尝试注入 CASE WHEN，不是有效枚举值，将被拦截',
                sec2Attack3: '尝试注入 IF() 盲注，不是有效枚举值，将被拦截',
                sec2Attack4: '尝试注入 SLEEP() 时间盲注，不是有效枚举值，将被拦截'
            };
            return descriptions[this.sec2PayloadType] || '';
        },
        formattedSql() {
            if (!this.pocUrl) return '';
            
            // 处理 orderBy 参数，只取第一个参数（orderBy），忽略 page 和 pageSize
            if (this.pocUrl.includes('orderBy=')) {
                const parts = this.pocUrl.split('orderBy=');
                if (parts.length === 2) {
                    // 提取 orderBy 的值（到 & 或字符串结尾）
                    const afterOrderBy = parts[1];
                    const endIndex = afterOrderBy.indexOf('&');
                    const orderByValue = endIndex > -1 ? afterOrderBy.substring(0, endIndex) : afterOrderBy;
                    
                    // 解码URL参数
                    const decodedValue = decodeURIComponent(orderByValue);
                    
                    // 只显示到 orderBy 参数结束
                    const baseUrl = parts[0] + 'orderBy=';
                    return baseUrl + '<span class="sql-param">' + decodedValue + '</span>';
                }
            }
            
            return this.pocUrl;
        }
    },
    watch: {
        selectedAttackType(newVal) {
            this.attackPayload = this.attackPayloads[newVal];
        },
        sec1PayloadType(newVal) {
            this.sec1Payload = this.sec1Payloads[newVal];
        },
        sec2PayloadType(newVal) {
            this.sec2Payload = this.sec2Payloads[newVal];
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        
        // 打开攻击测试对话框
        openAttackDialog() {
            this.selectedAttackType = 'normalId';
            this.attackPayload = this.attackPayloads.normalId;
            this.attackResultVisible = false;
            this.attackTableData = [];
            this.pocUrl = '';
            this.attackDialogVisible = true;
        },
        
        // 重置攻击对话框
        resetAttackDialog() {
            this.selectedAttackType = 'normalId';
            this.attackPayload = this.attackPayloads.normalId;
            this.attackResultVisible = false;
            this.attackTableData = [];
            this.attackSuccess = false;
            this.attackDuration = 0;
            this.pocUrl = '';
        },
        
        // 执行攻击测试
        async executeAttack() {
            try {
                this.attackLoading = true;
                this.attackResultVisible = false;
                
                // 构造 pocUrl
                this.pocUrl = `http://127.0.0.1:8080/sqli/orderby/vuln?orderBy=${encodeURIComponent(this.attackPayload)}&page=1&pageSize=5`;
                
                const startTime = Date.now();
                
                const response = await orderByVuln({ 
                    orderBy: this.attackPayload, 
                    page: 1, 
                    pageSize: 5 
                });
                
                const endTime = Date.now();
                this.attackDuration = endTime - startTime;
                
                if (response.code === 0) {
                    this.attackTableData = response.data.rows || [];
                    this.attackSuccess = true;
                    this.attackResultVisible = true;
                } else {
                    this.attackSuccess = false;
                    this.attackResultVisible = true;
                    this.attackTableData = [];
                }
            } catch (error) {
                this.attackSuccess = false;
                this.attackResultVisible = true;
                this.attackTableData = [];
            } finally {
                this.attackLoading = false;
            }
        },
        
        // 打开白名单测试对话框
        openSec1Dialog() {
            this.sec1PayloadType = 'sec1Normal1';
            this.sec1Payload = this.sec1Payloads.sec1Normal1;
            this.sec1ResultVisible = false;
            this.sec1TableData = [];
            this.sec1Success = false;
            this.sec1ErrorMsg = '';
            this.sec1DialogVisible = true;
        },
        
        // 执行白名单测试
        async executeSec1Test() {
            try {
                this.sec1Loading = true;
                this.sec1ResultVisible = false;
                
                const response = await orderBySec1({ 
                    orderBy: this.sec1Payload, 
                    page: 1, 
                    pageSize: 5 
                });
                
                if (response.code === 0) {
                    this.sec1TableData = response.data.rows || [];
                    this.sec1Success = true;
                    this.sec1ResultVisible = true;
                } else {
                    this.sec1Success = false;
                    this.sec1ResultVisible = true;
                    this.sec1TableData = [];
                    this.sec1ErrorMsg = response.msg || '非法排序字段';
                }
            } catch (error) {
                this.sec1Success = false;
                this.sec1ResultVisible = true;
                this.sec1TableData = [];
                this.sec1ErrorMsg = error.message || '请求失败';
            } finally {
                this.sec1Loading = false;
            }
        },
        
        // 重置白名单测试对话框
        resetSec1Dialog() {
            this.sec1PayloadType = 'sec1Normal1';
            this.sec1Payload = this.sec1Payloads.sec1Normal1;
            this.sec1ResultVisible = false;
            this.sec1TableData = [];
            this.sec1Success = false;
            this.sec1ErrorMsg = '';
        },
        
        // 打开枚举测试对话框
        openSec2Dialog() {
            this.sec2PayloadType = 'sec2Normal1';
            this.sec2Payload = this.sec2Payloads.sec2Normal1;
            this.sec2ResultVisible = false;
            this.sec2TableData = [];
            this.sec2Success = false;
            this.sec2ErrorMsg = '';
            this.sec2DialogVisible = true;
        },
        
        // 执行枚举测试
        async executeSec2Test() {
            try {
                this.sec2Loading = true;
                this.sec2ResultVisible = false;
                
                const response = await orderBySec2({ 
                    orderBy: this.sec2Payload, 
                    page: 1, 
                    pageSize: 5 
                });
                
                if (response.code === 0) {
                    this.sec2TableData = response.data.rows || [];
                    this.sec2Success = true;
                    this.sec2ResultVisible = true;
                } else {
                    this.sec2Success = false;
                    this.sec2ResultVisible = true;
                    this.sec2TableData = [];
                    this.sec2ErrorMsg = response.msg || '非法排序字段';
                }
            } catch (error) {
                this.sec2Success = false;
                this.sec2ResultVisible = true;
                this.sec2TableData = [];
                this.sec2ErrorMsg = error.message || '请求失败';
            } finally {
                this.sec2Loading = false;
            }
        },
        
        // 重置枚举测试对话框
        resetSec2Dialog() {
            this.sec2PayloadType = 'sec2Normal1';
            this.sec2Payload = this.sec2Payloads.sec2Normal1;
            this.sec2ResultVisible = false;
            this.sec2TableData = [];
            this.sec2Success = false;
            this.sec2ErrorMsg = '';
        }
    }
};
</script>

<style scoped>
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
    line-height: 1.8;
}

.vuln-detail code {
    background-color: #f0f0f0;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    color: #e74c3c;
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

.bg-purple {
    background: #d3dce6;
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

.sql-param {
    color: red;
    font-weight: bold;
}
</style>
