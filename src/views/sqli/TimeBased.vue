<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- 基于时间盲注</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            基于时间的盲注(Time-based Blind SQL Injection)是一种SQL注入技术，通过构造特殊的SQL语句，利用数据库的延时函数来判断注入条件是否成立，从而逐步获取数据库信息。<br /><br />
                            <span style="color: red;">时间盲注的特点：</span><br />
                            1. 页面没有明显的回显数据，也没有错误信息<br />
                            2. 通过响应时间的长短来判断SQL语句的执行结果<br />
                            3. 利用数据库的延时函数如SLEEP()、BENCHMARK()等<br />
                            4. 需要逐个字符进行猜测，效率相对较低<br />
                            5. 适用于没有回显和错误信息的场景
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            基于时间盲注漏洞的危害非常严重，攻击者可以通过延时判断获取大量敏感数据：<br /><br />
                            数据库信息泄露：获取数据库版本、数据库名、表结构等；<br />
                            敏感数据获取：通过延时判断逐步获取表中的敏感数据；<br />
                            权限提升：获取管理员账户信息，可能导致权限提升；<br />
                            数据泄露：获取用户密码、个人信息等敏感数据；<br />
                            系统信息泄露：可能泄露服务器路径、操作系统信息等。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】使用预编译语句<br />
                            使用PreparedStatement或MyBatis的#{}占位符，避免字符串拼接。<br /><br />
                            【必须】输入验证<br />
                            对用户输入进行严格的类型检查和长度限制。<br /><br />
                            【建议】超时控制<br />
                            设置合理的数据库查询超时时间，防止长时间查询。<br /><br />
                            【建议】最小权限原则<br />
                            数据库用户使用最小权限，避免高权限操作。<br /><br />
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://www.cnblogs.com/backlion/p/9721687.html" target="_blank" style="text-decoration: underline;">《SQL盲注详解》</a>：深入学习SQL盲注技术。<br />
                            <a href="https://blog.csdn.net/weixin_43921592/article/details/105456456" target="_blank" style="text-decoration: underline;">《MySQL时间盲注函数总结》</a>：MySQL时间盲注常用函数详解。
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 时间盲注 <div>
                            <el-button type="success" round size="mini" @click="fetchDataAndFillTable1">正常查询</el-button>
                            <el-button type="danger" round size="mini" @click="openTimeBasedDialog">去测试</el-button>
                        </div></el-row>
                        <pre v-highlightjs><code class="java">
// Controller业务接口
@RestController
@RequestMapping("/sqli/time")
public class TimeBasedInjectionController {
    @Autowired
    private TimeBasedInjectionService timeBasedInjectionService;

    @GetMapping("/getUserByUsernameTime")
    public Result getUserByUsernameTime(@RequestParam String username) {
        return Result.success(timeBasedInjectionService.getUserByUsernameTime(username));
    }
}

// Service实现类
@Service
public class TimeBasedInjectionServiceImpl implements TimeBasedInjectionService {
    @Autowired
    private TimeBasedInjectionMapper timeBasedInjectionMapper;

    @Override
    public List&lt;User&gt; getUserByUsernameTime(String username) {
        return timeBasedInjectionMapper.selectUserByUsernameTime(username);
    }
} 

// Mapper代理接口
@Mapper
public interface TimeBasedInjectionMapper {
    /**
     * 根据username查询用户，用于演示基于时间盲注
     * @param username
     * @return
     */
    @Select("SELECT * FROM user WHERE username = '${username}'")
    List&lt;User&gt; selectUserByUsernameTime(String username);
}
</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 预编译语句 <div>
                                <el-button type="success" round size="mini" @click="fetchDataAndFillTable2">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">
// Controller业务接口
@RestController
@RequestMapping("/sqli/time")
public class TimeBasedInjectionController {
    @Autowired
    private TimeBasedInjectionService timeBasedInjectionService;

    @GetMapping("/getUserByUsernameTimeSafe")
    public Result getUserByUsernameTimeSafe(@RequestParam String username) {
        return Result.success(timeBasedInjectionService.getUserByUsernameTimeSafe(username));
    }
}

// Service实现类
@Service
public class TimeBasedInjectionServiceImpl implements TimeBasedInjectionService {
    @Autowired
    private TimeBasedInjectionMapper timeBasedInjectionMapper;

    @Override
    public List&lt;User&gt; getUserByUsernameTimeSafe(String username) {
        return timeBasedInjectionMapper.selectUserByUsernameTimeSafe(username);
    }
} 

// Mapper代理接口
@Mapper
public interface TimeBasedInjectionMapper {
    /**
     * 根据username查询用户，用于演示防御基于时间盲注
     * @param username
     * @return
     */
    @Select("SELECT * FROM user WHERE username = #{username}")
    List&lt;User&gt; selectUserByUsernameTimeSafe(String username);
}
                        </code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
        <!-- 打开嵌套表格的对话框 -->
        <el-dialog title="查询用户信息接口" :visible.sync="dialogTableVisible">
            <div v-if="isError">
                <h3 style="color: red;">错误信息：</h3>
                <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px;">{{ errorMessage }}</pre>
            </div>
            <div v-else>
                执行的sql语句为: <span v-html="formattedSql"></span>
                <br />
                <br />
                <div v-if="isSafeTest">
                    <h4>返回内容：</h4>
                    <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px;">{{ safeResult }}</pre>
                </div>
                <el-table :data="gridData" v-else-if="gridData.length > 0">
                    <el-table-column property="id" label="编号" width="150"></el-table-column>
                    <el-table-column property="name" label="姓名" width="200"></el-table-column>
                    <el-table-column property="username" label="用户名" width="200"></el-table-column>
                    <el-table-column property="password" label="密码" width="200"></el-table-column>
                </el-table>
                <div v-else-if="!isSafeTest">
                    <p>查询结果：{{ resultMessage }}</p>
                </div>
            </div>
        </el-dialog>
        <!-- 时间盲注专用弹窗 -->
        <el-dialog title="时间盲注测试" :visible.sync="dialogTimeBasedVisible" @close="onTimeBasedDialogClose">
            <div style="margin-bottom: 16px;">
                <el-button type="primary" @click="testSleep5">测试延时5秒</el-button>
                <el-button type="primary" @click="testBenchmark">测试Benchmark</el-button>
                <el-button type="primary" @click="testDatabaseName">获取数据库名</el-button>
            </div>
            <div style="margin-bottom: 16px;">
                <label>测试参数：</label>
                <el-input 
                    v-model="testUsername" 
                    placeholder="请输入测试的用户名参数"
                    style="margin-top: 8px;"
                    clearable>
                </el-input>
                <div style="margin-top: 8px;">
                    <el-button type="success" @click="executeCustomTest">执行测试</el-button>
                    <el-button type="info" @click="clearTestResult">清空结果</el-button>
                </div>
            </div>
            <div v-if="timeBasedPocUrl">
                执行的sql语句为: <span v-html="formattedTimeBasedSql"></span>
                <br />
            </div>
            <div v-if="timeBasedResult">
                <h4>返回内容：</h4>
                <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px;">{{ timeBasedResult }}</pre>
            </div>
            <div v-if="responseTime">
                <h4>响应时间：</h4>
                <p style="color: red; font-weight: bold;">{{ responseTime }}ms</p>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { 
    getUserByUsernameTime, 
    getUserByUsernameTimeSafe
} from '@/api/sqli';

export default {
    data() {
        return {
            activeName: 'first',
            gridData: [],
            pocUrl: '',
            dialogTableVisible: false,
            isError: false,
            errorMessage: '',
            resultMessage: '',
            dialogTimeBasedVisible: false,
            timeBasedResult: '',
            timeBasedPocUrl: '',
            responseTime: '',
            isSafeTest: false,
            safeResult: '',
            testUsername: '',
        };
    },
    computed: {
        formattedSql() {
            if (!this.pocUrl) return '';
            
            const params = ['username='];
            let result = this.pocUrl;
            
            for (const param of params) {
                const index = result.indexOf(param);
                if (index > -1) {
                    const prefix = result.substring(0, index + param.length);
                    const value = decodeURIComponent(result.substring(index + param.length));
                    return prefix + '<span class="sql-param">' + value + '</span>';
                }
            }
            
            return result;
        },
        formattedTimeBasedSql() {
            if (!this.timeBasedPocUrl) return '';
            const params = ['username='];
            let result = this.timeBasedPocUrl;
            for (const param of params) {
                const index = result.indexOf(param);
                if (index > -1) {
                    const prefix = result.substring(0, index + param.length);
                    const value = decodeURIComponent(result.substring(index + param.length));
                    return prefix + '<span class="sql-param">' + value + '</span>';
                }
            }
            return result;
        },
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        // 时间盲注测试
        openTimeBasedDialog() {
            this.dialogTimeBasedVisible = true;
            this.timeBasedResult = '';
            this.responseTime = '';
            this.testUsername = "zhangsan' and sleep(5) -- ";
        },
        testSleep5() {
            this.testUsername = "zhangsan' and sleep(5) -- ";
            this.responseTime = '--';
            const startTime = Date.now();
            const url = "http://127.0.0.1:8080/sqli/time/getUserByUsernameTime?username=zhangsan' and sleep(5) -- ";
            this.timeBasedPocUrl = url;
            getUserByUsernameTime({ username: "zhangsan' and sleep(5) -- " })
                .then(response => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = error.response?.data?.message || error.message;
                });
        },
        testBenchmark() {
            this.testUsername = "zhangsan' and benchmark(1000000000,md5(1)) -- ";
            this.responseTime = '--';
            const startTime = Date.now();
            const url = "http://127.0.0.1:8080/sqli/time/getUserByUsernameTime?username=zhangsan' and benchmark(10000000,md5(1)) -- ";
            this.timeBasedPocUrl = url;
            getUserByUsernameTime({ username: "zhangsan' and benchmark(10000000,md5(1)) -- " })
                .then(response => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = error.response?.data?.message || error.message;
                });
        },
        testDatabaseName() {
            this.testUsername = "zhangsan' and if(substr(database(),1,1)='s',sleep(3),0) -- ";
            this.responseTime = '--';
            const startTime = Date.now();
            const url = "http://127.0.0.1:8080/sqli/time/getUserByUsernameTime?username=zhangsan' and if(substr(database(),1,1)='s',sleep(3),0) -- ";
            this.timeBasedPocUrl = url;
            getUserByUsernameTime({ username: "zhangsan' and if(substr(database(),1,1)='s',sleep(3),0) -- " })
                .then(response => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = error.response?.data?.message || error.message;
                });
        },
        // 安全代码测试
        fetchDataAndFillTable2() {
            this.isSafeTest = true;
            getUserByUsernameTimeSafe({ username: "zhangsan' and sleep(5) -- " })
                .then(response => {
                    this.isError = false;
                    this.pocUrl = "http://127.0.0.1:8080/sqli/time/getUserByUsernameTimeSafe?username=zhangsan' and sleep(5) -- ";
                    this.dialogTableVisible = true;
                    this.safeResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    this.isError = true;
                    this.errorMessage = error.response?.data?.message || error.message;
                    this.pocUrl = "http://127.0.0.1:8080/sqli/time/getUserByUsernameTimeSafe?username=zhangsan' and sleep(5) -- ";
                    this.dialogTableVisible = true;
                });
        },
        fetchDataAndFillTable1() {
            getUserByUsernameTime({ username: 'zhangsan' })
                .then(response => {
                    this.isError = false;
                    this.pocUrl = "http://127.0.0.1:8080/sqli/time/getUserByUsernameTime?username=zhangsan";
                    this.dialogTableVisible = true;
                    this.gridData = Array.isArray(response.data) ? response.data : [];
                })
                .catch(error => {
                    this.isError = true;
                    this.errorMessage = error.response?.data?.message || error.message;
                    this.dialogTableVisible = true;
                });
        },
        onTimeBasedDialogClose() {
            this.timeBasedPocUrl = '';
            this.timeBasedResult = '';
            this.responseTime = '';
            this.testUsername = '';
        },
        onDialogTableClose() {
            this.isSafeTest = false;
            this.safeResult = '';
        },
        executeCustomTest() {
            this.responseTime = '--';
            const startTime = Date.now();
            const url = `http://127.0.0.1:8080/sqli/time/getUserByUsernameTime?username=${this.testUsername}`;
            this.timeBasedPocUrl = url;
            getUserByUsernameTime({ username: this.testUsername })
                .then(response => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    const endTime = Date.now();
                    this.responseTime = endTime - startTime;
                    this.timeBasedResult = error.response?.data?.message || error.message;
                });
        },
        clearTestResult() {
            this.timeBasedPocUrl = '';
            this.timeBasedResult = '';
            this.responseTime = '';
        },
    }
};
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
    min-height: 36px;
    padding: 10px;
}

.grid-flex {
    margin-bottom: 20px;
}

.sql-param {
    color: red;
    font-weight: bold;
}
</style> 