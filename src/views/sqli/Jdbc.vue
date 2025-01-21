<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- JDBC</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            SQLI(SQL
                            Injection)，SQL注入是因为程序未能正确对用户的输入进行检查，将用户的输入以拼接的方式带入SQL语句，导致了SQL注入的产生。攻击者可通过SQL注入直接获取数据库信息，造成信息泄漏。<span
                                style="color: red;">JDBC</span>有两个方法执行SQL语句，分别是PrepareStatement和Statement。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="漏洞危害" name="second">
                        <div class="vuln-detail">
                            SQL注入漏洞的危险不仅限于造成敏感数据的泄漏，如果权限配置不当还可能造成数据篡改、数据删除，甚至是执行服务器命令等严重后果。<br /><br />
                            数据泄露：攻击者可以通过SQL注入获取数据库中的敏感数据；<br />
                            数据篡改：攻击者可以修改数据库中的数据，导致数据不一致或损坏；<br />
                            数据删除：攻击者可以删除数据库中的数据，造成严重的数据丢失；<br />
                            命令执行：攻击者可以执行系统命令，导致服务器被恶意控制。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="安全编码" name="third">
                        <div class="vuln-detail">
                            【必须】SQL语句默认使用预编译并绑定变量
                            Web后台系统应默认使用预编译绑定变量的形式创建sql语句，保持查询语句和数据相分离。以从本质上避免SQL注入风险。
                            <br />
                            【必须】屏蔽异常栈
                            应用程序出现异常时，禁止将数据库版本、数据库结构、操作系统版本、堆栈跟踪、文件名和路径信息、SQL查询字符串等对攻击者有用的信息返回给客户端。建议重定向到一个统一、默认的错误提示页面，进行信息过滤。
                            <br />
                            【建议】恶意字符过滤
                            对用户输入的数据进行恶意字符过滤，过滤掉SQL语句中的特殊字符，以防止SQL注入攻击。
                            <br />
                            【建议】强类型检查
                            对用户输入的数据进行强类型检查，确保数据类型的正确性，以防止SQL注入攻击。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <!-- 给超链接配置下划线 -->
                            <a href="https://mp.weixin.qq.com/s/MitJ6eecT9ZbMwg6ktdW1w?token=1562987233&lang=zh_CN"
                                target="_blank"
                                style="text-decoration: underline;">《再说PreparedStatement预编译》</a>：深入学习Mysql预编译技术。<br />
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - 语句拼接(Statement) <div>
                                <!-- <el-button type="danger" round size="mini" @click="handleButtonClick1">去测试</el-button> -->
                                <el-button type="text" @click="fetchDataAndFillTable1"
                                    style="color: green;">正常查询</el-button>
                                <el-button type="text" @click="fetchDataAndFillTable2"
                                    style="color: red;">注入查询</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/getUserByUsername")
public Result getUserByUsername(String username) throws Exception {
    List&lt;User&gt; users = new ArrayList&lt;&gt;();
    //1、注册驱动
    Class.forName("com.mysql.cj.jdbc.Driver");
    //2.获取连接
    Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
    //3.定义sql语句
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
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 恶意字符过滤 <div>
                                <el-button type="text" @click="fetchDataAndFillTable3"
                                    style="color: red;">注入查询</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// 安全工具类
public class Security {
    public static boolean checkSql(String content) {
        String[] black_list = { "'", ";", "and", "exec", "insert", "select", "delete", "update", "count", "*", "chr", "mid", "master", "truncate", "char", "declare", "or" };
        for (String str : black_list) {
            if (content.toLowerCase().contains(str)) {
                return true;
            }
        }
        return false;
    }
}   

// Jdbc：字符串型sql注入-恶意字符过滤
@GetMapping("/getUserSecByUsernameFilter") 
public Result getUserByUsernameFilter(String username) throws Exception {
    if (!Security.checkSql(username)) {
        List&lt;User&gt; users = new ArrayList&lt;&gt;();
        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");
        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
        //3.定义sql语句
        String sql = "select id, username, name from user where username = '" + username + "'";
        //4.获取statement对象
        Statement statement = conn.createStatement();
        ResultSet resultSet = statement.executeQuery(sql);
        //5.判断是否查询到数据，省略
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
                            语句拼接(PrepareStatement)<div>
                                <el-button type="text" @click="fetchDataAndFillTable4"
                                    style="color: green;">正常查询</el-button>
                                <el-button type="text" @click="fetchDataAndFillTable5"
                                    style="color: red;">注入查询</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/getUserSecByUsernameError")
public Result getUserSecByUsernameError(String username) throws Exception {
    List&lt;User&gt; users = new ArrayList&lt;&gt;();
    //1、注册驱动
    Class.forName("com.mysql.cj.jdbc.Driver");
    //2.获取连接
    Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
    //3.定义sql语句
    String sql = "select id, username, name from user where username = '" + username + "'";
    //4.获取statement对象
    PreparedStatement preparedStatement = conn.prepareStatement(sql);
    ResultSet resultSet = preparedStatement.executeQuery();
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
    preparedStatement.close();
    conn.close();
    return Result.success(users);
}</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 预编译 <div>
                                <el-button type="text" @click="fetchDataAndFillTable6"
                                    style="color: red;">注入查询</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">@GetMapping("/getUserSecByUsername")
public Result getUserSecByUsername(String username) throws Exception {
    List&lt;User&gt; users = new ArrayList&lt;&gt;();
    //1、注册驱动
    Class.forName("com.mysql.cj.jdbc.Driver");
    //2.获取连接
    Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);
    //3.定义sql语句
    String sql = "select id, username, name from user where username = ?";
    //4.获取statement对象
    PreparedStatement preparedStatement = conn.prepareStatement(sql);
    preparedStatement.setString(1, username);
    ResultSet resultSet = preparedStatement.executeQuery();
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
    preparedStatement.close();
    conn.close();
    return Result.success(users);
}
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
        <!-- 打开嵌套表格的对话框 -->
        <el-dialog title="查询用户信息接口" :visible.sync="dialogTableVisible">
            执行的sql语句为: {{ pocUrl }}
            <br />
            <br />
            <el-table :data="gridData">

                <el-table-column property="id" label="编号" width="150"></el-table-column>
                <el-table-column property="name" label="姓名" width="200"></el-table-column>
                <el-table-column property="username" label="用户名" width="200"></el-table-column>
                <el-table-column property="password" label="密码" width="200"></el-table-column>
            </el-table>
        </el-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import { getUserByUsername, getUserByUsernameFilter, getUserSecByUsernameError, getUserSecByUsername } from '@/api/sqli';

export default {
    data() {
        return {
            activeName: 'first',
            gridData: [],
            pocUrl: '',
            dialogTableVisible: false,
        };
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            getUserByUsername({ username: 'zhangsan' })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/jdbc/getUserByUsername?username=zhangsan";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable2() {
            getUserByUsername({ username: "zhangsan' or 'f'= 'f" })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/jdbc/getUserByUsername?username=zhangsan' or 'f'='f";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable3() {
            getUserByUsernameFilter({ username: "zhangsan' or 'f'= 'f" })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/jdbc/getUserSecByUsernameFilter?username=zhangsan' or 'f'='f";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable4() {
            getUserSecByUsernameError({ username: "zhangsan" })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/jdbc/getUserSecByUsernameError?username=zhangsan";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable5() {
            getUserSecByUsernameError({ username: "zhangsan' or 'f'= 'f" })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/jdbc/getUserSecByUsernameError?username=zhangsan' or 'f'='f";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable6() {
            getUserSecByUsername({ username: "zhangsan' or 'f'= 'f" })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/jdbc/getUserSecByUsername?username=zhangsan' or 'f'='f";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
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