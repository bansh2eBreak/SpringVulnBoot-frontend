<template>
    <div class="root-div">
        <div class="vuln-info">
            <div class="header-div">SQL注入 -- Mybatis类型</div>
            <div class="body-div">
                <el-tabs v-model="activeName" @tab-click="handleClick">
                    <el-tab-pane label="漏洞描述" name="first">
                        <div class="vuln-detail">
                            SQLI(SQL
                            Injection)，SQL注入是因为程序未能正确对用户的输入进行检查，将用户的输入以拼接的方式带入SQL语句，导致了SQL注入的产生。攻击者可通过SQL注入直接获取数据库信息，造成信息泄漏。<br />
                            <span style="color: red;">MyBatis框架</span>底层已经实现了对SQL注入的防御，但存在使用不当的情况下，仍然存在SQL注入的风险。
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
                            使用Mybatis作为持久层框架，应通过#{}语法进行参数绑定，MyBatis 会创建 PreparedStatement 参数占位符，并通过占位符安全地设置参数。
                            对于无法使用#{}的情况如order by 注入，可以在代码层面通过其他方式来解决，如过滤。
                            <br /><br />
                            【必须】屏蔽异常栈
                            应用程序出现异常时，禁止将数据库版本、数据库结构、操作系统版本、堆栈跟踪、文件名和路径信息、SQL查询字符串等对攻击者有用的信息返回给客户端。建议重定向到一个统一、默认的错误提示页面，进行信息过滤。
                            <br /><br />
                            【建议】恶意字符过滤
                            对用户输入的数据进行恶意字符过滤，过滤掉SQL语句中的特殊字符，以防止SQL注入攻击。
                            <br /><br />
                            【建议】强类型检查
                            对用户输入的数据进行强类型检查，确保数据类型的正确性，以防止SQL注入攻击。
                        </div>
                    </el-tab-pane>
                    <el-tab-pane label="参考文章" name="fourth">
                        <div class="vuln-detail">
                            <!-- 给超链接配置下划线 -->
                            <a href="https://mp.weixin.qq.com/s/XFIWgvJRyhZsGGLhTYMjnQ?token=1562987233&lang=zh_CN"
                                target="_blank" style="text-decoration: underline;">《写点不一样的order by参数注入》</a>：学习order
                            by参数为啥不能使用Mybatis的预编译模式。<br />
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
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 - ${} - 普通参数<div>
                                <el-button type="success" round size="mini" @click="fetchDataAndFillTable1"
                                  >正常查询</el-button>
                                <el-button type="danger" round size="mini" @click="fetchDataAndFillTable2"
                                    >去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">/**
 * Controller接口代码
 */
@GetMapping("/getUserById")
public Result getUserById2(String id) {
    return Result.success(userService.selectUserById(id));
}

/**
 * Service层代码
 */
@Override
public List&lt;User&gt; selectUserById(String id) {
    return userMapper.selectUserById(id);
}

/**
 * Mapper接口代码
 */
@Select("select id, username, name from user where id = ${id}")
List&lt;User&gt; selectUserById(String id);</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - 恶意字符过滤<div>
                                <el-button type="success" round size="mini" @click="fetchDataAndFillTable3"
                                    >去测试</el-button>
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
// Controller层
@GetMapping("/getUserByIdSec")
public Result getUserByIdSec(String id) {
    if (!Security.checkSql(id)) {
        return Result.success(userService.selectUserById(id));
    } else {
        log.warn("检测到非法注入字符: {}", id);
        return Result.error("检测到非法注入");
    }
}

// Service层
@Override
    public List&lt;User&gt; selectUserById(String id) {
        return userMapper.selectUserById(id);
    }

// Mapper接口层
@Select("select * from user where id = ${id}")
List&lt;User&gt; selectUserById(String id);
</code></pre>
                    </div>
                </el-col>
            </el-row>
            <el-row :gutter="20" class="grid-flex">
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">漏洞代码 -
                            ${} - order by参数 <div>
                                <el-button type="success" round size="mini" @click="fetchDataAndFillTable4"
                                    >正常查询</el-button>
                                <el-button type="danger" round size="mini" @click="fetchDataAndFillTable5"
                                    >去测试</el-button>
                            </div></el-row>
                        <pre
                            v-highlightjs><code class="java">// 注意，order by 参数无法使用预编译
// Controller层
@GetMapping("/getUserByPage")
public Result getUserByPage(@RequestParam(defaultValue = "id") String orderBy, @RequestParam(defaultValue = "1") Integer page, @RequestParam(defaultValue = "5") Integer pageSize) {
    log.info("分页查询，参数：{} {} {}", page, pageSize, orderBy);
    return Result.success(userService.pageOrderBy(orderBy, page, pageSize));
}

// Service层，处理分页逻辑、封装分页结果
@Override
public PageBean pageOrderBy(String orderBy, Integer page, Integer pageSize) {
    //1.获取总记录数
    int count = userMapper.count();

    //2.获取分页查询结果
    int start = (page - 1) * pageSize;
    List&lt;User&gt; userList = userMapper.pageOrderBy(orderBy, start, pageSize);

    //3.分装PageBean对象
    return new PageBean(count, userList);
}

// Mapper层

// 查询总记录数
@Select("select count(*) from user")
int count();

// 支持按字段排序的分页查询，获取用户列表数据
@Select("select * from user order by ${orderBy} limit #{start}, #{pageSize}")
List&lt;User&gt; pageOrderBy(@Param("orderBy") String orderBy, @Param("start") int start, @Param("pageSize") int pageSize);</code></pre>
                    </div>
                </el-col>
                <el-col :span="12">
                    <div class="grid-content bg-purple">
                        <el-row type="flex" justify="space-between" align="middle">安全代码 - #{}预编译<div>
                                <el-button type="success" round size="mini" @click="fetchDataAndFillTable6"
                                    >去测试</el-button>
                            </div></el-row>
                        <pre v-highlightjs><code class="java">// Controller层
/**
 * Mybatis：预编译
 * @param username
 * @return
 */
@GetMapping("/getUserSecByUsername")
public Result getUserSecByUsername(String username) {
   return Result.success(userService.selecctUserSecByUsername(username));
}

// Service层
@Override
public List&lt;User&gt; selecctUserSecByUsername(String username) {
   return userMapper.selectUserSecByUsername(username);
}

// Mapper层
/**
 * 根据username查询用户，使用预编译
 * @param username
 * @return
 */
@Select("select * from user where username = #{username}")
List&lt;User&gt; selectUserSecByUsername(@Param("username") String username);
</code></pre>
                    </div>
                </el-col>
            </el-row>
        </div>
        <!-- 打开嵌套表格的对话框 -->
        <el-dialog title="查询用户信息接口" :visible.sync="dialogTableVisible">
            执行的sql语句为: <span v-html="formattedSql"></span>
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
import { getUserByPage, getUserById, getUserByIdSec, getUserSecByUsername2 } from '@/api/sqli';

export default {
    data() {
        return {
            activeName: 'first',
            gridData: [],
            pocUrl: '',
            dialogTableVisible: false,
        };
    },
    computed: {
        formattedSql() {
            if (!this.pocUrl) return '';
            
            // 处理不同的参数类型
            const params = ['id=', 'username=', 'orderBy='];
            let result = this.pocUrl;
            
            for (const param of params) {
                if (result.includes(param)) {
                    const parts = result.split(param);
                    if (parts.length === 2) {
                        // 处理URL编码的参数
                        const value = decodeURIComponent(parts[1]);
                        result = parts[0] + param + '<span class="sql-param">' + value + '</span>';
                    }
                }
            }
            
            return result;
        }
    },
    methods: {
        handleClick(tab, event) {
            // console.log(tab, event);
        },
        fetchDataAndFillTable1() {
            getUserById({ id: '1' })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/mybatis/getUserById?id=1";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                    console.log(this.gridData);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable2() {
            getUserById({ id: '1 or 1=1' })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/mybatis/getUserById?id=1 or 1=1";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                    console.log(this.gridData);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable3() {
            getUserByIdSec({ id: '1 or 1=1' })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/mybatis/getUserByIdSec?username=zhangsan' or 'f'='f";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data;
                    console.log(this.gridData);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable4() {
            // 从localStorage获取token
            // const token = localStorage.getItem('token');
            getUserByPage({ page: 1, pageSize: 5, orderBy: 'username' })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/mybatis/getUserByPage?page=1&pageSize=5&orderBy=username";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data.rows;
                    console.log(this.gridData);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable5() {
            getUserByPage({ page: 1, pageSize: 5, orderBy: "(CASE WHEN (select substr((select database()),1,1)='a') THEN username ELSE id END)" })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/mybatis/getUserByPage?page=1&pageSize=5&orderBy=(CASE+WHEN+(select+substr((select+database()),1,1)='a')+THEN+username+ELSE+id+END)";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data.rows;
                    console.log(this.gridData);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        },
        fetchDataAndFillTable6() {
            getUserSecByUsername2({ username: "zhangsan' or 'f'='f" })
                .then(response => {
                    this.pocUrl = "http://127.0.0.1:8080/sqli/mybatis/getUserSecByUsername2?username=zhangsan' or 'f'='f";
                    this.dialogTableVisible = true; // 显示对话框
                    this.gridData = response.data.rows;
                    console.log(this.gridData);
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

.sql-param {
    color: red;
    font-weight: bold;
}
</style>