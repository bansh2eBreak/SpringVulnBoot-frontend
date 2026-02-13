import Vue from 'vue'
import Router from 'vue-router'

Vue.use(Router)

/* Layout */
import Layout from '@/layout'

/**
 * Note: sub-menu only appear when route children.length >= 1
 * Detail see: https://panjiachen.github.io/vue-element-admin-site/guide/essentials/router-and-nav.html
 *
 * hidden: true                   if set true, item will not show in the sidebar(default is false)
 * alwaysShow: true               if set true, will always show the root menu
 *                                if not set alwaysShow, when item has more than one children route,
 *                                it will becomes nested mode, otherwise not show the root menu
 * redirect: noRedirect           if set noRedirect will no redirect in the breadcrumb
 * name:'router-name'             the name is used by <keep-alive> (must set!!!)
 * meta : {
    roles: ['admin','editor']    control the page roles (you can set multiple roles)
    title: 'title'               the name show in sidebar and breadcrumb (recommend set)
    icon: 'svg-name'/'el-icon-x' the icon show in the sidebar
    breadcrumb: false            if set false, the item will hidden in breadcrumb(default is true)
    activeMenu: '/example/list'  if set path, the sidebar will highlight the path you set
  }
 */

/**
 * constantRoutes
 * 无需权限的公共路由，guest 和 admin 都可以访问
 */
export const constantRoutes = [
  {
    path: '/login',
    component: () => import('@/views/login/index'),
    hidden: true
  },

  {
    path: '/register',
    component: () => import('@/views/register/index'),
    hidden: true
  },

  {
    path: '/404',
    component: () => import('@/views/404'),
    hidden: true
  },

  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    children: [{
      path: 'dashboard',
      name: 'Dashboard',
      component: () => import('@/views/dashboard/index'),
      meta: { title: 'Dashboard', icon: 'dashboard' }
    }]
  },

  // ========== guest 可访问的基础漏洞（3个） ==========
  
  {
    path: '/sqli',
    component: Layout,
    redirect: '/sqli/jdbc',
    name: 'sqli',
    meta: { title: 'Sql注入', icon: 'el-icon-s-platform' },
    children: [
      {
        path: 'jdbc',
        name: 'Jdbc类型',
        component: () => import('@/views/sqli/Jdbc'),
        meta: { title: 'Jdbc类型', icon: 'el-icon-connection' }
      },
      {
        path: 'mybatis',
        name: 'Mybatis类型',
        component: () => import('@/views/sqli/Mybatis'),
        meta: { title: 'Mybatis类型', icon: 'el-icon-document' }
      },
      {
        path: 'orderByInjection',
        name: 'ORDER BY注入',
        component: () => import('@/views/sqli/OrderByInjection'),
        meta: { title: 'ORDER BY注入', icon: 'el-icon-sort' }
      },
      {
        path: 'errorInjection',
        name: '报错注入',
        component: () => import('@/views/sqli/ErrorInjection'),
        meta: { title: '报错注入', icon: 'el-icon-warning' }
      },
      {
        path: 'timeBased',
        name: '时间盲注',
        component: () => import('@/views/sqli/TimeBased'),
        meta: { title: '时间盲注', icon: 'el-icon-time' }
      },
      {
        path: 'booleanBlind',
        name: '布尔盲注',
        component: () => import('@/views/sqli/BooleanBlind'),
        meta: { title: '布尔盲注', icon: 'el-icon-view' }
      },
      {
        path: 'unionInjection',
        name: '联合注入',
        component: () => import('@/views/sqli/UnionInjection'),
        meta: { title: '联合注入', icon: 'el-icon-files' }
      },
      {
        path: 'secondOrder',
        name: '二次注入',
        component: () => import('@/views/sqli/SecondOrder'),
        meta: { title: '二次注入', icon: 'el-icon-refresh-right' }
      }
    ]
  },

  {
    path: '/xss',
    component: Layout,
    redirect: '/xss/reflected',
    name: 'xss',
    meta: { title: 'XSS跨站脚本', icon: 'el-icon-s-flag' },
    children: [
      {
        path: 'reflected',
        name: '反射型',
        component: () => import('@/views/xss/Reflected'),
        meta: { title: '反射型', icon: 'el-icon-refresh' }
      },
      {
        path: 'stored',
        name: '存储型',
        component: () => import('@/views/xss/Stored'),
        meta: { title: '存储型', icon: 'el-icon-folder' }
      },
      {
        path: 'dom',
        name: 'DOM型',
        component: () => import('@/views/xss/Dom'),
        meta: { title: 'DOM型', icon: 'el-icon-s-operation' }
      }
    ]
  },

  {
    path: '/cmd',
    component: Layout,
    children: [
      {
        path: 'exec',
        name: 'CmdExec',
        component: () => import('@/views/cmdexec/CmdExec'),
        meta: { title: '任意命令执行', icon: 'el-icon-s-tools' }
      }
    ]
  },

  {
    path: '/mass-assignment',
    component: Layout,
    children: [
      {
        path: 'index',
        name: 'MassAssignment',
        component: () => import('@/views/massAssignment/index'),
        meta: { title: '批量赋值漏洞', icon: 'el-icon-edit-outline' }
      }
    ]
  }
]

/**
 * asyncRoutes
 * 需要根据用户角色动态加载的路由
 * 只有 admin 角色可以访问以下页面
 */
export const asyncRoutes = [
  // ========== admin 专属漏洞页面 ==========
  
  {
    path: '/csrf',
    component: Layout,
    meta: { roles: ['admin'] },
    children: [
      {
        path: '',
        name: 'csrf',
        component: () => import('@/views/csrf/index'),
        meta: { title: 'CSRF漏洞', icon: 'el-icon-s-claim', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/ssrf',
    component: Layout,
    meta: { roles: ['admin'] },
    children: [
      {
        path: 'index',
        name: 'SSRF',
        component: () => import('@/views/ssrf/index'),
        meta: { title: 'SSRF漏洞', icon: 'el-icon-s-opportunity', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/accessControl',
    component: Layout,
    redirect: '/accessControl/HorizontalPriVuln',
    name: 'accessControl',
    meta: { title: '权限漏洞', icon: 'el-icon-lock', roles: ['admin'] },
    children: [
      {
        path: 'horizontalPriVuln',
        name: 'Horizontal Privilege Escalation',
        component: () => import('@/views/accessControl/HorizontalPriVuln'),
        meta: { title: '水平越权漏洞', icon: 'el-icon-sort', roles: ['admin'] }
      },
      {
        path: 'verticalPriVuln',
        name: 'Vertical Privilege Escalation',
        component: () => import('@/views/accessControl/VerticalPriVuln'),
        meta: { title: '垂直越权漏洞', icon: 'el-icon-sort-up', roles: ['admin'] }
      },
      {
        path: 'unauthorized',
        name: 'Unauthorized',
        component: () => import('@/views/accessControl/UnauthorizedPriVuln'),
        meta: { title: '未授权访问漏洞', icon: 'el-icon-warning', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/openUrl',
    component: Layout,
    meta: { roles: ['admin'] },
    children: [
      {
        path: 'openUrl',
        name: 'openUrl',
        component: () => import('@/views/openUrl/OpenUrl'),
        meta: { title: '任意URL跳转', icon: 'el-icon-s-promotion', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/authentication',
    component: Layout,
    redirect: '/authentication/passwordBased',
    name: 'authentication',
    meta: { title: '身份认证漏洞', icon: 'el-icon-s-custom', roles: ['admin'] },
    children: [
      {
        path: 'passwordBased',
        name: 'password-based authentication',
        component: () => import('@/views/authentication/passwordBased'),
        meta: { title: '密码登录漏洞', icon: 'el-icon-key', roles: ['admin'] }
      },
      {
        path: '2faBased',
        name: 'multi-factor authentication',
        component: () => import('@/views/authentication/mfaBased'),
        meta: { title: 'MFA认证漏洞', icon: 'el-icon-mobile', roles: ['admin'] }
      },
      {
        path: 'smsBased',
        name: 'sms-based authentication',
        component: () => import('@/views/authentication/smsBased'),
        meta: { title: '短信验证码漏洞', icon: 'el-icon-message', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/jwt',
    component: Layout,
    redirect: '/jwt/weakPassword',
    name: 'jwt',
    meta: { title: 'JWT安全漏洞', icon: 'el-icon-key', roles: ['admin'] },
    children: [
      {
        path: 'weakPassword',
        component: () => import('@/views/jwt/WeakPassword'),
        name: 'JWT弱密码',
        meta: { title: 'JWT弱密码', icon: 'el-icon-warning', roles: ['admin'] }
      },
      {
        path: 'sensitiveInfo',
        component: () => import('@/views/jwt/SensitiveInfo'),
        name: 'JWT存储敏感信息',
        meta: { title: 'JWT存储敏感信息', icon: 'el-icon-document', roles: ['admin'] }
      },
      {
        path: 'signatureVuln',
        component: () => import('@/views/jwt/SignatureVuln'),
        name: 'JWT None算法漏洞',
        meta: { title: 'JWT None算法漏洞', icon: 'el-icon-s-check', roles: ['admin'] }
      },
      {
        path: 'algorithmConfusion',
        component: () => import('@/views/jwt/AlgorithmConfusion'),
        name: 'JWT 算法混淆漏洞',
        meta: { title: 'JWT 算法混淆漏洞', icon: 'el-icon-lock', roles: ['admin'] }
      },
    ]
  },

  {
    path: '/pathtraversal',
    component: Layout,
    meta: { roles: ['admin'] },
    children: [
      {
        path: '',
        name: 'pathtraversal',
        component: () => import('@/views/pathtraversal/index'),
        meta: { title: '路径穿越漏洞', icon: 'el-icon-s-management', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/fileupload',
    component: Layout,
    meta: { roles: ['admin'] },
    children: [
      {
        path: '',
        name: 'fileupload',
        component: () => import('@/views/fileupload/index'),
        meta: { title: '文件上传漏洞', icon: 'el-icon-upload2', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/fileInclusion',
    component: Layout,
    meta: { roles: ['admin'] },
    children: [
      {
        path: '',
        name: 'FileInclusion',
        component: () => import('@/views/file-inclusion/index'),
        meta: { title: '文件包含漏洞', icon: 'el-icon-document-copy', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/deserialize',
    component: Layout,
    meta: { roles: ['admin'] },
    children: [
      {
        path: '',
        name: 'deserialize',
        component: () => import('@/views/deserialize/index'),
        meta: { title: '反序列化漏洞', icon: 'el-icon-s-data', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/xml',
    component: Layout,
    redirect: '/xml/xxe',
    name: 'xmlVuln',
    meta: {
      title: 'XML安全漏洞',
      icon: 'el-icon-document',
      roles: ['admin']
    },
    children: [
      {
        path: 'xxe',
        component: () => import('@/views/xml/xxe/index'),
        name: 'XML外部实体注入',
        meta: { title: 'XML外部实体注入', icon: 'el-icon-warning', roles: ['admin'] }
      },
      {
        path: 'xpath',
        component: () => import('@/views/xml/xpath/index'),
        name: 'XPath注入',
        meta: { title: 'XPath注入', icon: 'el-icon-connection', roles: ['admin'] }
      },
      {
        path: 'bomb',
        component: () => import('@/views/xml/bomb/index'),
        name: 'XML炸弹',
        meta: { title: 'XML炸弹', icon: 'el-icon-warning-outline', roles: ['admin'] }
      },
      {
        path: 'xxe-ssrf',
        component: () => import('@/views/xml/xxe-ssrf/index'),
        name: 'SSRF via XXE',
        meta: { title: 'SSRF via XXE', icon: 'el-icon-connection', roles: ['admin'] }
      },
      {
        path: 'xinclude',
        component: () => import('@/views/xml/xinclude/index'),
        name: 'XInclude注入',
        meta: { title: 'XInclude注入', icon: 'el-icon-document', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/components',
    component: Layout,
    redirect: '/components/fastjson',
    name: 'components',
    meta: {
      title: '组件漏洞',
      icon: 'el-icon-s-platform',
      roles: ['admin']
    },
    children: [
      {
        path: 'fastjson',
        component: () => import('@/views/components/fastjson/index'),
        name: 'fastjson',
        meta: { title: 'Fastjson漏洞', icon: 'el-icon-s-data', roles: ['admin'] }
      },
      {
        path: 'log4j2',
        component: () => import('@/views/components/log4j2/index'),
        name: 'log4j2',
        meta: { title: 'Log4j2漏洞', icon: 'el-icon-notebook-2', roles: ['admin'] }
      },
      {
        path: 'snakeyaml',
        component: () => import('@/views/components/snakeyaml/index'),
        name: 'snakeyaml',
        meta: { title: 'SnakeYAML漏洞', icon: 'el-icon-s-order', roles: ['admin'] }
      },
      {
        path: 'xmldecoder',
        component: () => import('@/views/components/xmldecoder/index'),
        name: 'xmldecoder',
        meta: { title: 'XMLDecoder漏洞', icon: 'el-icon-s-marketing', roles: ['admin'] }
      },
      {
        path: 'shiro',
        component: () => import('@/views/components/shiro/index'),
        name: 'shiro',
        meta: { title: 'Shiro-550漏洞', icon: 'el-icon-s-check', roles: ['admin'] }
      },
      {
        path: 'xstream',
        component: () => import('@/views/components/xstream/index'),
        name: 'xstream',
        meta: { title: 'XStream漏洞', icon: 'el-icon-s-operation', roles: ['admin'] }
      },
      {
        path: 'jackson',
        component: () => import('@/views/components/jackson/index'),
        name: 'jackson',
        meta: { title: 'Jackson漏洞', icon: 'el-icon-s-data', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/configVuln',
    component: Layout,
    redirect: '/configVuln/dirlist',
    name: 'configVuln',
    meta: {
      title: '配置漏洞',
      icon: 'el-icon-s-tools',
      roles: ['admin']
    },
    children: [
      {
        path: 'dirlist',
        component: () => import('@/views/configVuln/dirlist/index'),
        name: '列目录漏洞',
        meta: { title: '列目录漏洞', icon: 'el-icon-folder-opened', roles: ['admin'] }
      },
      {
        path: 'actuator',
        component: () => import('@/views/configVuln/actuator/index'),
        name: 'Actuator未授权',
        meta: { title: 'Actuator未授权', icon: 'el-icon-monitor', roles: ['admin'] }
      },
      {
        path: 'swagger',
        component: () => import('@/views/configVuln/swagger/index.vue'),
        name: 'Swagger未授权',
        meta: { title: 'Swagger未授权', icon: 'el-icon-document', roles: ['admin'] }
      }
    ]
  },

  {
    path: '/otherVuln',
    component: Layout,
    redirect: '/otherVuln/redos',
    name: 'otherVuln',
    meta: {
      title: '其他漏洞',
      icon: 'el-icon-plus',
      roles: ['admin']
    },
    children: [
      {
        path: 'redos',
        component: () => import('@/views/otherVuln/redos/index'),
        name: '正则拒绝服务漏洞',
        meta: { title: '正则拒绝服务漏洞', icon: 'el-icon-close', roles: ['admin'] }
      },
      {
        path: 'scientificNotationDoS',
        component: () => import('@/views/otherVuln/scientificNotationDoS/index'),
        name: '科学计数法DoS',
        meta: { title: '科学计数法DoS', icon: 'el-icon-warning', roles: ['admin'] }
      },
      {
        path: 'ldapInjection',
        component: () => import('@/views/otherVuln/ldapInjection/index'),
        name: 'LDAP注入',
        meta: { title: 'LDAP注入', icon: 'el-icon-user', roles: ['admin'] }
      },
      {
        path: 'ipspoofing',
        component: () => import('@/views/otherVuln/ipspoofing/index'),
        name: 'IP地址伪造',
        meta: { title: 'IP地址伪造', icon: 'el-icon-connection', roles: ['admin'] }
      },
      {
        path: 'spel',
        component: () => import('@/views/otherVuln/spel/index'),
        name: 'SpEL表达式注入',
        meta: { title: 'SpEL表达式注入', icon: 'el-icon-s-operation', roles: ['admin'] }
      }
    ]
  },

  // 外部链接（所有用户都可以访问）
  {
    path: '/external-link',
    component: Layout,
    meta: { roles: ['guest', 'admin'] },
    children: [
      {
        path: 'https://github.com/bansh2eBreak/SpringVulnBoot-backend',
        meta: { title: 'External Link', icon: 'link', roles: ['guest', 'admin'] }
      }
    ]
  },
  
  // 404 page must be placed at the end !!!
  { path: '*', redirect: '/404', hidden: true }
]

const createRouter = () => new Router({
  // mode: 'history', // require service support
  scrollBehavior: () => ({ y: 0 }),
  routes: constantRoutes
})

const router = createRouter()

// Detail see: https://github.com/vuejs/vue-router/issues/1234#issuecomment-357941465
export function resetRouter() {
  const newRouter = createRouter()
  router.matcher = newRouter.matcher // reset router
}

export default router
