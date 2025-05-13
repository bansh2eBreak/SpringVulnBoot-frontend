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
 * a base page that does not have permission requirements
 * all roles can be accessed
 */
export const constantRoutes = [
  {
    path: '/login',
    component: () => import('@/views/login/index'),
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

  {
    path: '/sqli',
    component: Layout,
    redirect: '/sqli/jdbc',
    name: 'sqli',
    meta: { title: 'Sql注入', icon: 'el-icon-s-help' },
    children: [
      {
        path: 'jdbc',
        name: 'Jdbc类型',
        component: () => import('@/views/sqli/Jdbc'),
        meta: { title: 'Jdbc类型', icon: 'table' }
      },
      {
        path: 'mybatis',
        name: 'Mybatis类型',
        component: () => import('@/views/sqli/Mybatis'),
        meta: { title: 'Mybatis类型', icon: 'tree' }
      }
    ]
  },

  {
    path: '/xss',
    component: Layout,
    redirect: '/xss/reflected',
    name: 'xss',
    meta: { title: 'XSS跨站脚本', icon: 'el-icon-s-help' },
    children: [
      {
        path: 'reflected',
        name: '反射型',
        component: () => import('@/views/xss/Reflected'),
        meta: { title: '反射型', icon: 'table' }
      },
      {
        path: 'stored',
        name: '存储型',
        component: () => import('@/views/xss/Stored'),
        meta: { title: '存储型', icon: 'tree' }
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
        meta: { title: '任意命令执行', icon: 'el-icon-s-help' }
      }
    ]
  },

  {
    path: '/accessControl',
    component: Layout,
    redirect: '/accessControl/HorizontalPriVuln',
    name: 'accessControl',
    meta: { title: '权限漏洞', icon: 'el-icon-s-help' },
    children: [
      {
        path: 'horizontalPriVuln',
        name: 'Horizontal Privilege Escalation',
        component: () => import('@/views/accessControl/HorizontalPriVuln'),
        meta: { title: '水平越权漏洞', icon: 'table' }
      },
      {
        path: 'verticalPriVuln',
        name: 'Vertical Privilege Escalation',
        component: () => import('@/views/accessControl/VerticalPriVuln'),
        meta: { title: '垂直越权漏洞', icon: 'tree' }
      },
      {
        path: 'unauthorized',
        name: 'Unauthorized',
        component: () => import('@/views/accessControl/UnauthorizedPriVuln'),
        meta: { title: '未授权访问漏洞', icon: 'tree' }
      }
    ]
  },

  {
    path: '/openUrl',
    component: Layout,
    children: [
      {
        path: 'openUrl',
        name: 'openUrl',
        component: () => import('@/views/openUrl/OpenUrl'),
        meta: { title: '任意URL跳转', icon: 'el-icon-s-help' }
      }
    ]
  },

  {
    path: '/authentication',
    component: Layout,
    redirect: '/authentication/passwordBased',
    name: 'authentication',
    meta: { title: '身份认证漏洞', icon: 'el-icon-s-help' },
    children: [
      {
        path: 'passwordBased',
        name: 'password-based authentication',
        component: () => import('@/views/authentication/passwordBased'),
        meta: { title: '密码登录漏洞', icon: 'table' }
      },
      {
        path: '2faBased',
        name: 'multi-factor authentication',
        component: () => import('@/views/authentication/mfaBased'),
        meta: { title: 'MFA登录漏洞', icon: 'tree' }
      },
      {
        path: 'smsBased',
        name: 'sms-based authentication',
        component: () => import('@/views/authentication/smsBased'),
        meta: { title: '短信验证码漏洞', icon: 'tree' }
      }
    ]
  },

  {
    path: '/pathtraversal',
    component: Layout,
    children: [
      {
        path: '',
        name: 'pathtraversal',
        component: () => import('@/views/pathtraversal/index'),
        meta: { title: '路径穿越漏洞', icon: 'el-icon-s-help' }
      }
    ]
  },

  {
    path: '/fileupload',
    component: Layout,
    children: [
      {
        path: '',
        name: 'fileupload',
        component: () => import('@/views/fileupload/index'),
        meta: { title: '文件上传漏洞', icon: 'el-icon-s-help' }
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
      icon: 'nested'
    },
    children: [
      {
        path: 'fastjson',
        component: () => import('@/views/components/fastjson/index'),
        name: 'fastjson',
        meta: { title: 'Fastjson漏洞' }
      },
      {
        path: 'log4j2',
        component: () => import('@/views/components/log4j2/index'),
        name: 'log4j2',
        meta: { title: 'Log4j2漏洞' }
      }
    ]
  },
  {
    path: 'external-link',
    component: Layout,
    children: [
      {
        path: 'https://panjiachen.github.io/vue-element-admin-site/#/',
        meta: { title: 'External Link', icon: 'link' }
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
