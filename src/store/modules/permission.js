import { asyncRoutes, constantRoutes } from '@/router'

/**
 * 判断是否有权限访问该路由
 * @param roles 用户角色数组
 * @param route 路由对象
 */
function hasPermission(roles, route) {
  if (route.meta && route.meta.roles) {
    return roles.some(role => route.meta.roles.includes(role))
  } else {
    return true  // 没有设置roles，表示都可以访问
  }
}

/**
 * 根据角色过滤异步路由表
 * @param routes asyncRoutes
 * @param roles 用户角色数组
 */
export function filterAsyncRoutes(routes, roles) {
  const res = []

  routes.forEach(route => {
    const tmp = { ...route }
    if (hasPermission(roles, tmp)) {
      if (tmp.children) {
        tmp.children = filterAsyncRoutes(tmp.children, roles)
      }
      res.push(tmp)
    }
  })

  return res
}

const state = {
  routes: [],
  addRoutes: []
}

const mutations = {
  SET_ROUTES: (state, routes) => {
    state.addRoutes = routes
    state.routes = constantRoutes.concat(routes)
  }
}

const actions = {
  generateRoutes({ commit }, roles) {
    return new Promise(resolve => {
      let accessedRoutes
      if (roles.includes('admin')) {
        // admin 拥有所有权限
        accessedRoutes = asyncRoutes || []
      } else {
        // 根据角色过滤
        accessedRoutes = filterAsyncRoutes(asyncRoutes, roles)
      }
      
      commit('SET_ROUTES', accessedRoutes)
      resolve(accessedRoutes)
    })
  }
}

export default {
  namespaced: true,
  state,
  mutations,
  actions
}
