import { shiroLogin, shiroLogout, testPermission, testRole } from '@/api/shiro'

const state = {
  userInfo: {
    isAuthenticated: false,
    username: '',
    roles: []
  }
}

const mutations = {
  SET_USER_INFO: (state, userInfo) => {
    state.userInfo = userInfo
  },
  CLEAR_USER_INFO: (state) => {
    state.userInfo = {
      isAuthenticated: false,
      username: '',
      roles: []
    }
  }
}

const actions = {
  // Shiro登录
  login({ commit }, loginForm) {
    return new Promise((resolve, reject) => {
      shiroLogin(loginForm).then(response => {
        if (response.code === 0) {
          commit('SET_USER_INFO', response.data)
        }
        resolve(response)
      }).catch(error => {
        reject(error)
      })
    })
  },

  // Shiro登出
  logout({ commit }) {
    return new Promise((resolve, reject) => {
      shiroLogout().then(response => {
        commit('CLEAR_USER_INFO')
        resolve(response)
      }).catch(error => {
        // 即使登出失败，也清除本地状态
        commit('CLEAR_USER_INFO')
        reject(error)
      })
    })
  },

  // 测试权限
  testPermission({ commit }, permission) {
    return new Promise((resolve, reject) => {
      testPermission(permission).then(response => {
        resolve(response)
      }).catch(error => {
        reject(error)
      })
    })
  },

  // 测试角色
  testRole({ commit }, role) {
    return new Promise((resolve, reject) => {
      testRole(role).then(response => {
        resolve(response)
      }).catch(error => {
        reject(error)
      })
    })
  },


}

export default {
  namespaced: true,
  state,
  mutations,
  actions
} 