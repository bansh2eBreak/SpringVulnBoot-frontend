import { jwtWeakLogin, jwtWeakGetInfo, jwtSensitiveVulnLogin, jwtSignatureVulnLogin, jwtSignatureVulnGetInfo, jwtSignatureSecureLogin, jwtSignatureSecureGetInfo } from '@/api/jwt'

const getDefaultState = () => {
  return {
    jwt: localStorage.getItem('jwt') || '',
    name: '',
    avatar: '',
    username: ''
  }
}

const state = getDefaultState()

const mutations = {
  RESET_STATE: (state) => {
    Object.assign(state, getDefaultState())
  },
  SET_JWT: (state, jwt) => {
    state.jwt = jwt
  },
  SET_NAME: (state, name) => {
    state.name = name
  },
  SET_AVATAR: (state, avatar) => {
    state.avatar = avatar
  },
  SET_USERNAME: (state, username) => {
    state.username = username
  }
}

const actions = {
  // JWT弱密码漏洞登录
  jwtWeakLogin({ commit }, userInfo) {
    const { username, password } = userInfo
    return new Promise((resolve, reject) => {
      jwtWeakLogin({ username: username.trim(), password: password }).then(response => {
        const { data } = response
        commit('SET_JWT', data)
        commit('SET_USERNAME', username.trim())
        localStorage.setItem('jwt', data)
        resolve()
      }).catch(error => {
        reject(error)
      })
    })
  },

  // JWT弱密码漏洞获取用户信息
  jwtWeakGetInfo({ commit, state }) {
    return new Promise((resolve, reject) => {
      jwtWeakGetInfo().then(response => {
        const { data } = response

        if (!data) {
          return reject('Verification failed, please Login again.')
        }

        const { name, avatar, username } = data

        commit('SET_NAME', name)
        commit('SET_AVATAR', avatar)
        commit('SET_USERNAME', username)
        resolve(data)
      }).catch(error => {
        reject(error)
      })
    })
  },

  // JWT存储敏感信息漏洞登录
  jwtSensitiveLogin({ commit }, userInfo) {
    const { username, password } = userInfo
    return new Promise((resolve, reject) => {
      jwtSensitiveVulnLogin({ username: username.trim(), password: password }).then(response => {
        const { data } = response
        commit('SET_JWT', data)
        commit('SET_USERNAME', username.trim())
        localStorage.setItem('jwt', data)
        resolve()
      }).catch(error => {
        reject(error)
      })
    })
  },

  // JWT存储敏感信息漏洞获取用户信息
  jwtSensitiveGetInfo({ commit, state }) {
    return new Promise((resolve, reject) => {
      jwtSensitiveGetInfo().then(response => {
        const { data } = response

        if (!data) {
          return reject('Verification failed, please Login again.')
        }

        const { name, avatar, username } = data

        commit('SET_NAME', name)
        commit('SET_AVATAR', avatar)
        commit('SET_USERNAME', username)
        resolve(data)
      }).catch(error => {
        reject(error)
      })
    })
  },

  // JWT None算法漏洞登录
  jwtSignatureVulnLogin({ commit }, userInfo) {
    const { username, password } = userInfo
    return new Promise((resolve, reject) => {
      jwtSignatureVulnLogin({ username: username.trim(), password: password }).then(response => {
        const { data } = response
        commit('SET_JWT', data)
        commit('SET_USERNAME', username.trim())
        localStorage.setItem('jwt', data)
        resolve()
      }).catch(error => {
        reject(error)
      })
    })
  },

  // JWT None算法漏洞获取用户信息
  jwtSignatureVulnGetInfo({ commit, state }) {
    return new Promise((resolve, reject) => {
      jwtSignatureVulnGetInfo().then(response => {
        const { data } = response

        if (!data) {
          return reject('Verification failed, please Login again.')
        }

        const { name, avatar, username } = data

        commit('SET_NAME', name)
        commit('SET_AVATAR', avatar)
        commit('SET_USERNAME', username)
        resolve(data)
      }).catch(error => {
        reject(error)
      })
    })
  },

  // JWT安全签名登录
  jwtSignatureSecureLogin({ commit }, userInfo) {
    const { username, password } = userInfo
    return new Promise((resolve, reject) => {
      jwtSignatureSecureLogin({ username: username.trim(), password: password }).then(response => {
        const { data } = response
        commit('SET_JWT', data)
        commit('SET_USERNAME', username.trim())
        localStorage.setItem('jwt', data)
        resolve()
      }).catch(error => {
        reject(error)
      })
    })
  },

  // JWT安全签名获取用户信息
  jwtSignatureSecureGetInfo({ commit, state }) {
    return new Promise((resolve, reject) => {
      jwtSignatureSecureGetInfo().then(response => {
        const { data } = response

        if (!data) {
          return reject('Verification failed, please Login again.')
        }

        const { name, avatar, username } = data

        commit('SET_NAME', name)
        commit('SET_AVATAR', avatar)
        commit('SET_USERNAME', username)
        resolve(data)
      }).catch(error => {
        reject(error)
      })
    })
  },

  // 清除JWT token
  resetJwt({ commit }) {
    return new Promise(resolve => {
      localStorage.removeItem('jwt')
      commit('RESET_STATE')
      resolve()
    })
  }
}

export default {
  namespaced: true,
  state,
  mutations,
  actions
}
