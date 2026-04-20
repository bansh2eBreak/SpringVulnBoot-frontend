import request from '@/utils/request'

/**
 * 执行 GraphQL 查询
 * @param {Object} data - 查询数据
 * @param {string} data.query - GraphQL 查询语句
 * @param {Object} data.variables - 查询变量（可选）
 */
export function executeGraphQL(data) {
  return request({
    url: '/api/graphql',
    method: 'post',
    data: {
      query: data.query,
      variables: data.variables || {}
    }
  })
}

/**
 * 执行 Introspection 查询（获取 Schema）
 */
export function introspectionQuery() {
  const query = `
    query IntrospectionQuery {
      __schema {
        types {
          name
          fields {
            name
            type {
              name
              kind
            }
          }
        }
      }
    }
  `
  
  return executeGraphQL({ query })
}

/**
 * 查询单个用户（包含敏感字段）
 * 使用 variables 传参，符合 GraphQL 规范并避免拼接风险
 * @param {number|string} userId - 用户ID
 */
export function getUserWithSensitiveFields(userId) {
  const query = `
    query GetUser($id: ID!) {
      user(id: $id) {
        id
        username
        email
        role
        salary
        ssn
        internalNotes
      }
    }
  `
  return executeGraphQL({ query, variables: { id: String(userId) } })
}

/**
 * 安全版：查询单个用户（敏感字段受字段级权限保护）
 * 演示：即使知道字段名，普通用户也无法获取敏感数据（返回 null + errors: Forbidden）
 * @param {number|string} userId - 用户ID
 */
export function getSecureUser(userId) {
  const query = `
    query GetSecureUser($id: ID!) {
      secureUser(id: $id) {
        id
        username
        email
        role
        salary
        ssn
        internalNotes
      }
    }
  `
  return executeGraphQL({ query, variables: { id: String(userId) } })
}

/**
 * IDOR 漏洞版：直接使用客户端传入的 id 查询用户信息
 * 服务端不验证该 id 是否属于当前登录用户，任何人可查任何人的数据
 * @param {number|string} targetUserId - 目标用户ID（攻击者可任意指定）
 */
export function myProfile(targetUserId) {
  const query = `
    query MyProfile($id: ID!) {
      myProfile(id: $id) {
        id
        username
        email
        role
        salary
        ssn
        internalNotes
      }
    }
  `
  return executeGraphQL({ query, variables: { id: String(targetUserId) } })
}

/**
 * IDOR 安全版：同样接受 id 参数，但服务端会校验该 id 必须与 JWT 中的当前用户一致
 * 不一致时返回 errors: "无权访问：只能查询自己的数据"
 * @param {number|string} targetUserId - 请求查询的用户ID
 */
export function secureMyProfile(targetUserId) {
  const query = `
    query SecureMyProfile($id: ID!) {
      secureMyProfile(id: $id) {
        id
        username
        email
        role
        salary
        ssn
        internalNotes
      }
    }
  `
  return executeGraphQL({ query, variables: { id: String(targetUserId) } })
}

/**
 * SQL注入-漏洞版：keyword 直接拼接到 SQL（后端使用 ${} 拼接）
 * @param {string} keyword - 搜索关键词（可注入）
 */
export function searchUsers(keyword) {
  const query = `
    query {
      searchUsers(keyword: "${keyword}") {
        id
        username
        email
        role
        salary
        ssn
        internalNotes
      }
    }
  `
  return executeGraphQL({ query })
}

/**
 * SQL注入-安全版：参数化查询，防止注入（后端使用 #{} 参数化）
 * @param {string} keyword - 搜索关键词
 */
export function secureSearchUsers(keyword) {
  const query = `
    query SearchUsers($keyword: String!) {
      secureSearchUsers(keyword: $keyword) {
        id
        username
        email
        role
        salary
        ssn
        internalNotes
      }
    }
  `
  return executeGraphQL({ query, variables: { keyword } })
}

