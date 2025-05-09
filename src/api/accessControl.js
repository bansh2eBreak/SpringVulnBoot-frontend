import request from '@/utils/request'
import { getToken } from '@/utils/auth'
import { parseJwt } from '@/utils/jwt'

// 获取当前登录用户ID
export function getCurrentUserId() {
    const token = getToken()
    if (token) {
        const decoded = parseJwt(token)
        return decoded.id
    }
    return null
}

// 水平越权查询他人MFA接口
export function getMfaVuln(userId) {
    return request({
        url: `/accessControl/HorizontalPri/vuln1/${userId}`,
        method: 'get'
    })
}

// 防水平越权查询他人MFA接口
export function getMfaSafe(userId) {
    return request({
        url: `/accessControl/HorizontalPri/sec1/${userId}`,
        method: 'get'
    })
}
