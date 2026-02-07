import request from '@/utils/request'

/**
 * Mass Assignment (批量赋值) 漏洞相关接口
 */

// 更新用户资料 - 漏洞版本（未使用 DTO，存在批量赋值风险）
export function updateProfileVuln(data) {
  return request({
    url: '/massAssignment/updateProfileVuln',
    method: 'post',
    data: data
  })
}

// 更新用户资料 - 安全版本（使用 DTO，只接收 avatar 字段）
export function updateProfileSec(data) {
  return request({
    url: '/massAssignment/updateProfileSec',
    method: 'post',
    data: data
  })
}
