import request from '@/utils/request'

// ==================== DocumentBuilder 解析器 ====================

/**
 * DocumentBuilder - 漏洞接口
 */
export function xxeVulnerable(data) {
  return request({
    url: '/xml/xxe/vuln',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

/**
 * DocumentBuilder - 安全接口
 */
export function xxeSecure(data) {
  return request({
    url: '/xml/xxe/sec',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

// ==================== SAXParser 解析器 ====================

/**
 * SAXParser - 漏洞接口
 */
export function saxVulnerable(data) {
  return request({
    url: '/xml/xxe/sax/vuln',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

/**
 * SAXParser - 安全接口
 */
export function saxSecure(data) {
  return request({
    url: '/xml/xxe/sax/sec',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

// ==================== XMLStreamReader (StAX) 解析器 ====================

/**
 * XMLStreamReader - 漏洞接口
 */
export function staxVulnerable(data) {
  return request({
    url: '/xml/xxe/stax/vuln',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

/**
 * XMLStreamReader - 安全接口
 */
export function staxSecure(data) {
  return request({
    url: '/xml/xxe/stax/sec',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

// ==================== Unmarshaller (JAXB) 解析器 ====================

/**
 * Unmarshaller - 漏洞接口
 */
export function jaxbVulnerable(data) {
  return request({
    url: '/xml/xxe/jaxb/vuln',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

/**
 * Unmarshaller - 安全接口
 */
export function jaxbSecure(data) {
  return request({
    url: '/xml/xxe/jaxb/sec',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

// ==================== SAXReader (dom4j) 解析器 ====================

/**
 * SAXReader - 漏洞接口
 */
export function dom4jVulnerable(data) {
  return request({
    url: '/xml/xxe/dom4j/vuln',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

/**
 * SAXReader - 安全接口
 */
export function dom4jSecure(data) {
  return request({
    url: '/xml/xxe/dom4j/sec',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

// ==================== TransformerFactory (XSLT) 解析器 ====================

/**
 * TransformerFactory - 漏洞接口
 */
export function xsltVulnerable(data) {
  return request({
    url: '/xml/xxe/xslt/vuln',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

/**
 * TransformerFactory - 安全接口
 */
export function xsltSecure(data) {
  return request({
    url: '/xml/xxe/xslt/sec',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/xml'
    }
  })
}

// ==================== XPath注入漏洞 ====================

/**
 * XPath注入 - 登录验证漏洞接口
 */
export function xpathLoginVulnerable(data) {
  return request({
    url: '/xml/xpath/login/vuln',
    method: 'post',
    data: data
  })
}

/**
 * XPath注入 - 登录验证安全接口
 */
export function xpathLoginSecure(data) {
  return request({
    url: '/xml/xpath/login/sec',
    method: 'post',
    data: data
  })
}


