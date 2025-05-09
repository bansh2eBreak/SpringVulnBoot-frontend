/**
 * 解析JWT token
 * @param {string} token JWT token
 * @returns {object} 解析后的token数据
 */
export function parseJwt(token) {
    try {
        // JWT token由三部分组成，用.分隔，我们只需要第二部分（payload）
        const base64Url = token.split('.')[1];
        // 将base64Url转换为base64
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        // 解码base64
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error('JWT解析错误:', error);
        return null;
    }
} 