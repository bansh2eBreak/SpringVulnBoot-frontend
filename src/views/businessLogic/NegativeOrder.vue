<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">业务逻辑漏洞 -- 负数下单</div>
      <div class="body-div">
        <el-tabs v-model="activeName">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              电商下单时，<strong>购买数量必须是大于 0 的整数</strong>。如果后端只根据 <code>单价 × 数量</code> 计算订单金额，却遗漏了数量下限校验，攻击者就能把 <code>quantity</code> 改为 <code>-1</code>。<br><br>
              <span style="color: red;">负数为何会让余额增加？</span><br>
              本课服务端商品单价为 <code>199.00</code> 元，账户余额为 <code>1000.00</code> 元。攻击者提交 <code>quantity = -1</code> 后：<br>
              <pre class="inline-code">订单金额 = 199.00 × (-1) = -199.00
扣款后余额 = 1000.00 - (-199.00) = 1199.00</pre>
              <strong>负数订单金额没有被拒绝，常规“扣减余额”公式反而变成了加钱。</strong><br><br>
              <span style="color: red;">漏洞根因：服务端把数量当作可信的业务参数</span><br>
              前端输入框设置最小值只能改善正常用户体验；攻击者可通过 Burp Suite、脚本或浏览器开发者工具直接构造请求。<strong>数量上下限必须由服务端校验。</strong>
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              <span style="color: red;">主要危害：</span><br>
              • <strong>余额被刷高</strong>：负数订单绕过扣款，攻击者可反复增加钱包余额、积分或预付卡额度；<br>
              • <strong>财务损失</strong>：攻击者用异常增加的余额购买真实商品、提现或兑换权益；<br>
              • <strong>订单与账务对账异常</strong>：订单数量、订单金额或支付流水出现负值，退款、售后和财务统计被污染；<br>
              • <strong>连带业务绕过</strong>：同类缺陷也常出现在积分兑换、购物车更新、优惠抵扣、库存增减和运费计算。<br><br>
              <span style="color: red;">常见误区：</span><br>
              “前端已经限制最少买 1 件”并不是安全控制。任何来自 HTTP 请求的数量、价格、优惠、地址和状态，都必须视为不可信输入。
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】服务端校验数量为正整数</span><br>
              在所有计算金额、扣余额、扣库存之前，服务端必须拒绝 <code>quantity &lt; 1</code>、超出业务上限或格式异常的请求。<br><br>
              <span style="color: red;">【必须】价格与金额由服务端计算</span><br>
              前端只提交商品标识和数量；商品单价、优惠资格和订单总额必须由服务端权威数据计算。本课固定商品单价为服务端常量，接口不接收 <code>price</code> 或 <code>totalAmount</code>。<br><br>
              <span style="color: red;">【必须】扣余额使用事务和条件更新</span><br>
              使用 <code>BigDecimal</code> 计算金额；同一事务中以 <code>UPDATE ... WHERE balance &gt;= amount</code> 扣款并写订单。余额不足时更新行数为 0，订单不得落库。<br><br>
              <span style="color: red;">【纵深防御】数据库约束</span><br>
              生产系统应在安全订单表增加 <code>CHECK (quantity &gt; 0)</code>。本靶场让漏洞与安全场景共用一张教学订单表，以保留负数订单作为漏洞证据，因此安全性由安全接口的服务端校验保证。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP Input Validation Cheat Sheet》</a>：服务端输入验证原则。<br>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP Transaction Authorization Cheat Sheet》</a>：交易类业务规则与授权校验。<br>
              <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/math/BigDecimal.html" target="_blank" style="text-decoration: underline;">《Java BigDecimal》</a>：货币金额精确计算。
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>

    <div class="code-demo">
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              正常下单流程（数量为正）
              <el-button type="primary" round size="mini" @click="normalVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 正常下单：数量合法且余额充足才允许创建订单。
 */
@Transactional
public OrderResult order(Integer userId, int quantity) {
    if (quantity &lt; 1 || quantity &gt; 99) {
        return OrderResult.fail("购买数量必须是 1 至 99");
    }
    BigDecimal total = UNIT_PRICE.multiply(
        BigDecimal.valueOf(quantity));
    if (deductIfEnough(userId, total) != 1) {
        return OrderResult.fail("余额不足");
    }
    return createOrder(quantity, total);
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 — 缺少数量下限校验
              <el-button type="danger" round size="mini" @click="vulnVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * ❌ 只校验数量上限，遗漏 quantity 必须大于 0。
 */
@Transactional
public OrderResult orderVuln(Integer userId, int quantity) {
    if (quantity &gt; 99 || quantity &lt; -99) {
        return OrderResult.fail("数量超出范围");
    }
    BigDecimal total = UNIT_PRICE.multiply(
        BigDecimal.valueOf(quantity));
    // quantity=-1 时：balance - (-199) = balance + 199
    if (balanceMapper.deductIfEnough(userId, total) != 1) {
        return OrderResult.fail("余额不足");
    }
    return createOrder(quantity, total);
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 — 服务端严格校验数量
              <el-button type="success" round size="mini" @click="secVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * ✅ 数量校验在金额计算和余额扣减之前完成。
 */
@Transactional
public OrderResult orderSec(Integer userId, int quantity) {
    if (quantity &lt; 1 || quantity &gt; 99) {
        return OrderResult.fail("购买数量必须是 1 至 99");
    }
    BigDecimal total = UNIT_PRICE.multiply(
        BigDecimal.valueOf(quantity));
    if (deductIfEnough(userId, total) != 1) {
        return OrderResult.fail("余额不足");
    }
    return createOrder(quantity, total);
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-dialog :visible.sync="normalVisible" width="800px" :show-close="true" :close-on-click-modal="true" @open="loadStatus('normal')">
      <div slot="title" class="dialog-title">正常下单流程（正数数量）</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 说明</h3>
          <el-alert title="当前靶场管理员就是本次测试账户" type="info" :closable="false" show-icon>
            <div class="alert-detail">
              <p><strong>商品：</strong>演示蓝牙耳机，服务端单价 199.00 元</p>
              <p><strong>初始余额：</strong>1000.00 元。重置会清空当前账户的负数下单演示订单并恢复余额。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>2. 正常购买</h3>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-input-number v-model="normalQuantity" :min="1" :max="99" :disabled="normalLoading" />
            <el-button type="primary" :loading="normalLoading" @click="placeOrder('normal', normalQuantity)">正常下单</el-button>
          </div>
          <div v-if="normalResult" class="result-box">
            <el-alert :title="normalResult.ordered ? '下单成功' : '下单被拒绝'" :description="normalResult.message" :type="normalResult.ordered ? 'success' : 'warning'" :closable="false" show-icon />
          </div>
        </div>
        <div class="test-section status-section">
          <h3>3. 当前账户与订单记录</h3>
          <p class="balance-text">当前账户余额：<strong>{{ formatMoney(normalStatus.balance) }}</strong> 元</p>
          <p class="section-tip">当前账户订单记录：{{ normalStatus.orderCount }} 条</p>
          <el-table v-if="normalStatus.orders.length" :data="normalStatus.orders" size="mini" border>
            <el-table-column prop="orderNo" label="订单号" min-width="180" />
            <el-table-column prop="quantity" label="数量" width="70" />
            <el-table-column label="订单金额" width="110">
              <template slot-scope="scope">{{ formatMoney(scope.row.totalAmount) }}</template>
            </el-table-column>
            <el-table-column prop="createdAt" label="创建时间" width="170" />
          </el-table>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="vulnVisible" width="800px" :show-close="true" :close-on-click-modal="true" @open="loadStatus('vuln')">
      <div slot="title" class="dialog-title">负数下单漏洞测试</div>
      <div class="test-container">
        <div class="test-section">
          <h3>攻击步骤说明</h3>
          <el-alert title="前端限制不会阻止攻击者直接修改请求体" type="warning" :closable="false" show-icon>
            <div class="alert-detail">
              <p><strong>第 1 步：</strong>重置当前测试账户，确认初始余额是 1000.00 元。</p>
              <p><strong>第 2 步：</strong>正常购买 1 件，观察余额按 199.00 元扣减。</p>
              <p><strong>第 3 步：</strong>将请求中的 <code>quantity</code> 改为 <code>-1</code> 并提交。</p>
              <p><strong>第 4 步：</strong>查看负数订单金额和增加后的余额。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>1. 正常请求与恶意请求</h3>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="primary" :loading="vulnLoading" @click="placeOrder('vuln', 1)">正常购买 1 件</el-button>
            <el-button type="danger" :loading="vulnLoading" @click="placeOrder('vuln', -1)">篡改 quantity 为 -1</el-button>
          </div>
          <div class="request-example">{{ vulnRequest }}</div>
          <div v-if="vulnResult" class="result-box">
            <el-alert :title="vulnResult.ordered ? '接口接受了该订单' : '下单被拒绝'" :description="vulnResult.message" :type="vulnResult.ordered ? 'error' : 'warning'" :closable="false" show-icon />
          </div>
        </div>
        <div v-if="vulnResult && vulnResult.order && vulnResult.order.quantity < 0" class="result-box">
          <el-alert title="漏洞复现成功" :description="'数量为 ' + vulnResult.order.quantity + '，订单金额为 ' + formatMoney(vulnResult.order.totalAmount) + ' 元；当前账户余额已变为 ' + formatMoney(vulnResult.balance) + ' 元。'" type="error" :closable="false" show-icon />
        </div>
        <div class="test-section status-section">
          <h3>2. 当前账户与订单记录</h3>
          <p class="balance-text">当前账户余额：<strong>{{ formatMoney(vulnStatus.balance) }}</strong> 元</p>
          <p class="section-tip">当前账户订单记录：{{ vulnStatus.orderCount }} 条</p>
          <el-table v-if="vulnStatus.orders.length" :data="vulnStatus.orders" size="mini" border>
            <el-table-column prop="orderNo" label="订单号" min-width="180" />
            <el-table-column prop="quantity" label="数量" width="70" />
            <el-table-column label="订单金额" width="110">
              <template slot-scope="scope">{{ formatMoney(scope.row.totalAmount) }}</template>
            </el-table-column>
            <el-table-column prop="createdAt" label="创建时间" width="170" />
          </el-table>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="secVisible" width="800px" :show-close="true" :close-on-click-modal="true" @open="loadStatus('sec')">
      <div slot="title" class="dialog-title">安全代码测试 — 拒绝负数数量</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 安全控制点</h3>
          <el-alert title="数量校验必须在服务端、金额计算之前执行" type="success" :closable="false" show-icon>
            <div class="alert-detail">
              <p>安全接口只接受 1 至 99 的整数。</p>
              <p>提交 <code>-1</code> 时会直接拒绝，不写订单，不扣减或增加余额。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>2. 对比测试</h3>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="danger" :loading="secLoading" @click="placeOrder('sec', -1)">提交 quantity = -1</el-button>
            <el-button type="success" :loading="secLoading" @click="placeOrder('sec', 1)">正常购买 1 件</el-button>
          </div>
          <div class="request-example">{{ secRequest }}</div>
          <div v-if="secResult" class="result-box">
            <el-alert :title="secResult.ordered ? '下单成功' : '安全校验已拒绝'" :description="secResult.message" :type="secResult.ordered ? 'success' : 'success'" :closable="false" show-icon />
          </div>
        </div>
        <div v-if="secResult && !secResult.ordered" class="result-box">
          <el-alert title="安全校验通过" description="负数数量没有进入金额计算、余额扣减或订单写入流程。" type="success" :closable="false" show-icon />
        </div>
        <div class="test-section status-section">
          <h3>3. 当前账户与订单记录</h3>
          <p class="balance-text">当前账户余额：<strong>{{ formatMoney(secStatus.balance) }}</strong> 元</p>
          <p class="section-tip">当前账户订单记录：{{ secStatus.orderCount }} 条</p>
          <el-table v-if="secStatus.orders.length" :data="secStatus.orders" size="mini" border>
            <el-table-column prop="orderNo" label="订单号" min-width="180" />
            <el-table-column prop="quantity" label="数量" width="70" />
            <el-table-column label="订单金额" width="110">
              <template slot-scope="scope">{{ formatMoney(scope.row.totalAmount) }}</template>
            </el-table-column>
            <el-table-column prop="createdAt" label="创建时间" width="170" />
          </el-table>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import {
  negativeOrderStatusNormal,
  negativeOrderStatusSec,
  negativeOrderStatusVuln,
  orderNormal,
  orderSec,
  orderVuln,
  resetNegativeOrder
} from '@/api/negativeOrder'

const emptyStatus = () => ({
  balance: 0,
  orderCount: 0,
  orders: []
})

export default {
  name: 'NegativeOrder',
  data() {
    return {
      activeName: 'first',
      normalVisible: false,
      vulnVisible: false,
      secVisible: false,
      resetting: false,
      normalLoading: false,
      vulnLoading: false,
      secLoading: false,
      normalQuantity: 1,
      normalResult: null,
      vulnResult: null,
      secResult: null,
      normalStatus: emptyStatus(),
      vulnStatus: emptyStatus(),
      secStatus: emptyStatus(),
      vulnRequest: 'POST /businessLogic/negativeOrder/vuln/order\nAuthorization: <当前靶场管理员 JWT>\nContent-Type: application/json\n\n{"quantity":-1}',
      secRequest: 'POST /businessLogic/negativeOrder/sec/order\nAuthorization: <当前靶场管理员 JWT>\nContent-Type: application/json\n\n{"quantity":-1}'
    }
  },
  methods: {
    async resetAll() {
      this.resetting = true
      try {
        await resetNegativeOrder()
        this.normalResult = null
        this.vulnResult = null
        this.secResult = null
        await Promise.all([this.loadStatus('normal'), this.loadStatus('vuln'), this.loadStatus('sec')])
      } finally {
        this.resetting = false
      }
    },
    async placeOrder(scene, quantity) {
      const api = {
        normal: orderNormal,
        vuln: orderVuln,
        sec: orderSec
      }[scene]
      const loadingKey = scene + 'Loading'
      this[loadingKey] = true
      try {
        const res = await api(quantity)
        this[scene + 'Result'] = res.data
        await this.loadStatus(scene)
      } finally {
        this[loadingKey] = false
      }
    },
    async loadStatus(scene) {
      const api = {
        normal: negativeOrderStatusNormal,
        vuln: negativeOrderStatusVuln,
        sec: negativeOrderStatusSec
      }[scene]
      const res = await api()
      this[scene + 'Status'] = res.data
    },
    formatMoney(value) {
      return Number(value || 0).toFixed(2)
    }
  }
}
</script>

<style scoped>
.vuln-info { border-radius: 10px; margin: 10px 20px 20px; }
.header-div { font-size: 24px; color: #409EFF; font-weight: bold; padding: 10px; border-bottom: 1px solid #ccc; }
.body-div { padding: 10px; font-size: 14px; }
.vuln-detail { background-color: #dce9f8; padding: 10px; line-height: 1.7; }
.inline-code { background: #f5f5f5; border-radius: 4px; color: #333; margin: 8px 0; padding: 10px; }
.code-demo { margin: 20px; border-top: 1px solid #ccc; padding-top: 20px; }
pre code { font-size: 12px; }
.el-row { margin-bottom: 20px; }
.el-col { border-radius: 4px; }
.bg-purple { background: #d3dce6; }
.grid-content { border-radius: 4px; height: 100%; padding: 10px; }
.grid-flex { display: flex; align-items: stretch; }
.dialog-title { font-size: 18px; text-align: center; }
.test-container { padding: 20px; }
.test-section { background-color: #fafafa; border: 1px solid #e4e7ed; border-radius: 8px; margin-bottom: 30px; padding: 20px; }
.test-section h3 { color: #409EFF; font-size: 16px; margin-bottom: 15px; margin-top: 0; }
.alert-detail { line-height: 1.8; text-align: left; }
.section-tip { color: #606266; font-size: 13px; line-height: 1.7; margin: 0 0 12px; }
.test-buttons { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }
.result-box { margin-top: 15px; }
.request-example { background: #282c34; border-radius: 4px; color: #d7dae0; font: 12px/1.6 Consolas, monospace; margin-top: 15px; padding: 12px; white-space: pre-wrap; }
.status-section { margin-bottom: 0; }
.balance-text { color: #303133; margin: 0 0 8px; }
.balance-text strong { color: #f56c6c; font-size: 18px; }
</style>
