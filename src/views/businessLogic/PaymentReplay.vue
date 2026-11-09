<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">业务逻辑漏洞 -- 支付回调重复处理</div>
      <div class="body-div">
        <el-tabs v-model="activeName">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              支付平台会因为网络超时、商户响应丢失或补偿任务，对<strong>同一笔成功交易重复发送回调</strong>。重复回调是正常现象；商户必须保证同一业务事件只会产生一次余额入账、发货或发券等副作用。<br><br>
              本课创建一笔服务端固定金额 <code>100.00</code> 元的充值订单，并用同一交易号重复模拟支付成功回调。漏洞版每次回调都执行余额增加；安全版只允许订单从 <code>PENDING</code> 原子转换为 <code>PAID</code> 一次。<br><br>
              <span style="color: #e6a23c; font-weight: bold;">注意：</span>本页以当前 JWT 模拟支付网关已完成签名、商户号和金额校验；真实支付回调还必须在服务端验证网关签名，不能信任浏览器提交的数据。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              • <strong>充值重复到账</strong>：同一笔真实支付被多次记入钱包余额；<br>
              • <strong>权益重复发放</strong>：会员积分、优惠券、抽奖次数可被重复增加；<br>
              • <strong>重复履约</strong>：相同订单被重复发货或重复开通服务；<br>
              • <strong>财务对账异常</strong>：订单金额、支付流水和账户余额无法一一对应。<br><br>
              该漏洞不依赖并发。相同回调即使按顺序到达，只要每次都执行副作用，仍会造成资金损失。
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】将状态转换作为幂等开关</span><br>
              使用 <code>UPDATE ... WHERE status = 'PENDING'</code> 原子更新订单状态。只有影响行数为 1 的首次回调可以执行余额入账。<br><br>
              <span style="color: red;">【必须】回调校验与订单入账在同一事务</span><br>
              验签、订单金额比对、状态更新和余额入账应在服务端完成；状态改为已支付但入账失败时必须一起回滚。<br><br>
              <span style="color: red;">【必须】重复回调返回成功确认</span><br>
              同一交易号的重复回调应被识别并返回成功确认，但不重复执行业务副作用；交易号不一致则应标记为异常。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP Transaction Authorization Cheat Sheet》</a>：交易状态与幂等控制。<br>
              <a href="https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/transaction/annotation/Transactional.html" target="_blank" style="text-decoration: underline;">《Spring Transactional》</a>：事务边界与回滚语义。
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
              正常支付回调（单次到账）
              <el-button type="primary" round size="mini" @click="normalVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@Transactional
public CallbackResult notify(PaymentCallback callback) {
    RechargeOrder order = verify(callback);
    if (markPaidIfPending(order, callback) != 1) {
        return CallbackResult.ignored("重复回调已确认");
    }
    creditBalance(order.getUserId(), order.getAmount());
    return CallbackResult.success("充值到账");
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 — 每次回调都入账
              <el-button type="danger" round size="mini" @click="vulnVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@Transactional
public CallbackResult notifyVuln(PaymentCallback callback) {
    RechargeOrder order = verify(callback);
    markPaid(order, callback); // 已 PAID 仍会继续执行
    // ❌ 同一交易号重复回调，仍重复增加余额
    creditBalance(order.getUserId(), order.getAmount());
    return CallbackResult.success("充值到账");
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 — 原子状态转换
              <el-button type="success" round size="mini" @click="secVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">@Transactional
public CallbackResult notifySecure(PaymentCallback callback) {
    RechargeOrder order = verify(callback);
    int changed = markPaidIfPending(order, callback);
    if (changed != 1) {
        return CallbackResult.ignored("重复回调已确认");
    }
    // ✅ 只有首次 PENDING → PAID 才入账
    creditBalance(order.getUserId(), order.getAmount());
    return CallbackResult.success("充值到账");
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-dialog :visible.sync="normalVisible" width="800px" @open="loadStatus">
      <div slot="title" class="dialog-title">正常支付回调（单次到账）</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 创建订单并发送一次回调</h3>
          <p class="section-tip">服务端创建 100.00 元充值订单。重置会清空本课程订单并恢复共享演示余额。</p>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="primary" :loading="normalLoading" @click="createOrder('normal')">创建充值订单</el-button>
            <el-button type="primary" :loading="normalLoading" :disabled="!orders.normal" @click="notifyOnce('normal')">发送成功回调</el-button>
          </div>
          <div v-if="orders.normal" class="request-example">{{ orderDescription(orders.normal) }}</div>
          <div v-if="results.normal.length" class="callback-results">
            <el-alert v-for="(result, index) in results.normal" :key="index" :title="'第 ' + (index + 1) + ' 次回调：' + result.message" :description="'本次入账 ' + result.creditedAmount + ' 元'" :type="result.duplicateIgnored ? 'warning' : 'success'" :closable="false" show-icon />
          </div>
        </div>
        <div class="test-section status-section">
          <h3>2. 当前账户与充值订单</h3>
          <p class="balance-text">当前账户余额：<strong>{{ money(status.balance) }}</strong> 元</p>
          <p class="section-tip">当前账户充值订单：{{ status.orderCount }} 条</p>
          <el-table v-if="status.orders.length" :data="status.orders" size="mini" border>
            <el-table-column prop="rechargeNo" label="商户订单号" min-width="180" />
            <el-table-column label="充值金额" width="110"><template slot-scope="scope">{{ money(scope.row.amount) }}</template></el-table-column>
            <el-table-column prop="status" label="状态" width="100" />
            <el-table-column prop="gatewayTransactionNo" label="网关交易号" min-width="180" />
            <el-table-column prop="paidAt" label="支付时间" width="170" />
          </el-table>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="vulnVisible" width="800px" @open="loadStatus">
      <div slot="title" class="dialog-title">支付回调重复处理漏洞测试</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 使用同一交易号重复发送回调</h3>
          <p class="section-tip">第二次请求与第一次使用完全相同的充值订单号和网关交易号。漏洞版会对两次请求都执行余额入账。</p>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="primary" :loading="vulnLoading" @click="createOrder('vuln')">创建充值订单</el-button>
            <el-button type="danger" :loading="vulnLoading" :disabled="!orders.vuln" @click="replayTwice('vuln')">同一回调发送两次</el-button>
          </div>
          <div v-if="orders.vuln" class="request-example">{{ orderDescription(orders.vuln) }}</div>
          <div v-if="results.vuln.length" class="callback-results">
            <el-alert v-for="(result, index) in results.vuln" :key="index" :title="'第 ' + (index + 1) + ' 次回调：' + result.message" :description="'本次入账 ' + result.creditedAmount + ' 元'" :type="result.duplicateIgnored ? 'warning' : 'success'" :closable="false" show-icon />
          </div>
        </div>
        <div v-if="results.vuln.length === 2 && results.vuln[0].accepted && results.vuln[1].accepted" class="result-box">
          <el-alert title="漏洞复现成功" :description="'同一笔 100.00 元充值被处理两次，当前余额为 ' + money(status.balance) + ' 元。'" type="error" :closable="false" show-icon />
        </div>
        <div class="test-section status-section">
          <h3>2. 当前账户与充值订单</h3>
          <p class="balance-text">当前账户余额：<strong>{{ money(status.balance) }}</strong> 元</p>
          <p class="section-tip">当前账户充值订单：{{ status.orderCount }} 条</p>
          <el-table v-if="status.orders.length" :data="status.orders" size="mini" border>
            <el-table-column prop="rechargeNo" label="商户订单号" min-width="180" />
            <el-table-column label="充值金额" width="110"><template slot-scope="scope">{{ money(scope.row.amount) }}</template></el-table-column>
            <el-table-column prop="status" label="状态" width="100" />
            <el-table-column prop="gatewayTransactionNo" label="网关交易号" min-width="180" />
            <el-table-column prop="paidAt" label="支付时间" width="170" />
          </el-table>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="secVisible" width="800px" @open="loadStatus">
      <div slot="title" class="dialog-title">安全代码测试 — 重复回调不重复入账</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 使用同一交易号重复发送回调</h3>
          <p class="section-tip">第一次回调完成入账；第二次回调被确认但不会再次修改余额。</p>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="primary" :loading="secLoading" @click="createOrder('sec')">创建充值订单</el-button>
            <el-button type="success" :loading="secLoading" :disabled="!orders.sec" @click="replayTwice('sec')">同一回调发送两次</el-button>
          </div>
          <div v-if="orders.sec" class="request-example">{{ orderDescription(orders.sec) }}</div>
          <div v-if="results.sec.length" class="callback-results">
            <el-alert v-for="(result, index) in results.sec" :key="index" :title="'第 ' + (index + 1) + ' 次回调：' + result.message" :description="'本次入账 ' + result.creditedAmount + ' 元'" :type="result.duplicateIgnored ? 'warning' : 'success'" :closable="false" show-icon />
          </div>
        </div>
        <div v-if="results.sec.length === 2 && results.sec[1].duplicateIgnored" class="result-box">
          <el-alert title="安全校验通过" :description="'第二次回调已被幂等忽略，当前余额为 ' + money(status.balance) + ' 元。'" type="success" :closable="false" show-icon />
        </div>
        <div class="test-section status-section">
          <h3>3. 当前账户与充值订单</h3>
          <p class="balance-text">当前账户余额：<strong>{{ money(status.balance) }}</strong> 元</p>
          <p class="section-tip">当前账户充值订单：{{ status.orderCount }} 条</p>
          <el-table v-if="status.orders.length" :data="status.orders" size="mini" border>
            <el-table-column prop="rechargeNo" label="商户订单号" min-width="180" />
            <el-table-column label="充值金额" width="110"><template slot-scope="scope">{{ money(scope.row.amount) }}</template></el-table-column>
            <el-table-column prop="status" label="状态" width="100" />
            <el-table-column prop="gatewayTransactionNo" label="网关交易号" min-width="180" />
            <el-table-column prop="paidAt" label="支付时间" width="170" />
          </el-table>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import {
  createRechargeOrder,
  notifyPayment,
  paymentReplayStatus,
  resetPaymentReplay
} from '@/api/paymentReplay'

const emptyStatus = () => ({
  balance: 0,
  orderCount: 0,
  orders: []
})

export default {
  name: 'PaymentReplay',
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
      orders: { normal: null, vuln: null, sec: null },
      results: { normal: [], vuln: [], sec: [] },
      status: emptyStatus()
    }
  },
  methods: {
    async resetAll() {
      this.resetting = true
      try {
        await resetPaymentReplay()
        this.orders = { normal: null, vuln: null, sec: null }
        this.results = { normal: [], vuln: [], sec: [] }
        await this.loadStatus()
      } finally {
        this.resetting = false
      }
    },
    async createOrder(mode) {
      this[mode + 'Loading'] = true
      try {
        const res = await createRechargeOrder()
        this.$set(this.orders, mode, res.data)
        this.$set(this.results, mode, [])
        await this.loadStatus()
      } finally {
        this[mode + 'Loading'] = false
      }
    },
    async notifyOnce(mode) {
      this[mode + 'Loading'] = true
      try {
        const res = await notifyPayment(mode, this.orders[mode])
        this.$set(this.results, mode, this.results[mode].concat(res.data))
        await this.loadStatus()
      } finally {
        this[mode + 'Loading'] = false
      }
    },
    async replayTwice(mode) {
      await this.notifyOnce(mode)
      await this.notifyOnce(mode)
    },
    async loadStatus() {
      const res = await paymentReplayStatus()
      this.status = res.data
    },
    money(value) {
      return Number(value || 0).toFixed(2)
    },
    orderDescription(order) {
      return '商户订单号：' + order.rechargeNo +
        '\n网关交易号：' + order.gatewayTransactionNo +
        '\n充值金额：' + order.amount + ' 元'
    }
  }
}
</script>

<style scoped>
.vuln-info { border-radius: 10px; margin: 10px 20px 20px; }
.header-div { font-size: 24px; color: #409EFF; font-weight: bold; padding: 10px; border-bottom: 1px solid #ccc; }
.body-div { padding: 10px; font-size: 14px; }
.vuln-detail { background-color: #dce9f8; padding: 10px; line-height: 1.7; }
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
.section-tip { color: #606266; font-size: 13px; line-height: 1.7; margin: 0 0 12px; }
.test-buttons { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }
.request-example { background: #282c34; border-radius: 4px; color: #d7dae0; font: 12px/1.6 Consolas, monospace; margin-top: 15px; padding: 12px; white-space: pre-wrap; }
.callback-results { margin-top: 15px; }
.callback-results .el-alert { margin-top: 8px; }
.result-box { margin: 15px 0; }
.status-section { margin-bottom: 0; }
.balance-text { color: #303133; margin: 0 0 8px; }
.balance-text strong { color: #f56c6c; font-size: 18px; }
</style>
