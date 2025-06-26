// File: middlewares/risk-assessment.js
const { instance: historyStore } = require('./history-store');
const RiskEngine = require('../src/risk/engine');

// 检查导入的 historyStore 实例
console.log('[risk-assessment] historyStore 类型:', typeof historyStore);
console.log('[risk-assessment] historyStore 方法检查:', {
  getTotalLoginCount: typeof historyStore?.getTotalLoginCount,
  getGlobalFeatureStats: typeof historyStore?.getGlobalFeatureStats,
  users: historyStore?.users ? '已初始化' : '未定义'
});

// 创建 RiskEngine 实例
const riskEngine = new RiskEngine(historyStore);
const config = require('../src/risk/config.js'); // 导入项目内的config.js

/**
 * 生成合理的RTT随机值
 * @returns {number} 20-300ms之间的随机RTT值
 */
function generateRandomRTT() {
  // 生成20ms到300ms之间的随机值，模拟真实网络环境
  const minRTT = 20;  // 最小RTT值(ms)
  const maxRTT = 300; // 最大RTT值(ms)
  return Math.floor(Math.random() * (maxRTT - minRTT + 1)) + minRTT;
}

module.exports = async (req, res, next) => {
  console.log('====== 进入风险检查中间件 ======');

  // 仅在登录路由执行
  if (req.path !== '/login') {
    console.log('[跳过] 非 /login 请求');
    return next();
  }

  // 添加前置检查防止重复执行
  if (req.riskChecked) {
    return next();
  }
  req.riskChecked = true;

  console.log('请求体内容:', JSON.stringify(req.body)); // 关键日志：检查客户端发送的数据
  console.log('req.user 状态:', req.user ? `已认证 (用户ID: ${req.user.id})` : '未认证');

  if (!req.user || !req.user.id) {
    console.error('[错误] 未授权：req.user 不存在或缺少 id');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  //const engine = new RiskEngine(historyStore);
  console.log('RiskEngine 初始化完成');

  // 计算或生成RTT值
  let rttValue;
  if (!req._startTime || req.ip === '::1' || req.ip === '127.0.0.1') {
    // 本地环境或无法获取准确RTT时，生成随机RTT
    rttValue = generateRandomRTT();
    console.log(`[本地环境] 生成随机RTT值: ${rttValue}ms`);
  } else {
    // 正常计算RTT
    rttValue = Date.now() - req._startTime;
  }

  const features = {
    ip: req.ip,
    ua: req.get('User-Agent'),
    rtt: rttValue
  };
  console.log('提取的特征参数:', features); // 关键日志：检查传入 RiskEngine 的参数

  try {
    console.log('开始计算风险评分...');
    const riskResult = await riskEngine.calculate(req.user.id, features); // 返回对象 { score: number, action: string }

    // 正确提取风险评分
    const riskScore = (riskResult?.score ?? 1.0).toFixed(4); // 添加空值校验和默认值
    const action = riskResult.action;
    try {
      // 添加日志记录条件判断
      if (!req.headers['x-risk-logged']) { // 新增唯一标识检查
        await historyStore.logRiskEvent({
          user_id: req.user.id,
          ip_address: req.clientInfo.ip,
          user_agent: req.clientInfo.userAgent,
          //rtt: req.rtt,
          rtt: rttValue,
          geo_data: riskEngine.parseIP(req.clientInfo.ip),
          risk_score: riskScore
        });
        req.headers['x-risk-logged'] = 'true'; // 标记已记录
      }
    } catch (err) {
      console.error('[风险日志记录失败]', err);
    }

    console.log(`风险评分结果: ${riskScore}, 处置动作: ${action}`);

    if (action === 'REJECT') {
      console.log(`[阻断] 高风险访问 (分数: ${riskScore})`);
      return res.status(403).json({
        error: '高风险访问',
        score: parseFloat(riskScore), // 转为数字类型
        action: action
      });
    } else if (action === 'CHALLENGE') {
      console.log(`[需要2FA] 中等风险 (分数: ${riskScore})`);
      return res.redirect('/verify-2fa'); // 重定向到 2FA 页面
    }

    console.log(`[通过] 风险检查 (分数: ${riskScore})`);
    next();
  } catch (err) {
    console.error('风险评估异常:', err);
    return res.status(500).json({ error: '风险评估失败' });
  }
};