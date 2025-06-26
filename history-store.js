// File: middlewares/history-store.js
const mysql = require('mysql2/promise');
const config = require('../src/risk/config.js');

class HistoryStore {


  constructor() {
    this.users = {}; // 显式初始化 ✅
    this.pool = mysql.createPool(config.database);
    // 初始化连接池（复用config中的数据库配置）
    // this.pool = mysql.createPool({
    //   ...config.database,
    //   namedPlaceholders: true, // 启用命名占位符
    //   timezone: '+00:00'      // 统一使用UTC时间
    // });
    this.cache = {
      users: {},       // 用户历史缓存
      globalStats: {   // 全局统计缓存
        totalLoginCount: 0,
        featureStats: {},
        totalStats: {}
      },
      lastUpdated: 0   // 最后更新时间戳
    };

  }
  async getGlobalFeatureStats() {
    if (Date.now() - this.cache.lastUpdated < 60000) { // 缓存1分钟
      return this.cache.globalStats.featureStats;
    }
    const stats = await this._getGlobalFeatureStats(); // 调用实际执行查询的方法
    this.cache.globalStats.featureStats = stats;
    this.cache.lastUpdated = Date.now();
    return stats;
  }

  /**
   * 记录风险分析结果
   * @param {Object} params - 参数对象
   * @param {string} params.user_id - 用户ID（对应数据库字段）
   * @param {string} params.ip_address - IP地址
   * @param {Object} params.geo_data - 地理数据对象
   * @param {number} params.risk_score - 风险评分
   * @returns {Promise<number>} 插入的记录ID
   */
  async logRiskEvent({ user_id, ip_address, geo_data, risk_score, user_agent, rtt }) {
    // 参数检查增强版
    const missingParams = [];
    const params = [
      { name: 'user_id', value: user_id },
      { name: 'ip_address', value: ip_address },
      { name: 'geo_data', value: geo_data },
      { name: 'risk_score', value: risk_score },
      { name: 'rtt', value: rtt }
    ];

    // 检查每个参数
    params.forEach(param => {
      if (!param.value) {
        missingParams.push(param.name);
        console.error(`[风险日志错误] 缺失参数检测: ${param.name}`, {
          eventType: "PARAM_MISSING",
          param: param.name,
          timestamp: new Date().toISOString()
        });
      }
    });

    // 如果有缺失参数则报错
    if (missingParams.length > 0) {
      throw new Error(`缺少必需的参数: ${missingParams.join(', ')}`);
    }

    const connection = await this.pool.getConnection();
    try {
      const [result] = await connection.execute(
        `INSERT INTO risk_logs 
        (user_id, ip_address, geo_data, risk_score, user_agent, rtt)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [user_id, ip_address, JSON.stringify(geo_data), risk_score, user_agent, rtt]
      );
      return result.insertId;
    } catch (error) {
      const transactionId = require('uuid').v4();
      const timestamp = new Date().toISOString();
      console.error(JSON.stringify({
        eventType: "DB_INSERT_ERROR",
        transactionId,
        timestamp,
        params: { user_id, ip_address, geo_data: geo_data ? '***' : null, risk_score, user_agent, rtt },
        error: {
          code: error.code,
          sqlState: error.sqlState,
          sqlMessage: error.sqlMessage.replace(/\d+/g, '?')
        },
        stack: error.stack,
        sql: `INSERT INTO risk_logs (user_id, ip_address, geo_data, risk_score, user_agent, rtt) VALUES (?, ?, ?, ?, ?, ?)`
      }, null, 2));
      this.handleDBError(error, '风险日志记录失败');
      throw error; // 确保错误被正确传播
    } finally {
      connection.release();
    }
  }




  /**
   * 获取用户风险历史（精确匹配用户ID和时间范围）
   * @param {string} user_id - 用户ID
   * @param {Object} [options] - 查询选项
   * @param {number} [options.hours=24] - 查询时间范围（小时）
   * @param {number} [options.limit=50] - 最大返回数量
   * @returns {Promise<Array>} 风险日志数组
   */
  async getRiskHistory(user_id, { hours = 24, limit = 50 } = {}) {
    const connection = await this.pool.getConnection();
    try {
      const [rows] = await connection.execute(
        `SELECT 
          id,
          ip_address AS ip,
          geo_data AS geo,
          risk_score AS score,
          created_at AS timestamp
        FROM risk_logs
        WHERE user_id = :user_id
          AND created_at >= NOW() - INTERVAL :hours HOUR
        ORDER BY created_at DESC
        LIMIT :limit`,
        { user_id, hours, limit }
      );

      return rows.map(row => ({
          ...row,
          geo: row.geo ? JSON.parse(row.geo) : null,
          timestamp: new Date(row.timestamp).toISOString()
        }));
    } catch (error) {
      this.handleDBError(error, '风险历史查询失败');
    } finally {
      connection.release();
    }
  }

  /**
   * 错误处理统一方法
   * @param {Error} error - 原始错误对象
   * @param {string} message - 自定义错误信息
   */
  handleDBError(error, message) {
    console.error(`[HistoryStore] ${message}:`, {
      code: error.code,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      stack: error.stack
    });
    throw new Error(`${message}（错误码：${error.code}）`);
  }

  /**
   * 关闭连接池（用于优雅退出）
   */
  async close() {
    await this.pool.end();
    console.log('[HistoryStore] 数据库连接池已关闭');
  }

  /**
  * 获取全局登录总次数
  * @returns {Promise<number>}
  */
  async getTotalLoginCount() {
    const connection = await this.pool.getConnection();
    try {
      const [rows] = await connection.execute(
        'SELECT COUNT(*) AS total FROM risk_logs'
      );
      return rows[0].total || 0;
    } catch (error) {
      this.handleDBError(error, '全局登录次数查询失败');
    } finally {
      connection.release();
    }
  }

  /**
   * 获取全局特征统计
   * @returns {Promise<Object>}
   */
  /**
   * 获取全局特征统计（内部实现）
   * @returns {Promise<Object>}
   * @private
   */
  async _getGlobalFeatureStats() {
    const connection = await this.pool.getConnection();
    try {
      // IP统计查询
      const [ipStats] = await connection.execute(
        `SELECT 
          ip_address AS feature, 
          COUNT(*) AS count 
        FROM risk_logs 
        GROUP BY ip_address`
      ) || [];

      // 新增：ASN和CC统计查询
      const [geoStats] = await connection.execute(
        `SELECT 
          JSON_EXTRACT(geo_data, '$.asn') AS asn,
          JSON_EXTRACT(geo_data, '$.cc') AS cc,
          COUNT(*) AS count
        FROM risk_logs 
        WHERE geo_data IS NOT NULL AND geo_data != '{}'
        GROUP BY JSON_EXTRACT(geo_data, '$.asn'), JSON_EXTRACT(geo_data, '$.cc')`
      ) || [];

      // UA统计查询
      const [uaRawStats] = await connection.execute(
        `SELECT 
          user_agent AS feature, 
          COUNT(*) AS count 
        FROM risk_logs 
        GROUP BY user_agent`
      ) || [];

      // 新增RTT统计查询
      const [rttStats] = await connection.execute(
        `SELECT 
            rtt AS feature,
            COUNT(*) AS count
        FROM risk_logs
        GROUP BY rtt`
      ) || [];

      // 处理UA统计数据
      const uaStats = this._processUAStats(uaRawStats);

      // 处理ASN和CC统计
      const asnStats = {};
      const ccStats = {};
      geoStats.forEach(row => {
        // 去除JSON字符串中的引号
        // 双重类型保护：先转为字符串再处理引号
        // 统一的安全处理方式
        const asn = String(row.asn ?? '').replace(/\"/g, '') || 'Unknown';
        const ccValue = String(row.cc ?? '').replace(/\"/g, '').trim();
        const cc = ccValue || 'XX';
        console.debug('[地理数据处理]', { rawAsn: row.asn, rawCc: row.cc, processed: { asn, cc } });

        asnStats[asn] = (asnStats[asn] || 0) + row.count;
        ccStats[cc] = (ccStats[cc] || 0) + row.count;
      });

      // 修复：将对象格式转换为数组格式
      const browsersArray = Object.entries(uaStats.browsers || {}).map(([name, count]) => ({ name, count }));
      const versionsArray = Object.entries(uaStats.versions || {}).map(([version, count]) => ({ version, count }));
      const osVersionsArray = Object.entries(uaStats.osVersions || {}).map(([os, count]) => ({ os, count }));
      const devicesArray = Object.entries(uaStats.devices || {}).map(([device, count]) => ({ device, count }));

      // 构建特征统计结构
      const featureStats = {
        ip: this._arrayToObject(Array.isArray(ipStats) ? ipStats : [], 'feature', 'count'),
        asn: asnStats,  // 新增ASN统计
        cc: ccStats,    // 新增CC统计
        ua: this._arrayToObject(browsersArray, 'name', 'count'),
        bv: this._arrayToObject(versionsArray, 'version', 'count'),
        osv: this._arrayToObject(osVersionsArray, 'os', 'count'),
        df: this._arrayToObject(devicesArray, 'device', 'count'),
        rtt: this._arrayToObject(rttStats, 'feature', 'count')
      };

      console.debug('[全局特征统计生成]', {
        ipCount: Object.keys(featureStats.ip).length,
        asnCount: Object.keys(featureStats.asn).length,
        ccCount: Object.keys(featureStats.cc).length,
        uaCount: Object.keys(featureStats.ua).length,
        bvCount: Object.keys(featureStats.bv).length,
        osvCount: Object.keys(featureStats.osv).length,
        dfCount: Object.keys(featureStats.df).length
      });

      return featureStats;
    } catch (error) {
      console.error('[全局特征统计失败]', error.stack);
      // 返回完整结构兜底
      return {
        ip: {},
        asn: {},  // 新增
        cc: {},   // 新增
        ua: {},
        bv: {},
        osv: {},
        df: {},
        rtt: {}
      };
    } finally {
      connection.release();
    }
  }

  // 新增：处理UA统计数据的辅助方法
  _processUAStats(uaRawStats) {
    const UAParser = require('ua-parser-js');
    const browsers = {};
    const versions = {};
    const osVersions = {};
    const devices = {};

    uaRawStats.forEach(item => {
      try {
        const parser = new UAParser(item.feature);
        const browser = parser.getBrowser();
        const os = parser.getOS();
        const device = parser.getDevice();

        // 浏览器名称统计
        const browserName = browser.name || 'Unknown';
        browsers[browserName] = (browsers[browserName] || 0) + item.count;

        // 浏览器版本统计
        const browserVersion = this._parseVersion(browser.version);
        versions[browserVersion] = (versions[browserVersion] || 0) + item.count;

        // 操作系统版本统计
        const osVersion = os.version || 'Unknown';
        osVersions[osVersion] = (osVersions[osVersion] || 0) + item.count;

        // 设备类型统计
        const deviceType = device.model ? device.model : 'desktop';
        devices[deviceType] = (devices[deviceType] || 0) + item.count;
      } catch (e) {
        console.error('UA解析失败:', e);
      }
    });

    return { browsers, versions, osVersions, devices };
  }

  // 辅助方法：解析版本号
  _parseVersion(version) {
    if (!version) return '0.0.0';
    return version.split('.').slice(0, 3).join('.');
  }

  // 辅助方法：将数组转换为对象
  _arrayToObject(array, keyField, valueField) {
    const result = {};

    // 添加类型检查，确保 array 是数组
    if (!Array.isArray(array)) {
      console.warn('[HistoryStore] _arrayToObject 接收到非数组参数:', {
        type: typeof array,
        value: array
      });
      return result; // 返回空对象
    }

    array.forEach(item => {
      result[item[keyField]] = item[valueField];
    });
    return result;
  }

  /**
   * 获取全局总计数
   * @param {boolean} forceRefresh 是否强制刷新缓存
   * @returns {Promise<Object>}
   */
  async getGlobalTotalStats(forceRefresh = false) {
    // 检查缓存
    if (!forceRefresh &&
      Date.now() - this.cache.lastUpdated < 60000 &&
      Object.keys(this.cache.globalStats.totalStats).length > 0) {
      return this.cache.globalStats.totalStats;
    }

    const connection = await this.pool.getConnection();
    try {
      // 获取总记录数
      const [total] = await connection.execute(
        `SELECT COUNT(*) AS total_records FROM risk_logs`
      );

      const totalRecords = total[0].total_records || 0;

      // 构建总计数对象 - 所有特征使用相同的总记录数
      const totalStats = {
        ip: totalRecords,
        ua: totalRecords,
        asn: totalRecords,
        cc: totalRecords,
        bv: totalRecords,
        osv: totalRecords,
        df: totalRecords,
        rtt: totalRecords
      };

      // 更新缓存
      this.cache.globalStats.totalStats = totalStats;
      this.cache.lastUpdated = Date.now();

      return totalStats;
    } catch (error) {
      this.handleDBError(error, '全局总计数查询失败');
      return {};
    } finally {
      connection.release();
    }
  }
  /**
  * 获取UA相关子特征的不同值数量
  * @returns {Promise<Object>}
  * @private
  */
  async _getUADistinctCounts() {
    const connection = await this.pool.getConnection();
    try {
      const [uaRawStats] = await connection.execute(
        `SELECT user_agent FROM risk_logs`
      );

      const UAParser = require('ua-parser-js');
      const versions = new Set();
      const osVersions = new Set();
      const devices = new Set();

      uaRawStats.forEach(row => {
        try {
          const parser = new UAParser(row.user_agent);
          const browser = parser.getBrowser();
          const os = parser.getOS();
          const device = parser.getDevice();

          // 收集不同的浏览器版本
          if (browser.version) {
            versions.add(this._parseVersion(browser.version));
          }

          // 收集不同的操作系统版本
          if (os.version) {
            osVersions.add(os.version);
          }

          // 收集不同的设备类型
          const deviceType = device.model ? device.model : 'desktop';
          devices.add(deviceType);
        } catch (e) {
          console.error('UA解析失败:', e);
        }
      });

      return {
        bv: versions.size,
        osv: osVersions.size,
        df: devices.size
      };
    } catch (error) {
      console.error('获取UA特征统计失败:', error);
      return { bv: 0, osv: 0, df: 0 };
    } finally {
      connection.release();
    }
  }
  /**
   * 初始化用户历史
   * @param {string} userId 用户ID或用户名
   * @param {boolean} forceRefresh 是否强制刷新缓存
   * @returns {Promise<Object>} 用户历史数据
   */
  async initializeUserHistory(userId, forceRefresh = false) {
    if (!userId) return null;

    // 如果已经在缓存中且不需要强制刷新，直接返回
    if (this.users[userId] && !forceRefresh) {
      console.log(`[HistoryStore] 用户历史已在缓存中: ${userId}`);
      return this.users[userId];
    }

    console.log(`[HistoryStore] 从数据库加载用户历史: ${userId}`);
    const connection = await this.pool.getConnection();
    try {
      // 检查是否为用户名而非用户ID
      let userIdForQuery = userId;
      let userIdForCache = userId;

      // 尝试从users.json文件中查找用户ID
      try {
        const fs = require('fs');
        const usersData = JSON.parse(fs.readFileSync('users.json', 'utf8'));

        // 如果输入的是用户名，查找对应的用户ID
        if (isNaN(userId) || userId.length < 10) {
          const user = usersData.find(u => u.username === userId);
          if (user && user.id) {
            userIdForQuery = user.id;
            console.log(`[HistoryStore] 用户名 ${userId} 映射到用户ID: ${userIdForQuery}`);
            userIdForCache = userIdForQuery; // 使用用户ID作为缓存键
          }
        }
        // 如果输入的是用户ID，也记录用户名用于日志
        else {
          const user = usersData.find(u => u.id === userId);
          if (user && user.username) {
            console.log(`[HistoryStore] 用户ID ${userId} 对应用户名: ${user.username}`);
          }
        }
      } catch (err) {
        console.error('[HistoryStore] 读取users.json失败:', err);
        // 继续使用原始userId
      }

      // 获取登录次数
      const [loginCountResult] = await connection.execute(
        `SELECT COUNT(*) AS loginCount 
        FROM risk_logs 
        WHERE user_id = ?`,
        [userIdForQuery]
      );

      const loginCount = loginCountResult[0].loginCount || 0;
      console.log(`[HistoryStore] 用户 ${userIdForQuery} 登录次数: ${loginCount}`);

      // 获取IP统计
      const [ipStatsResult] = await connection.execute(
        `SELECT 
          ip_address AS ip,
          COUNT(*) AS count
        FROM risk_logs 
        WHERE user_id = ?
        GROUP BY ip_address`,
        [userIdForQuery]
      );

      // 获取UA统计
      const [uaStatsResult] = await connection.execute(
        `SELECT 
          user_agent AS ua,
          COUNT(*) AS count
        FROM risk_logs 
        WHERE user_id = ?
        GROUP BY user_agent`,
        [userIdForQuery]
      );

      // 获取地理位置数据统计
      const [geoStatsResult] = await connection.execute(
        `SELECT 
          JSON_EXTRACT(geo_data, '$.asn') AS asn,
          JSON_EXTRACT(geo_data, '$.cc') AS cc,
          COUNT(*) AS count
        FROM risk_logs 
        WHERE user_id = ? AND geo_data IS NOT NULL AND geo_data != '{}'
        GROUP BY JSON_EXTRACT(geo_data, '$.asn'), JSON_EXTRACT(geo_data, '$.cc')`,
        [userIdForQuery]
      );

      console.log(`[HistoryStore] 用户 ${userIdForQuery} 统计结果:`, {
        ipCount: ipStatsResult.length,
        uaCount: uaStatsResult.length,
        geoCount: geoStatsResult.length
      });

      // 转换为需要的结构
      const ipStats = ipStatsResult.reduce((acc, row) => {
        acc[row.ip] = row.count;
        return acc;
      }, {});

      // 处理UA统计 - 修复：确保UA数据正确转换
      const uaRawStats = uaStatsResult.map(row => ({ feature: row.ua, count: row.count }));
      const uaStats = this._processUAStats(uaRawStats);

      // 修复：将对象格式转换为数组格式，以便_arrayToObject方法可以正确处理
      const browsersArray = Object.entries(uaStats.browsers || {}).map(([name, count]) => ({ name, count }));
      const versionsArray = Object.entries(uaStats.versions || {}).map(([version, count]) => ({ version, count }));
      const osVersionsArray = Object.entries(uaStats.osVersions || {}).map(([os, count]) => ({ os, count }));
      const devicesArray = Object.entries(uaStats.devices || {}).map(([device, count]) => ({ device, count }));

      // 处理地理位置统计
      const asnStats = {};
      const ccStats = {};
      geoStatsResult.forEach(row => {
        // 安全处理可能为null或非字符串的值
        // 双重类型保护和空值处理
        const asn = String(row.asn ?? '').replace(/\"/g, '') || 'Unknown';
        const cc = String(row.cc ?? '').replace(/\"/g, '') || 'XX';

        asnStats[asn] = (asnStats[asn] || 0) + row.count;
        ccStats[cc] = (ccStats[cc] || 0) + row.count;
      });

      // 构建UA相关特征对象 - 使用转换后的数组
      const uaFeatures = this._arrayToObject(browsersArray, 'name', 'count');
      const bvFeatures = this._arrayToObject(versionsArray, 'version', 'count');
      const osvFeatures = this._arrayToObject(osVersionsArray, 'os', 'count');
      const dfFeatures = this._arrayToObject(devicesArray, 'device', 'count');


      // 新增用户RTT统计查询
      const [rttStatsResult] = await connection.execute(
        `SELECT 
            rtt AS feature,
            COUNT(*) AS count
        FROM risk_logs 
        WHERE user_id = ?
        GROUP BY rtt`,
        [userIdForQuery]
      );

      // 处理RTT统计数据
      const rttStats = rttStatsResult.reduce((acc, row) => {
        acc[row.feature] = row.count;
        return acc;
      }, {});

      // 使用正确的用户ID作为缓存键
      this.users[userIdForCache] = {
        loginCount: loginCount,
        features: {
          ip: ipStats,
          ua: uaFeatures,
          bv: bvFeatures,
          osv: osvFeatures,
          df: dfFeatures,
          asn: asnStats,
          cc: ccStats,
          rtt: rttStats
        },
        total: {
          ip: ipStatsResult.length || 0,
          ua: uaStatsResult.length || 0,
          asn: Object.keys(asnStats).length || 0,
          cc: Object.keys(ccStats).length || 0,
          bv: Object.keys(bvFeatures).length || 0,
          osv: Object.keys(osvFeatures).length || 0,
          df: Object.keys(dfFeatures).length || 0,
          rtt: rttStatsResult.length || 0
        }
      };

      // 同时在用户名和用户ID下都缓存相同的数据（如果它们不同）
      if (userId !== userIdForCache) {
        this.users[userId] = this.users[userIdForCache];
      }

      console.log(`[HistoryStore] 用户历史加载成功: ${userIdForCache}`, {
        loginCount: this.users[userIdForCache].loginCount,
        ipCount: Object.keys(this.users[userIdForCache].features.ip).length,
        uaCount: Object.keys(this.users[userIdForCache].features.ua).length,
        asnCount: Object.keys(this.users[userIdForCache].features.asn).length,
        ccCount: Object.keys(this.users[userIdForCache].features.cc).length
      });

      return this.users[userIdForCache];
    } catch (error) {
      console.error(`[HistoryStore] 用户历史初始化失败: ${userId}`, error);
      // 返回默认结构，防止后续代码出错
      this.users[userId] = {
        loginCount: 0,
        features: { ip: {}, ua: {}, bv: {}, osv: {}, df: {}, asn: {}, cc: {} },
        total: { ip: 0, ua: 0, asn: 0, cc: 0, bv: 0, osv: 0, df: 0, rtt: 0 }
      };
      return this.users[userId];
    } finally {
      connection.release();
    }
  }

  /**
   * 清除用户缓存
   * @param {string} userId - 可选，特定用户ID。如果不提供，则清除所有用户缓存
   */
  clearUserCache(userId = null) {
    if (userId) {
      delete this.users[userId];
      console.log(`[HistoryStore] 已清除用户缓存: ${userId}`);
    } else {
      this.users = {};
      console.log('[HistoryStore] 已清除所有用户缓存');
    }
  }

  /**
   * 清除全局统计缓存
   */
  clearGlobalCache() {
    this.cache.globalStats = {
      totalLoginCount: 0,
      featureStats: {},
      totalStats: {}
    };
    this.cache.lastUpdated = 0;
    console.log('[HistoryStore] 已清除全局统计缓存');
  }

  /**
   * 强制刷新所有缓存
   * @returns {Promise<void>}
   */
  async refreshAllCaches() {
    console.log('[HistoryStore] 开始强制刷新所有缓存');
    this.clearGlobalCache();
    this.clearUserCache();

    // 重新加载全局统计
    await this.getTotalLoginCount();
    await this.getGlobalFeatureStats();
    await this.getGlobalTotalStats(true);

    console.log('[HistoryStore] 所有缓存刷新完成');
  }
}


// 创建单例实例（供中间件使用）
const historyStoreInstance = new HistoryStore();

// 修改中间件挂载方式
module.exports = {
  instance: historyStoreInstance,
  middleware: (req, res, next) => {
    req.historyStore = historyStoreInstance;
    if (req.path === '/login' && req.method === 'POST') {
      // 强制刷新用户历史
      const userId = req.body?.username || req.user?.id;
      if (userId) {
        historyStoreInstance.initializeUserHistory(userId, true)
          .catch(err => console.error('用户历史初始化失败:', err));
      }
    }
    next();
  }
};

