const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');




// 用户数据存储路径
const USERS_FILE = 'users.json';
const ADMIN_USERNAME = 'admin';

// auth-middleware.js
module.exports = async (req, res, next) => {
    console.log('[认证中间件] 开始用户认证');
    
    const { username, password } = req.body;
    if (!username || !password) {
      console.error('[认证失败] 缺少用户名或密码');
      return res.status(400).json({ error: 'Missing credentials' });
    }
  
    try {
      const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8'));
      const user = users.find(u => u.username === username);
      
      if (!user) {
        console.error('[认证失败] 用户不存在', { username });
        return res.status(401).json({ error: 'User not found' });
      }
  
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        console.error('[认证失败] 密码错误', { username });
        return res.status(401).json({ error: 'Invalid password' });
      }
  
      // 认证成功，设置 req.user
      req.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };
      
      // 在认证成功后添加标记
      req.authenticatedAt = Date.now();
      console.log('[认证成功] 用户已设置', { userId: user.id });
      next();
    } catch (error) {
      console.error('[认证错误] 服务器异常', error.stack);
      res.status(500).json({ error: 'Server error' });
    }
  };