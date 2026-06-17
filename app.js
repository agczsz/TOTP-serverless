const express = require('express');
const serverless = require('serverless-http');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { authenticator } = require('otplib');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, DeleteCommand } = require('@aws-sdk/lib-dynamodb');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 环境与数据库配置
const TABLE_NAME = process.env.DYNAMODB_TABLE;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

const client = new DynamoDBClient({});
const dynamoDb = DynamoDBDocumentClient.from(client);

// ==========================================
// 辅助函数：数据库操作
// ==========================================
async function getTotps() {
    const res = await dynamoDb.send(new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: "#type = :type",
        ExpressionAttributeNames: { "#type": "type" },
        ExpressionAttributeValues: { ":type": "TOTP" }
    }));
    return res.Items || [];
}

async function getTotpById(id) {
    const res = await dynamoDb.send(new GetCommand({ TableName: TABLE_NAME, Key: { PK: `TOTP#${id}` } }));
    return res.Item;
}

async function getLinks() {
    const now = Math.floor(Date.now() / 1000);
    const res = await dynamoDb.send(new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: "#type = :type AND #ttl > :now",
        ExpressionAttributeNames: { "#type": "type", "#ttl": "ttl" },
        ExpressionAttributeValues: { ":type": "LINK", ":now": now }
    }));
    return res.Items || [];
}

// ==========================================
// 中间件：登录拦截
// ==========================================
const requireAuth = (req, res, next) => {
    const token = req.cookies.admin_token;
    if (!token) return res.redirect('/login');
    try {
        jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.clearCookie('admin_token');
        res.redirect('/login');
    }
};

// ==========================================
// 路由控制器
// ==========================================

// 1. 登录页
app.get('/login', (req, res) => {
    res.send(renderLogin());
});

app.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('admin_token', token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 });
        res.redirect('/dashboard');
    } else {
        res.send(renderLogin('密码错误，请重试'));
    }
});

// 2. 登出
app.get('/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.redirect('/login');
});

// 3. 管理控制台
app.get(['/', '/dashboard'], requireAuth, async (req, res) => {
    const totps = await getTotps();
    const links = await getLinks();
    res.send(renderDashboard(totps, links, req.query.created));
});

// 4. 新增 TOTP
app.post('/totp/add', requireAuth, async (req, res) => {
    const { issuer, account, secret } = req.body;
    const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
    const id = crypto.randomUUID();
    
    await dynamoDb.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: { PK: `TOTP#${id}`, type: 'TOTP', id, issuer, account, secret: cleanSecret, createdAt: Date.now() }
    }));
    res.redirect('/dashboard');
});

// 5. 生成临时链接 (自定义时间)
app.post('/link/generate', requireAuth, async (req, res) => {
    const { totpId, expireHours } = req.body;
    const hours = parseFloat(expireHours) || 1;
    const token = crypto.randomBytes(24).toString('hex');
    const ttl = Math.floor(Date.now() / 1000) + Math.floor(hours * 3600);
    
    await dynamoDb.send(new PutCommand({
        TableName: TABLE_NAME,
        Item: { PK: `LINK#${token}`, type: 'LINK', token, totpId, ttl }
    }));
    res.redirect(`/dashboard?created=${token}`);
});

// 6. 撤销临时链接
app.post('/link/revoke', requireAuth, async (req, res) => {
    await dynamoDb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: `LINK#${req.body.token}` } }));
    res.redirect('/dashboard');
});

// 7. 删除 TOTP
app.post('/totp/delete', requireAuth, async (req, res) => {
    await dynamoDb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: `TOTP#${req.body.id}` } }));
    res.redirect('/dashboard');
});

// 8. 访客查看临时链接
app.get('/view', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.send(renderExpired());

    const linkRes = await dynamoDb.send(new GetCommand({ TableName: TABLE_NAME, Key: { PK: `LINK#${token}` } }));
    const link = linkRes.Item;
    
    if (!link || link.ttl < Math.floor(Date.now() / 1000)) {
        return res.send(renderExpired());
    }

    const totp = await getTotpById(link.totpId);
    if (!totp) return res.send(renderExpired());

    res.send(renderTempPage(totp, link.ttl));
});

module.exports.handler = serverless(app);

// ==========================================
// 前端渲染模板 (基于原生 CSS)
// ==========================================

const commonCss = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Noto+Sans+SC:wght@300;400;500&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0a0a0f;--panel:#13131a;--border:#252535;
    --accent:#00e5ff;--accent2:#7b2fff;--green:#00ff88;
    --text:#e8e8f0;--muted:#5a5a7a;--error:#ff4d6d;
  }
  body{background:var(--bg);color:var(--text);font-family:'Noto Sans SC',sans-serif;min-height:100vh;}
  .btn{padding:10px 20px;background:linear-gradient(135deg,var(--accent2),var(--accent));border:none;border-radius:8px;color:#fff;font-family:'Space Mono',monospace;cursor:pointer;transition:opacity .2s;text-transform:uppercase;font-size:12px;text-decoration:none;display:inline-block;}
  .btn:hover{opacity:.85;}
  .btn-danger{background:transparent;border:1px solid rgba(255,77,109,.3);color:var(--error);}
  .btn-danger:hover{background:rgba(255,77,109,.1);}
  input, select{width:100%;background:#0d0d14;border:1px solid var(--border);border-radius:8px;padding:12px 14px;color:var(--text);font-family:'Space Mono',monospace;outline:none;margin-bottom:12px;}
  label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px;font-family:'Space Mono',monospace;}
`;

function renderLogin(error = '') {
    const errHtml = error ? `<div style="color:var(--error);background:rgba(255,77,109,.1);padding:10px;border-radius:8px;margin-bottom:16px;">${error}</div>` : '';
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TOTP 管理器</title><style>${commonCss} body{display:flex;align-items:center;justify-content:center;} .card{background:var(--panel);border:1px solid var(--border);padding:40px;border-radius:16px;width:100%;max-width:400px;}</style></head><body>
    <div class="card">
        <h1 style="font-weight:500;margin-bottom:24px;">TOTP 管理后台</h1>
        ${errHtml}
        <form method="POST" action="/login">
            <label>访问密码</label>
            <input type="password" name="password" placeholder="••••••••">
            <button type="submit" class="btn" style="width:100%;margin-top:10px;">进入系统 →</button>
        </form>
    </div></body></html>`;
}

function renderDashboard(totps, links, createdToken) {
    const remain = authenticator.timeRemaining();
    const pct = Math.round((remain / 30) * 100);

    let totpHtml = totps.map(t => {
        const code = authenticator.generate(t.secret);
        return `
        <div class="card" style="background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:24px;margin-bottom:16px;">
            <div style="display:flex;justify-content:space-between;align-items:start;">
                <div>
                    <div style="color:var(--muted);font-size:12px;margin-bottom:8px;">${t.issuer} · ${t.account}</div>
                    <div style="font-family:'Space Mono';font-size:36px;color:var(--accent);font-weight:700;margin-bottom:12px;" class="totp-code">${code}</div>
                </div>
                <form method="POST" action="/totp/delete" onsubmit="return confirm('确认删除？')">
                    <input type="hidden" name="id" value="${t.id}">
                    <button type="submit" class="btn btn-danger" style="padding:6px 10px;">删除</button>
                </form>
            </div>
            <div style="height:3px;background:var(--border);border-radius:2px;overflow:hidden;"><div class="bar" style="height:100%;background:var(--accent);width:${pct}%;transition:width 1s linear;"></div></div>
        </div>`;
    }).join('');
    if(!totpHtml) totpHtml = '<p style="color:var(--muted)">暂无账号，请先添加。</p>';

    let linkHtml = links.map(l => {
        const minLeft = Math.ceil((l.ttl - (Date.now()/1000)) / 60);
        return `<tr style="border-bottom:1px solid var(--border);">
            <td style="padding:12px;font-family:'Space Mono';font-size:12px;">${l.token.substring(0,12)}...</td>
            <td style="padding:12px;color:var(--accent);">${minLeft} 分钟</td>
            <td style="padding:12px;"><a href="/view?token=${l.token}" target="_blank" style="color:var(--green)">访问</a></td>
            <td style="padding:12px;">
                <form method="POST" action="/link/revoke"><input type="hidden" name="token" value="${l.token}"><button type="submit" class="btn btn-danger" style="padding:4px 8px;font-size:11px;">撤销</button></form>
            </td>
        </tr>`;
    }).join('');

    const newLinkNotice = createdToken ? `
        <div style="background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);padding:16px;border-radius:8px;margin-bottom:24px;color:var(--green);">
            ✓ 新临时链接生成成功！<br>
            <a href="/view?token=${createdToken}" target="_blank" style="color:#fff;word-break:break-all;display:block;margin-top:8px;">/view?token=${createdToken}</a>
        </div>
    ` : '';

    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>控制台</title><style>${commonCss} main{max-width:1000px;margin:0 auto;padding:32px 24px;} .grid{display:grid;grid-template-columns:1fr 350px;gap:24px;} @media(max-width:768px){.grid{grid-template-columns:1fr}}</style></head><body>
    <header style="background:var(--panel);padding:16px 32px;display:flex;justify-content:space-between;border-bottom:1px solid var(--border);">
        <div style="color:var(--accent);font-family:'Space Mono';">▸ TOTP Cloud</div>
        <a href="/logout" style="color:var(--muted);text-decoration:none;">退出登录</a>
    </header>
    <main>
        ${newLinkNotice}
        <div class="grid">
            <div class="left-col">
                <h3 style="margin-bottom:16px;">我的验证器</h3>
                ${totpHtml}
                
                <h3 style="margin-top:40px;margin-bottom:16px;">有效临时链接</h3>
                <div style="background:var(--panel);border:1px solid var(--border);border-radius:14px;overflow:hidden;">
                    <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
                        <tr style="background:var(--bg);color:var(--muted);"><th style="padding:12px;">Token</th><th style="padding:12px;">剩余</th><th style="padding:12px;">链接</th><th style="padding:12px;">操作</th></tr>
                        ${linkHtml || '<tr><td colspan="4" style="padding:24px;text-align:center;color:var(--muted);">暂无有效链接</td></tr>'}
                    </table>
                </div>
            </div>
            
            <div class="right-col">
                <div style="background:var(--panel);padding:24px;border-radius:14px;border:1px solid var(--border);margin-bottom:24px;">
                    <h3 style="margin-bottom:16px;">➕ 添加新账号</h3>
                    <form method="POST" action="/totp/add">
                        <label>发行方 (如 Github, AWS)</label>
                        <input type="text" name="issuer" required>
                        <label>账号/邮箱</label>
                        <input type="text" name="account" required>
                        <label>密钥 (Base32)</label>
                        <input type="text" name="secret" required placeholder="JBSWY3DPEHPK3PXP">
                        <button type="submit" class="btn" style="width:100%;">保存账号</button>
                    </form>
                </div>

                <div style="background:var(--panel);padding:24px;border-radius:14px;border:1px solid var(--border);">
                    <h3 style="margin-bottom:16px;">🔗 生成临时链接</h3>
                    <form method="POST" action="/link/generate">
                        <label>选择账户</label>
                        <select name="totpId" required>
                            ${totps.map(t => `<option value="${t.id}">${t.issuer} (${t.account})</option>`).join('')}
                        </select>
                        <label>有效期 (小时)</label>
                        <input type="number" step="0.1" name="expireHours" value="1" required>
                        <button type="submit" class="btn" style="width:100%;background:transparent;border:1px solid var(--green);color:var(--green);">生成链接</button>
                    </form>
                </div>
            </div>
        </div>
    </main>
    <script>
        let remain = ${remain};
        function tick(){
            remain--;
            if(remain <= 0) return location.reload();
            document.querySelectorAll('.bar').forEach(b => b.style.width = Math.round(remain/30*100) + '%');
            if(remain <= 5) document.querySelectorAll('.totp-code').forEach(c => { c.style.color='var(--error)'; });
            setTimeout(tick, 1000);
        }
        setTimeout(tick, 1000);
    </script>
    </body></html>`;
}

function renderTempPage(totp, expireTimestamp) {
    const code = authenticator.generate(totp.secret);
    const remain = authenticator.timeRemaining();
    const pct = Math.round((remain / 30) * 100);
    const minsLeft = Math.ceil((expireTimestamp - (Date.now()/1000)) / 60);

    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>临时验证码</title><style>${commonCss} body{display:flex;align-items:center;justify-content:center;text-align:center;} .code{font-family:'Space Mono';font-size:64px;color:var(--accent);background:var(--panel);border:1px solid var(--border);padding:24px 48px;border-radius:16px;margin:20px 0;display:inline-block;} @media(max-width:480px){.code{font-size:48px;}}</style></head><body>
    <div>
        <div style="color:var(--muted);font-family:'Space Mono';letter-spacing:2px;font-size:12px;">${totp.issuer} · ${totp.account}</div>
        <div class="code" id="code">${code}</div>
        <div style="width:100%;height:3px;background:var(--border);border-radius:2px;margin-bottom:16px;overflow:hidden;"><div id="bar" style="height:100%;background:var(--accent);width:${pct}%;"></div></div>
        <div style="color:var(--muted);font-size:13px;">验证码剩余 <span id="sec">${remain}</span> 秒</div>
        <div style="margin-top:40px;color:#ffb830;background:rgba(255,184,48,.1);padding:10px;border-radius:8px;font-size:12px;">页面将在 ${minsLeft} 分钟后失效</div>
    </div>
    <script>
        let remain = ${remain};
        const expireTime = ${expireTimestamp};
        function tick(){
            remain--;
            if(remain <= 0 || (Date.now()/1000) > expireTime) return location.reload();
            document.getElementById('sec').innerText = remain;
            document.getElementById('bar').style.width = Math.round(remain/30*100) + '%';
            if(remain <= 5) document.getElementById('code').style.color = 'var(--error)';
            setTimeout(tick, 1000);
        }
        setTimeout(tick, 1000);
    </script>
    </body></html>`;
}

function renderExpired() {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>已失效</title><style>${commonCss} body{display:flex;align-items:center;justify-content:center;}</style></head><body><div style="text-align:center;color:var(--muted);font-family:'Space Mono';"><h1 style="font-size:64px;color:var(--border);margin-bottom:16px;">410</h1><p>该链接已失效或不存在</p></div></body></html>`;
}