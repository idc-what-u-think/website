import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

app.use('*', cors());

function generateId(prefix = 'id') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function verifyApiKey(c, next) {
  const apiKey = c.req.header('X-API-Key');
  if (!apiKey || apiKey !== c.env.API_KEY) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  await next();
}

async function verifyJWT(c, next) {
  const auth = c.req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  const token = auth.substring(7);
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    c.set('user', payload);
    await next();
  } catch (error) {
    return c.json({ error: 'Invalid token' }, 401);
  }
}

async function verifyAdmin(c, next) {
  const user = c.get('user');
  if (!user || !user.isAdmin) {
    return c.json({ error: 'Admin access required' }, 403);
  }
  await next();
}

app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>QuantumX Bot</title>
      <style>
        body {
          margin: 0;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .container {
          text-align: center;
          padding: 40px;
        }
        h1 {
          font-size: 48px;
          margin-bottom: 20px;
        }
        p {
          font-size: 20px;
          margin-bottom: 30px;
          opacity: 0.9;
        }
        .btn {
          display: inline-block;
          padding: 15px 40px;
          background: white;
          color: #667eea;
          text-decoration: none;
          border-radius: 30px;
          font-weight: 600;
          transition: transform 0.2s;
        }
        .btn:hover {
          transform: translateY(-2px);
        }
        .stats {
          margin-top: 40px;
          display: flex;
          gap: 30px;
          justify-content: center;
        }
        .stat {
          background: rgba(255,255,255,0.1);
          padding: 20px 30px;
          border-radius: 10px;
        }
        .stat-number {
          font-size: 32px;
          font-weight: bold;
        }
        .stat-label {
          opacity: 0.8;
          margin-top: 5px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>QuantumX Bot</h1>
        <p>The most advanced Discord bot with 300+ commands</p>
        <a href="https://discord.com/api/oauth2/authorize?client_id=YOUR_CLIENT_ID&permissions=8&scope=bot%20applications.commands" class="btn">Add to Discord</a>
        <div class="stats">
          <div class="stat">
            <div class="stat-number">1000+</div>
            <div class="stat-label">Servers</div>
          </div>
          <div class="stat">
            <div class="stat-number">300+</div>
            <div class="stat-label">Commands</div>
          </div>
          <div class="stat">
            <div class="stat-number">50K+</div>
            <div class="stat-label">Users</div>
          </div>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.post('/api/auth/google', async (c) => {
  try {
    console.log('=== Google Auth Request ===');
    
    const body = await c.req.json();
    console.log('Request body:', body);
    const { code } = body;
    
    if (!code) {
      return c.json({ success: false, error: 'No code provided' }, 400);
    }
    
    console.log('Environment check:');
    console.log('- GOOGLE_CLIENT_ID:', c.env.GOOGLE_CLIENT_ID ? 'Present' : 'Missing');
    console.log('- GOOGLE_CLIENT_SECRET:', c.env.GOOGLE_CLIENT_SECRET ? 'Present' : 'Missing');
    console.log('- GOOGLE_REDIRECT_URI:', c.env.GOOGLE_REDIRECT_URI);
    console.log('- DB:', c.env.DB ? 'Connected' : 'Missing');
    
    console.log('Exchanging code with Google...');
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret: c.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: c.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });

    console.log('Google token response status:', tokenResponse.status);
    const tokens = await tokenResponse.json();
    console.log('Tokens received:', tokens.access_token ? 'Yes' : 'No');
    
    if (tokens.error) {
      console.error('Google OAuth error:', tokens.error);
      return c.json({ success: false, error: tokens.error_description || tokens.error }, 400);
    }

    console.log('Fetching user info from Google...');
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    const googleUser = await userResponse.json();
    console.log('Google user:', googleUser.email);

    console.log('Checking database for existing user...');
    let user = await c.env.DB.prepare(
      'SELECT * FROM users WHERE google_id = ?'
    ).bind(googleUser.id).first();

    if (!user) {
      console.log('Creating new user...');
      const userId = generateId('user');
      await c.env.DB.prepare(
        `INSERT INTO users (id, google_id, email, display_name, profile_picture, created_at)
         VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
      ).bind(userId, googleUser.id, googleUser.email, googleUser.name, googleUser.picture).run();

      user = { id: userId, google_id: googleUser.id, email: googleUser.email };
      console.log('New user created:', userId);
    } else {
      console.log('Existing user found:', user.id);
    }

    const token = btoa(JSON.stringify({ 
      userId: user.id, 
      email: user.email,
      isAdmin: false 
    }));

    console.log('Auth successful, returning token');
    return c.json({ 
      success: true, 
      token, 
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.display_name,
        profilePicture: user.profile_picture,
      }
    });

  } catch (error) {
    console.error('Auth error:', error);
    return c.json({ success: false, error: error.message || 'Authentication failed' }, 500);
  }
});

app.get('/api/auth/me', verifyJWT, async (c) => {
  try {
    const payload = c.get('user');
    const user = await c.env.DB.prepare(
      'SELECT id, email, username, display_name, profile_picture FROM users WHERE id = ?'
    ).bind(payload.userId).first();

    if (!user) {
      return c.json({ error: 'User not found' }, 404);
    }

    return c.json({ user });
  } catch (error) {
    return c.json({ error: 'Failed to get user' }, 500);
  }
});

app.post('/api/users/username', verifyJWT, async (c) => {
  try {
    const payload = c.get('user');
    const { username } = await c.req.json();

    if (!username || username.length < 3 || username.length > 20) {
      return c.json({ error: 'Username must be 3-20 characters' }, 400);
    }

    const existing = await c.env.DB.prepare(
      'SELECT id FROM users WHERE username = ? AND id != ?'
    ).bind(username, payload.userId).first();

    if (existing) {
      return c.json({ error: 'Username already taken' }, 400);
    }

    await c.env.DB.prepare(
      'UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(username, payload.userId).run();

    return c.json({ success: true, username });
  } catch (error) {
    return c.json({ error: 'Failed to update username' }, 500);
  }
});

app.get('/api/chat/messages', verifyJWT, async (c) => {
  try {
    const limit = parseInt(c.req.query('limit')) || 50;
    const offset = parseInt(c.req.query('offset')) || 0;

    const messages = await c.env.DB.prepare(
      `SELECT cm.*, u.username, u.profile_picture 
       FROM chat_messages cm
       JOIN users u ON cm.user_id = u.id
       ORDER BY cm.created_at DESC
       LIMIT ? OFFSET ?`
    ).bind(limit, offset).all();

    const total = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM chat_messages'
    ).first();

    return c.json({ 
      messages: messages.results.reverse(),
      total: total.count 
    });
  } catch (error) {
    return c.json({ error: 'Failed to fetch messages' }, 500);
  }
});

app.post('/api/chat/messages', verifyJWT, async (c) => {
  try {
    const payload = c.get('user');
    const { message } = await c.req.json();

    if (!message || message.length > 2000) {
      return c.json({ error: 'Invalid message' }, 400);
    }

    const id = generateId('msg');
    await c.env.DB.prepare(
      `INSERT INTO chat_messages (id, user_id, message, created_at)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP)`
    ).bind(id, payload.userId, message).run();

    return c.json({ success: true, message: { id, message } });
  } catch (error) {
    return c.json({ error: 'Failed to send message' }, 500);
  }
});

app.get('/api/bot/servers/:serverId/config', verifyApiKey, async (c) => {
  try {
    const serverId = c.req.param('serverId');
    
    let config = await c.env.DB.prepare(
      'SELECT * FROM server_configs WHERE server_id = ?'
    ).bind(serverId).first();

    if (!config) {
      const id = serverId;
      await c.env.DB.prepare(
        `INSERT INTO server_configs (server_id, prefix, created_at)
         VALUES (?, '!', CURRENT_TIMESTAMP)`
      ).bind(id).run();
      
      config = await c.env.DB.prepare(
        'SELECT * FROM server_configs WHERE server_id = ?'
      ).bind(serverId).first();
    }

    return c.json(config);
  } catch (error) {
    return c.json({ error: 'Failed to fetch config' }, 500);
  }
});

app.put('/api/bot/servers/:serverId/config', verifyApiKey, async (c) => {
  try {
    const serverId = c.req.param('serverId');
    const updates = await c.req.json();

    const fields = [];
    const values = [];

    if (updates.prefix) {
      fields.push('prefix = ?');
      values.push(updates.prefix);
    }
    if (updates.welcomeMessage) {
      fields.push('welcome_message = ?');
      values.push(updates.welcomeMessage);
    }
    if (updates.levelingEnabled !== undefined) {
      fields.push('leveling_enabled = ?');
      values.push(updates.levelingEnabled ? 1 : 0);
    }

    if (fields.length === 0) {
      return c.json({ error: 'No valid fields to update' }, 400);
    }

    values.push(serverId);

    await c.env.DB.prepare(
      `UPDATE server_configs SET ${fields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE server_id = ?`
    ).bind(...values).run();

    return c.json({ success: true });
  } catch (error) {
    return c.json({ error: 'Failed to update config' }, 500);
  }
});

app.post('/api/bot/levels/award', verifyApiKey, async (c) => {
  try {
    const { userId, serverId, xp } = await c.req.json();

    const existing = await c.env.DB.prepare(
      'SELECT * FROM user_levels WHERE user_id = ? AND server_id = ?'
    ).bind(userId, serverId).first();

    if (existing) {
      const newXP = existing.xp + xp;
      const newLevel = Math.floor(0.1 * Math.sqrt(newXP));
      const leveledUp = newLevel > existing.level;

      await c.env.DB.prepare(
        `UPDATE user_levels 
         SET xp = ?, level = ?, messages_sent = messages_sent + 1, last_xp_gain = CURRENT_TIMESTAMP
         WHERE user_id = ? AND server_id = ?`
      ).bind(newXP, newLevel, userId, serverId).run();

      return c.json({ 
        success: true, 
        leveledUp, 
        newLevel,
        totalXP: newXP 
      });
    } else {
      const id = generateId('lvl');
      await c.env.DB.prepare(
        `INSERT INTO user_levels (id, user_id, server_id, xp, level, messages_sent, last_xp_gain)
         VALUES (?, ?, ?, ?, 0, 1, CURRENT_TIMESTAMP)`
      ).bind(id, userId, serverId, xp).run();

      return c.json({ 
        success: true, 
        leveledUp: false,
        newLevel: 0,
        totalXP: xp 
      });
    }
  } catch (error) {
    return c.json({ error: 'Failed to award XP' }, 500);
  }
});

app.get('/api/bot/levels/:serverId/:userId', verifyApiKey, async (c) => {
  try {
    const serverId = c.req.param('serverId');
    const userId = c.req.param('userId');

    const level = await c.env.DB.prepare(
      'SELECT * FROM user_levels WHERE user_id = ? AND server_id = ?'
    ).bind(userId, serverId).first();

    if (!level) {
      return c.json({ xp: 0, level: 0, messagesSent: 0 });
    }

    return c.json(level);
  } catch (error) {
    return c.json({ error: 'Failed to fetch level' }, 500);
  }
});

app.post('/api/bot/commands/log', verifyApiKey, async (c) => {
  try {
    const { commandName, serverId, userId, success, executionTime, errorMessage } = await c.req.json();

    const id = generateId('cmd');
    await c.env.DB.prepare(
      `INSERT INTO command_usage (id, command_name, server_id, user_id, success, execution_time, error_message, used_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
    ).bind(id, commandName, serverId, userId, success ? 1 : 0, executionTime || 0, errorMessage).run();

    return c.json({ success: true });
  } catch (error) {
    return c.json({ error: 'Failed to log command' }, 500);
  }
});

app.get('/api/bot/blacklist/:type/:id', verifyApiKey, async (c) => {
  try {
    const type = c.req.param('type');
    const targetId = c.req.param('id');

    const result = await c.env.DB.prepare(
      'SELECT * FROM blacklist WHERE type = ? AND target_id = ?'
    ).bind(type, targetId).first();

    return c.json({ blacklisted: !!result });
  } catch (error) {
    return c.json({ error: 'Failed to check blacklist' }, 500);
  }
});

app.post('/api/bot/moderation/log', verifyApiKey, async (c) => {
  try {
    const { serverId, userId, moderatorId, action, reason, duration } = await c.req.json();

    const id = generateId('mod');
    await c.env.DB.prepare(
      `INSERT INTO mod_logs (id, server_id, user_id, moderator_id, action, reason, duration, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
    ).bind(id, serverId, userId, moderatorId, action, reason, duration).run();

    return c.json({ success: true, logId: id });
  } catch (error) {
    return c.json({ error: 'Failed to log moderation' }, 500);
  }
});

app.put('/api/bot/stats', verifyApiKey, async (c) => {
  try {
    const { totalServers, totalUsers } = await c.req.json();

    const id = 'main_stats';
    await c.env.DB.prepare(
      `INSERT OR REPLACE INTO bot_stats (id, total_servers, total_users, last_restart, recorded_at)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
    ).bind(id, totalServers, totalUsers).run();

    return c.json({ success: true });
  } catch (error) {
    return c.json({ error: 'Failed to update stats' }, 500);
  }
});

app.post('/api/bot/warnings/add', verifyApiKey, async (c) => {
  try {
    const { id, serverId, userId, moderatorId, reason } = await c.req.json();

    await c.env.DB.prepare(
      `INSERT INTO warnings (id, server_id, user_id, moderator_id, reason, active, created_at)
       VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`
    ).bind(id, serverId, userId, moderatorId, reason).run();

    return c.json({ success: true });
  } catch (error) {
    return c.json({ error: 'Failed to add warning' }, 500);
  }
});

app.get('/api/bot/warnings/:serverId/:userId', verifyApiKey, async (c) => {
  try {
    const serverId = c.req.param('serverId');
    const userId = c.req.param('userId');

    const warnings = await c.env.DB.prepare(
      'SELECT * FROM warnings WHERE server_id = ? AND user_id = ? AND active = 1 ORDER BY created_at DESC'
    ).bind(serverId, userId).all();

    return c.json({ 
      warnings: warnings.results,
      count: warnings.results.length 
    });
  } catch (error) {
    return c.json({ error: 'Failed to fetch warnings' }, 500);
  }
});

app.delete('/api/bot/warnings/clear', verifyApiKey, async (c) => {
  try {
    const { serverId, userId } = await c.req.json();

    await c.env.DB.prepare(
      'UPDATE warnings SET active = 0 WHERE server_id = ? AND user_id = ?'
    ).bind(serverId, userId).run();

    return c.json({ success: true });
  } catch (error) {
    return c.json({ error: 'Failed to clear warnings' }, 500);
  }
});

app.post('/api/admin/login', async (c) => {
  try {
    const { username, password } = await c.req.json();

    if (username !== c.env.ADMIN_USERNAME) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }

    const hashedInput = await hashPassword(password);
    const hashedAdmin = await hashPassword(c.env.ADMIN_PASSWORD);

    if (hashedInput !== hashedAdmin) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }

    const token = btoa(JSON.stringify({ 
      userId: 'admin',
      username: username,
      isAdmin: true 
    }));

    return c.json({ success: true, token });
  } catch (error) {
    return c.json({ error: 'Login failed' }, 500);
  }
});

app.get('/api/admin/bot/stats', verifyJWT, verifyAdmin, async (c) => {
  try {
    const stats = await c.env.DB.prepare(
      'SELECT * FROM bot_stats WHERE id = ?'
    ).bind('main_stats').first();

    return c.json(stats || { totalServers: 0, totalUsers: 0 });
  } catch (error) {
    return c.json({ error: 'Failed to fetch stats' }, 500);
  }
});

app.get('/api/admin/servers', verifyJWT, verifyAdmin, async (c) => {
  try {
    const limit = parseInt(c.req.query('limit')) || 50;
    const offset = parseInt(c.req.query('offset')) || 0;

    const servers = await c.env.DB.prepare(
      'SELECT * FROM server_configs ORDER BY created_at DESC LIMIT ? OFFSET ?'
    ).bind(limit, offset).all();

    const total = await c.env.DB.prepare(
      'SELECT COUNT(*) as count FROM server_configs'
    ).first();

    return c.json({ 
      servers: servers.results,
      total: total.count 
    });
  } catch (error) {
    return c.json({ error: 'Failed to fetch servers' }, 500);
  }
});

export default app;
