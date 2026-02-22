require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const { Client, GatewayIntentBits } = require('discord.js');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-production';
const MONGO_URI  = process.env.MONGO_URI  || '';
const DB_NAME    = process.env.DB_NAME    || 'chatapp';

// ── チャンネル定義 ─────────────────────────────────────────────────
// アプリのチャンネルID → Discord チャンネルID のマッピング
// 環境変数: DISCORD_CHANNEL_ID_general=1234567890
const APP_CHANNELS = ['general', 'random', 'media', 'dev'];

function getDiscordChannelId(appChannelId) {
  return process.env[`DISCORD_CHANNEL_ID_${appChannelId}`] || null;
}

// Discord チャンネルID → アプリチャンネルID の逆引きマップ
// Bot起動時に構築する
const discordToApp = {}; // { '1234567890': 'general', ... }

// ── Discord Webhook (サイト→Discord 送信用) ────────────────────────
function getDiscordWebhook(channelId) {
  return process.env[`DISCORD_WEBHOOK_${channelId}`]
      || process.env.DISCORD_WEBHOOK_DEFAULT
      || null;
}

async function sendToDiscord(channelId, username, content, fileInfo = null) {
  const webhookUrl = getDiscordWebhook(channelId);
  if (!webhookUrl) return;

  const body = { username: `${username} (web#${channelId})` };

  if (fileInfo) {
    body.embeds = [{
      title: '📎 ' + fileInfo.filename,
      description: `**${username}** がファイルを送信しました`,
      color: 0x5865F2,
      footer: { text: `#${channelId} | NexusChat` },
      timestamp: new Date().toISOString()
    }];
  } else {
    body.content = content;
  }

  console.log(`[Webhook→Discord] #${channelId} "${username}": ${content || fileInfo?.filename}`);

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (res.ok || res.status === 204) {
      console.log(`[Webhook→Discord] ✅ 送信成功`);
    } else {
      console.error(`[Webhook→Discord] ❌ 失敗 (${res.status}): ${await res.text()}`);
    }
  } catch (err) {
    console.error(`[Webhook→Discord] ❌ エラー: ${err.message}`);
  }
}

// ── Discord Bot (Discord→サイト 受信用) ───────────────────────────
function startDiscordBot() {
  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token) {
    console.warn('⚠️  DISCORD_BOT_TOKEN 未設定 → Discord→サイト の受信は無効');
    return;
  }

  const bot = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
    ]
  });

  bot.once('ready', () => {
    console.log(`✅ Discord Bot ログイン成功: ${bot.user.tag}`);

    // 逆引きマップを構築
    APP_CHANNELS.forEach(appCh => {
      const discordChId = getDiscordChannelId(appCh);
      if (discordChId) {
        discordToApp[discordChId] = appCh;
        console.log(`  📌 Discord #${discordChId} ↔ App #${appCh}`);
      } else {
        console.warn(`  ⚠️  DISCORD_CHANNEL_ID_${appCh} 未設定`);
      }
    });
  });

  bot.on('messageCreate', (message) => {
    // ① Bot自身のメッセージは無視
    if (message.author.bot) return;

    // ② Webhookのメッセージは無視（サイト→Discordのエコーバック防止）
    if (message.webhookId) return;

    // ③ 対象チャンネルか確認
    const appChannelId = discordToApp[message.channelId];
    if (!appChannelId) return;

    const content = message.content;
    const username = message.author.displayName || message.author.username;

    console.log(`[Discord→サイト] #${appChannelId} "${username}": ${content}`);

    // ④ アプリのメッセージとして Socket.io でブロードキャスト
    const msg = buildMessage(
      `${username} [Discord]`,
      content,
      appChannelId,
      'text'
    );
    channels[appChannelId]?.messages.push(msg);
    io.to(appChannelId).emit('message', msg);
  });

  bot.on('error', (err) => {
    console.error('[Discord Bot] エラー:', err.message);
  });

  bot.login(token).catch(err => {
    console.error('❌ Discord Bot ログイン失敗:', err.message);
    console.error('   DISCORD_BOT_TOKEN が正しいか確認してください。');
  });
}

// ── 起動時設定確認ログ ─────────────────────────────────────────────
function checkConfig() {
  console.log('── Discord 設定確認 ──────────────────────────');
  console.log('  [Webhook: サイト→Discord]');
  APP_CHANNELS.forEach(ch => {
    const url = process.env[`DISCORD_WEBHOOK_${ch}`];
    console.log(`    ${url ? '✅' : '❌'} DISCORD_WEBHOOK_${ch}`);
  });
  console.log('  [Bot: Discord→サイト]');
  console.log(`    ${process.env.DISCORD_BOT_TOKEN ? '✅' : '❌'} DISCORD_BOT_TOKEN`);
  APP_CHANNELS.forEach(ch => {
    const id = process.env[`DISCORD_CHANNEL_ID_${ch}`];
    console.log(`    ${id ? '✅' : '❌'} DISCORD_CHANNEL_ID_${ch}${id ? ' = ' + id : ''}`);
  });
  console.log('─────────────────────────────────────────────');
}

// ── MongoDB + インメモリフォールバック ────────────────────────────
let usersCol = null;
const inMemoryUsers = {};

const Users = {
  async findOne(query) {
    if (usersCol) return usersCol.findOne(query);
    if (query.usernameLower !== undefined)
      return Object.values(inMemoryUsers).find(u => u.usernameLower === query.usernameLower) || null;
    return null;
  },
  async insertOne(doc) {
    if (usersCol) return usersCol.insertOne(doc);
    if (inMemoryUsers[doc.usernameLower]) {
      const err = new Error('duplicate key'); err.code = 11000; throw err;
    }
    inMemoryUsers[doc.usernameLower] = doc;
    return { insertedId: doc.id };
  }
};

async function connectMongo() {
  if (!MONGO_URI) {
    console.warn('⚠️  MONGO_URI 未設定 → インメモリモードで起動');
    return;
  }
  const client = new MongoClient(MONGO_URI, {
    serverSelectionTimeoutMS: 8000,
    connectTimeoutMS: 8000,
  });
  try {
    await client.connect();
    await client.db('admin').command({ ping: 1 });
    const mongoDb = client.db(DB_NAME);
    usersCol = mongoDb.collection('users');
    await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB 接続失敗 → インメモリモードで続行:', err.message);
    usersCol = null;
  }
}

// ── In-memory state ───────────────────────────────────────────────
const channels = {
  general: { id: 'general', name: 'general', messages: [] },
  random:  { id: 'random',  name: 'random',  messages: [] },
  media:   { id: 'media',   name: 'media',   messages: [] },
  dev:     { id: 'dev',     name: 'dev',     messages: [] },
};
const onlineUsers = {};

// ── Uploads dir ───────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ── Middleware ────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

app.get('/', (req, res) => {
  const f = path.join(__dirname, 'index.html');
  if (fs.existsSync(f)) res.sendFile(f);
  else res.status(404).send('index.html not found');
});

// ── Auth helpers ──────────────────────────────────────────────────
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const user = verifyToken(auth.split(' ')[1]);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

// ── REST: Health ──────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    mongo: usersCol ? 'connected' : 'in-memory',
    discord_bot: !!process.env.DISCORD_BOT_TOKEN,
    discord_channels: Object.fromEntries(
      APP_CHANNELS.map(ch => [ch, discordToApp[getDiscordChannelId(ch)] ? '✅' : '❌'])
    )
  });
});

// ── REST: Auth ────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20)
    return res.status(400).json({ error: 'Username must be 3-20 characters' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(), username,
    usernameLower: username.toLowerCase(),
    passwordHash,
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
    createdAt: new Date()
  };
  try {
    await Users.insertOne(user);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Username already taken' });
    throw e;
  }
  res.json({ token: generateToken(user), user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await Users.findOne({ usernameLower: username?.toLowerCase() });
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  if (!await bcrypt.compare(password, user.passwordHash))
    return res.status(401).json({ error: 'Invalid username or password' });
  res.json({ token: generateToken(user), user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await Users.findOne({ usernameLower: req.user.username.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, avatar: user.avatar });
});

app.get('/api/channels', authMiddleware, (req, res) => {
  res.json(Object.values(channels).map(c => ({ id: c.id, name: c.name })));
});

app.get('/api/channels/:id/messages', authMiddleware, (req, res) => {
  const ch = channels[req.params.id];
  if (!ch) return res.status(404).json({ error: 'Channel not found' });
  res.json(ch.messages.slice(-100));
});

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    filename: req.file.originalname,
    url: `/uploads/${req.file.filename}`,
    mimetype: req.file.mimetype,
    size: req.file.size,
    uploadedBy: req.user.username,
    uploadedAt: new Date().toISOString()
  });
});

// ── Socket.io ─────────────────────────────────────────────────────
io.use((socket, next) => {
  const user = verifyToken(socket.handshake.auth.token);
  if (!user) return next(new Error('Authentication error'));
  socket.user = user;
  next();
});

io.on('connection', (socket) => {
  console.log(`[+] ${socket.user.username} connected`);
  onlineUsers[socket.id] = { username: socket.user.username, channelId: null };
  io.emit('online_users', Object.values(onlineUsers).map(u => u.username));

  socket.on('join_channel', (channelId) => {
    if (!channels[channelId]) return;
    const prev = onlineUsers[socket.id]?.channelId;
    if (prev) socket.leave(prev);
    socket.join(channelId);
    onlineUsers[socket.id].channelId = channelId;
    const sysMsg = buildMessage('system', `${socket.user.username} joined #${channelId}`, channelId, 'system');
    channels[channelId].messages.push(sysMsg);
    socket.to(channelId).emit('message', sysMsg);
  });

  socket.on('send_message', async ({ channelId, content }) => {
    if (!channels[channelId] || !content?.trim()) return;
    const msg = buildMessage(socket.user.username, content.trim(), channelId, 'text');
    channels[channelId].messages.push(msg);
    io.to(channelId).emit('message', msg);
    sendToDiscord(channelId, socket.user.username, content.trim()).catch(() => {});
  });

  socket.on('send_file', async ({ channelId, fileInfo }) => {
    if (!channels[channelId] || !fileInfo) return;
    const msg = buildMessage(socket.user.username, fileInfo.filename, channelId, 'file', fileInfo);
    channels[channelId].messages.push(msg);
    io.to(channelId).emit('message', msg);
    sendToDiscord(channelId, socket.user.username, null, fileInfo).catch(() => {});
  });

  socket.on('add_reaction', ({ msgId, emoji, channelId }) => {
    if (!channels[channelId] || !msgId || !emoji) return;
    const msg = channels[channelId].messages.find(m => m.id === msgId);
    if (!msg) return;
    if (!msg.reactions) msg.reactions = {};
    if (!msg.reactions[emoji]) msg.reactions[emoji] = [];
    const users = msg.reactions[emoji];
    const idx = users.indexOf(socket.user.username);
    if (idx === -1) { users.push(socket.user.username); }
    else { users.splice(idx, 1); if (users.length === 0) delete msg.reactions[emoji]; }
    io.to(channelId).emit('reaction_update', { msgId, reactions: msg.reactions });
  });

  socket.on('typing', ({ channelId, isTyping }) => {
    socket.to(channelId).emit('typing', { username: socket.user.username, isTyping });
  });

  socket.on('disconnect', () => {
    console.log(`[-] ${socket.user.username} disconnected`);
    delete onlineUsers[socket.id];
    io.emit('online_users', Object.values(onlineUsers).map(u => u.username));
  });
});

function buildMessage(author, content, channelId, type, fileInfo = null) {
  return { id: uuidv4(), author, content, channelId, type, fileInfo, timestamp: new Date().toISOString() };
}

// ── Start ─────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  checkConfig();
  connectMongo().catch(err => console.error('connectMongo error:', err));
  startDiscordBot();
});
