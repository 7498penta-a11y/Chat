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
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-production';
const MONGO_URI  = process.env.MONGO_URI  || '';
const DB_NAME    = process.env.DB_NAME    || 'chatapp';

// ── チャンネルマッピング ──────────────────────────────────────────
const APP_CHANNELS = ['general', 'random', 'media', 'dev'];
const discordToApp = {}; // discordChannelId → appChannelId

function getDiscordChannelId(appCh) {
  return process.env[`DISCORD_CHANNEL_ID_${appCh}`] || null;
}
function getDiscordWebhook(appCh) {
  return process.env[`DISCORD_WEBHOOK_${appCh}`] || process.env.DISCORD_WEBHOOK_DEFAULT || null;
}

// ── Discord Bot (グローバルで保持) ────────────────────────────────
let discordBot = null; // Bot ready後にセット

// Discord メッセージ → アプリ共通フォーマット変換
function discordMsgToApp(dMsg, appChannelId) {
  // Webhookで送ったサイト発メッセージは "(web#xxx)" suffix が付いている
  const isFromSite = dMsg.webhookId != null;
  const rawAuthor  = dMsg.author?.username || 'Discord';
  // webhook名から "(web#channelId)" を除去してサイト側のユーザー名に戻す
  const author = isFromSite
    ? rawAuthor.replace(/\s*\(web#\w+\)$/, '')
    : `${rawAuthor} [Discord]`;

  // 添付ファイル
  const attach = dMsg.attachments?.first();
  if (attach) {
    const isImage = attach.contentType?.startsWith('image/') ?? /\.(png|jpe?g|gif|webp)$/i.test(attach.name);
    return {
      id:        dMsg.id,
      author,
      content:   attach.name,
      channelId: appChannelId,
      type:      'file',
      fileInfo: {
        filename: attach.name,
        url:      attach.url,
        mimetype: attach.contentType || (isImage ? 'image/png' : 'application/octet-stream'),
        size:     attach.size || 0,
      },
      timestamp: dMsg.createdAt.toISOString(),
      fromDiscord: !isFromSite,
    };
  }

  return {
    id:          dMsg.id,
    author,
    content:     dMsg.content || '',
    channelId:   appChannelId,
    type:        'text',
    fileInfo:    null,
    timestamp:   dMsg.createdAt.toISOString(),
    fromDiscord: !isFromSite,
  };
}

// Discord チャンネルから過去メッセージを取得（最大100件）
async function fetchDiscordHistory(appChannelId, limit = 50) {
  if (!discordBot) return null;
  const discordChId = getDiscordChannelId(appChannelId);
  if (!discordChId) return null;

  try {
    const ch = await discordBot.channels.fetch(discordChId);
    if (!ch || !ch.isTextBased()) return null;

    const fetched = await ch.messages.fetch({ limit });
    // Discord APIは新しい順で返るので古い順に並べ替え
    const sorted = [...fetched.values()].sort((a, b) => a.createdTimestamp - b.createdTimestamp);

    // 空メッセージ（embed only等）は除外
    return sorted
      .filter(m => m.content || m.attachments.size > 0)
      .map(m => discordMsgToApp(m, appChannelId));
  } catch (err) {
    console.error(`[Discord履歴] #${appChannelId} 取得失敗:`, err.message);
    return null;
  }
}

// ── Discord Webhook (サイト→Discord) ─────────────────────────────
async function sendToDiscord(appChannelId, username, content, fileInfo = null) {
  const webhookUrl = getDiscordWebhook(appChannelId);
  if (!webhookUrl) return;

  const body = { username: `${username} (web#${appChannelId})` };
  if (fileInfo) {
    body.embeds = [{
      title: '📎 ' + fileInfo.filename,
      description: `**${username}** がファイルを送信しました`,
      color: 0x5865F2,
      footer: { text: `#${appChannelId} | NexusChat` },
      timestamp: new Date().toISOString()
    }];
  } else {
    body.content = content;
  }

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (res.ok || res.status === 204) {
      console.log(`[Webhook→Discord] ✅ #${appChannelId} "${username}"`);
    } else {
      console.error(`[Webhook→Discord] ❌ (${res.status}): ${await res.text()}`);
    }
  } catch (err) {
    console.error(`[Webhook→Discord] ❌ ${err.message}`);
  }
}

// ── Discord Bot 起動 ──────────────────────────────────────────────
function startDiscordBot() {
  const botToken = process.env.DISCORD_BOT_TOKEN;
  if (!botToken) {
    console.warn('⚠️  DISCORD_BOT_TOKEN 未設定 → Discord連携は無効');
    return;
  }

  const bot = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
    ]
  });

  bot.once('clientReady', () => {
    discordBot = bot; // グローバルにセット（履歴取得で使用）
    console.log(`✅ Discord Bot ログイン成功: ${bot.user.tag}`);
    APP_CHANNELS.forEach(appCh => {
      const id = getDiscordChannelId(appCh);
      if (id) { discordToApp[id] = appCh; console.log(`  📌 Discord #${id} ↔ App #${appCh}`); }
      else console.warn(`  ⚠️  DISCORD_CHANNEL_ID_${appCh} 未設定`);
    });
  });

  // リアルタイム受信（Discord → サイト）
  bot.on('messageCreate', (message) => {
    if (message.author.bot) return;
    if (message.webhookId) return; // サイトからのWebhookはエコーバックしない

    const appChannelId = discordToApp[message.channelId];
    if (!appChannelId) return;

    const msg = discordMsgToApp(message, appChannelId);
    channels[appChannelId]?.messages.push(msg);
    io.to(appChannelId).emit('message', msg);
    console.log(`[Discord→サイト] #${appChannelId} "${msg.author}": ${msg.content.substring(0, 50)}`);
  });

  bot.on('error', err => console.error('[Discord Bot]', err.message));
  bot.login(botToken).catch(err => {
    console.error('❌ Discord Bot ログイン失敗:', err.message);
  });
}

// ── 設定確認ログ ──────────────────────────────────────────────────
function checkConfig() {
  console.log('── Discord 設定確認 ──────────────────────────');
  APP_CHANNELS.forEach(ch => {
    const w = !!getDiscordWebhook(ch), c = !!getDiscordChannelId(ch);
    console.log(`  #${ch}: Webhook ${w?'✅':'❌'}  ChannelID ${c?'✅':'❌'}`);
  });
  console.log(`  BOT_TOKEN: ${process.env.DISCORD_BOT_TOKEN ? '✅' : '❌'}`);
  console.log('─────────────────────────────────────────────');
}

// ── MongoDB + インメモリフォールバック ────────────────────────────
let usersCol = null;
const inMemoryUsers = {};
const Users = {
  async findOne(q) {
    if (usersCol) return usersCol.findOne(q);
    if (q.usernameLower !== undefined)
      return Object.values(inMemoryUsers).find(u => u.usernameLower === q.usernameLower) || null;
    return null;
  },
  async insertOne(doc) {
    if (usersCol) return usersCol.insertOne(doc);
    if (inMemoryUsers[doc.usernameLower]) {
      const e = new Error('duplicate'); e.code = 11000; throw e;
    }
    inMemoryUsers[doc.usernameLower] = doc;
    return { insertedId: doc.id };
  }
};

async function connectMongo() {
  if (!MONGO_URI) { console.warn('⚠️  MONGO_URI 未設定 → インメモリモード'); return; }
  const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000, connectTimeoutMS: 8000 });
  try {
    await client.connect();
    await client.db('admin').command({ ping: 1 });
    const db = client.db(DB_NAME);
    usersCol = db.collection('users');
    await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB 接続失敗 → インメモリ続行:', err.message);
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

// ── Uploads ───────────────────────────────────────────────────────
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
  fs.existsSync(f) ? res.sendFile(f) : res.status(404).send('index.html not found');
});

// ── Auth ──────────────────────────────────────────────────────────
function generateToken(user) { return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' }); }
function verifyToken(t) { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } }
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const user = verifyToken(auth.split(' ')[1]);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user; next();
}

// ── REST ──────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok',
  mongo: usersCol ? 'connected' : 'in-memory',
  discord_bot: !!discordBot,
}));

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), username, usernameLower: username.toLowerCase(), passwordHash,
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`, createdAt: new Date() };
  try { await Users.insertOne(user); }
  catch (e) { if (e.code === 11000) return res.status(409).json({ error: 'Username already taken' }); throw e; }
  res.json({ token: generateToken(user), user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await Users.findOne({ usernameLower: username?.toLowerCase() });
  if (!user || !await bcrypt.compare(password, user.passwordHash))
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

// ── メッセージ取得: Discord履歴を優先、なければインメモリ ──────────
app.get('/api/channels/:id/messages', authMiddleware, async (req, res) => {
  const channelId = req.params.id;
  const ch = channels[channelId];
  if (!ch) return res.status(404).json({ error: 'Channel not found' });

  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const discordHistory = await fetchDiscordHistory(channelId, limit);

  if (discordHistory && discordHistory.length > 0) {
    // Discordの履歴をインメモリにも同期（重複はIDで除外）
    const existingIds = new Set(ch.messages.map(m => m.id));
    for (const msg of discordHistory) {
      if (!existingIds.has(msg.id)) ch.messages.push(msg);
    }
    // タイムスタンプ順でソートして返す
    const sorted = [...ch.messages].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    console.log(`[履歴] #${channelId}: Discord ${discordHistory.length}件 + インメモリ → 計${sorted.length}件`);
    return res.json(sorted.slice(-limit));
  }

  // Discordが使えない場合はインメモリのみ
  console.log(`[履歴] #${channelId}: インメモリのみ ${ch.messages.length}件 (Discord Bot未接続)`);
  res.json(ch.messages.slice(-limit));
});

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    filename: req.file.originalname, url: `/uploads/${req.file.filename}`,
    mimetype: req.file.mimetype, size: req.file.size,
    uploadedBy: req.user.username, uploadedAt: new Date().toISOString()
  });
});

// ── Socket.io ─────────────────────────────────────────────────────
io.use((socket, next) => {
  const user = verifyToken(socket.handshake.auth.token);
  if (!user) return next(new Error('Authentication error'));
  socket.user = user; next();
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
    const sys = buildMessage('system', `${socket.user.username} joined #${channelId}`, channelId, 'system');
    channels[channelId].messages.push(sys);
    socket.to(channelId).emit('message', sys);
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
    if (idx === -1) users.push(socket.user.username);
    else { users.splice(idx, 1); if (!users.length) delete msg.reactions[emoji]; }
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
