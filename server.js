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
const APP_CHANNELS   = ['general', 'random', 'media', 'dev'];
const VOICE_CHANNELS = ['voice-general', 'voice-gaming'];
const discordToApp   = {};

function getDiscordChannelId(appCh) {
  return process.env[`DISCORD_CHANNEL_ID_${appCh}`] || null;
}

// ── Discord Bot ────────────────────────────────────────────────────
let discordBot = null;

function discordMsgToApp(dMsg, appChannelId) {
  const isFromBot = discordBot && dMsg.author?.id === discordBot.user?.id;
  let author, content;

  if (isFromBot) {
    const match = dMsg.content?.match(/^\*\*\[(.+?)\]\*\*: ([\s\S]*)$/);
    if (match) { author = match[1]; content = match[2]; }
    else { author = 'Web User'; content = dMsg.content; }
  } else {
    author  = `${dMsg.author?.username} [Discord]`;
    content = dMsg.content;
  }

  const attach = dMsg.attachments?.first();
  if (attach) {
    const isImage = attach.contentType?.startsWith('image/') ?? /\.(png|jpe?g|gif|webp)$/i.test(attach.name);
    return {
      id: dMsg.id, author, content: attach.name, channelId: appChannelId,
      type: 'file', fileInfo: {
        filename: attach.name, url: attach.url,
        mimetype: attach.contentType || (isImage ? 'image/png' : 'application/octet-stream'),
        size: attach.size || 0,
      },
      timestamp: dMsg.createdAt.toISOString(), fromDiscord: !isFromBot,
    };
  }
  return {
    id: dMsg.id, author, content: content || '', channelId: appChannelId,
    type: 'text', fileInfo: null,
    timestamp: dMsg.createdAt.toISOString(), fromDiscord: !isFromBot,
  };
}

async function fetchDiscordHistory(appChannelId, limit = 50) {
  if (!discordBot) return null;
  const discordChId = getDiscordChannelId(appChannelId);
  if (!discordChId) return null;
  try {
    const ch = await discordBot.channels.fetch(discordChId);
    if (!ch || !ch.isTextBased()) return null;
    const fetched = await ch.messages.fetch({ limit });
    const sorted = [...fetched.values()].sort((a, b) => a.createdTimestamp - b.createdTimestamp);
    return sorted.filter(m => m.content || m.attachments.size > 0).map(m => discordMsgToApp(m, appChannelId));
  } catch (err) {
    console.error(`[Discord履歴] #${appChannelId} 取得失敗:`, err.message);
    return null;
  }
}

// サイト→Discord送信（Botを使用）
async function sendToDiscordViaBot(appChannelId, username, content, fileInfo = null) {
  if (!discordBot) return;
  const discordChId = getDiscordChannelId(appChannelId);
  if (!discordChId) return;
  try {
    const ch = await discordBot.channels.fetch(discordChId);
    if (!ch?.isTextBased()) return;
    if (fileInfo) {
      await ch.send(`**[${username}]**: 📎 ${fileInfo.filename}`);
    } else {
      await ch.send(`**[${username}]**: ${content}`);
    }
    console.log(`[Bot→Discord] ✅ #${appChannelId} "${username}"`);
  } catch (err) {
    console.error(`[Bot→Discord] ❌ ${err.message}`);
  }
}

function startDiscordBot() {
  const botToken = process.env.DISCORD_BOT_TOKEN;
  if (!botToken) { console.warn('⚠️  DISCORD_BOT_TOKEN 未設定 → Discord連携は無効'); return; }

  const bot = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent],
  });

  bot.once('clientReady', () => {
    discordBot = bot;
    console.log(`✅ Discord Bot ログイン成功: ${bot.user.tag}`);
    APP_CHANNELS.forEach(appCh => {
      const id = getDiscordChannelId(appCh);
      if (id) { discordToApp[id] = appCh; console.log(`  📌 #${id} ↔ #${appCh}`); }
      else console.warn(`  ⚠️  DISCORD_CHANNEL_ID_${appCh} 未設定`);
    });
  });

  bot.on('messageCreate', (message) => {
    if (message.author.id === bot.user?.id) return; // 自サイト経由のメッセージをスキップ
    if (message.author.bot) return;

    const appChannelId = discordToApp[message.channelId];
    if (!appChannelId) return;

    const msg = discordMsgToApp(message, appChannelId);
    channels[appChannelId]?.messages.push(msg);
    if (messagesCol) messagesCol.insertOne({ ...msg }).catch(() => {});
    io.to(appChannelId).emit('message', msg);
    console.log(`[Discord→サイト] #${appChannelId} "${msg.author}": ${msg.content.substring(0, 50)}`);
  });

  bot.on('error', err => console.error('[Discord Bot]', err.message));
  bot.login(botToken).catch(err => console.error('❌ Discord Bot ログイン失敗:', err.message));
}

// ── MongoDB ────────────────────────────────────────────────────────
let usersCol    = null;
let messagesCol = null;
let dmsCol      = null;
let pinsCol     = null;

const inMemoryUsers = {};
const Users = {
  async findOne(q) {
    if (usersCol) return usersCol.findOne(q);
    if (q.id) return Object.values(inMemoryUsers).find(u => u.id === q.id) || null;
    if (q.usernameLower !== undefined)
      return Object.values(inMemoryUsers).find(u => u.usernameLower === q.usernameLower) || null;
    return null;
  },
  async insertOne(doc) {
    if (usersCol) return usersCol.insertOne(doc);
    if (inMemoryUsers[doc.usernameLower]) { const e = new Error('dup'); e.code = 11000; throw e; }
    inMemoryUsers[doc.usernameLower] = doc;
    return { insertedId: doc.id };
  },
  async updateOne(q, update) {
    if (usersCol) return usersCol.updateOne(q, update);
    const user = await this.findOne(q);
    if (user && update.$set) Object.assign(user, update.$set);
  },
  async countDocuments() {
    if (usersCol) return usersCol.countDocuments();
    return Object.keys(inMemoryUsers).length;
  },
  async find() {
    if (usersCol) return usersCol.find({}).toArray();
    return Object.values(inMemoryUsers);
  },
};

async function connectMongo() {
  if (!MONGO_URI) { console.warn('⚠️  MONGO_URI 未設定 → インメモリモード'); return; }
  const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000, connectTimeoutMS: 8000 });
  try {
    await client.connect();
    await client.db('admin').command({ ping: 1 });
    const db    = client.db(DB_NAME);
    usersCol    = db.collection('users');
    messagesCol = db.collection('messages');
    dmsCol      = db.collection('dms');
    pinsCol     = db.collection('pins');

    await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
    await messagesCol.createIndex({ content: 'text' });
    await messagesCol.createIndex({ channelId: 1, timestamp: 1 });
    await dmsCol.createIndex({ roomId: 1, timestamp: 1 });
    await pinsCol.createIndex({ channelId: 1 });

    // 既存のシステムメッセージをDBから削除（増殖問題の根治）
    const deleted = await messagesCol.deleteMany({ type: 'system' });
    if (deleted.deletedCount > 0) console.log(`🧹 システムメッセージ ${deleted.deletedCount} 件をDBから削除`);\
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB 接続失敗 → インメモリ続行:', err.message);
    usersCol = messagesCol = dmsCol = pinsCol = null;
  }
}

// ── In-memory state ───────────────────────────────────────────────
const channels = {
  general: { id: 'general', name: 'general', messages: [], pins: [] },
  random:  { id: 'random',  name: 'random',  messages: [], pins: [] },
  media:   { id: 'media',   name: 'media',   messages: [], pins: [] },
  dev:     { id: 'dev',     name: 'dev',     messages: [], pins: [] },
};
const dmMessages   = {};
const onlineUsers  = {};
const voiceRooms   = {};
const socketByUser = {};

// ── Uploads ───────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ── Middleware ─────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));
app.get('/', (req, res) => {
  const f = path.join(__dirname, 'public/index.html');
  fs.existsSync(f) ? res.sendFile(f) : res.status(404).send('Not found');
});

// ── Auth helpers ──────────────────────────────────────────────────
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}
function verifyToken(t) { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } }
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const user = verifyToken(auth.split(' ')[1]);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user; next();
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: '管理者権限が必要です' });
  next();
}

// ── REST ──────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', mongo: !!usersCol, discord_bot: !!discordBot }));

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });

  const count = await Users.countDocuments();
  const role  = count === 0 ? 'admin' : 'member';
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(), username, usernameLower: username.toLowerCase(), passwordHash, role,
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
    createdAt: new Date(),
  };
  try { await Users.insertOne(user); }
  catch (e) { if (e.code === 11000) return res.status(409).json({ error: 'Username already taken' }); throw e; }
  res.json({ token: generateToken(user), user: { id: user.id, username: user.username, avatar: user.avatar, role: user.role } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await Users.findOne({ usernameLower: username?.toLowerCase() });
  if (!user || !await bcrypt.compare(password, user.passwordHash))
    return res.status(401).json({ error: 'Invalid username or password' });
  res.json({ token: generateToken(user), user: { id: user.id, username: user.username, avatar: user.avatar, role: user.role } });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await Users.findOne({ usernameLower: req.user.username.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, avatar: user.avatar, role: user.role });
});

app.get('/api/channels', authMiddleware, (req, res) => {
  const text  = Object.values(channels).map(c => ({ id: c.id, name: c.name, type: 'text' }));
  const voice = VOICE_CHANNELS.map(id => ({ id, name: id.replace('voice-',''), type: 'voice' }));
  res.json([...text, ...voice]);
});

app.get('/api/channels/:id/messages', authMiddleware, async (req, res) => {
  const channelId = req.params.id;
  const ch = channels[channelId];
  if (!ch) return res.status(404).json({ error: 'Channel not found' });
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);

  // システムメッセージを除外するフィルター
  const filterSystem = msgs => msgs.filter(m => m.type !== 'system');

  const discordHistory = await fetchDiscordHistory(channelId, limit);
  if (discordHistory && discordHistory.length > 0) {
    const existingIds = new Set(ch.messages.map(m => m.id));
    for (const msg of discordHistory) {
      if (!existingIds.has(msg.id)) {
        ch.messages.push(msg);
        if (messagesCol) messagesCol.updateOne({ id: msg.id }, { $setOnInsert: msg }, { upsert: true }).catch(() => {});
      }
    }
    return res.json(filterSystem([...ch.messages].sort((a,b) => new Date(a.timestamp)-new Date(b.timestamp))).slice(-limit));
  }

  if (messagesCol) {
    // MongoDB からはシステムメッセージを除外して取得
    const msgs = await messagesCol.find({ channelId, type: { $ne: 'system' } }).sort({ timestamp: 1 }).limit(limit).toArray();
    if (msgs.length > 0) return res.json(msgs);
  }
  res.json(filterSystem(ch.messages).slice(-limit));
});

app.get('/api/channels/:id/pins', authMiddleware, async (req, res) => {
  const channelId = req.params.id;
  const ch = channels[channelId];
  if (!ch) return res.status(404).json({ error: 'Channel not found' });
  if (pinsCol) return res.json(await pinsCol.find({ channelId }).sort({ pinnedAt: -1 }).toArray());
  res.json(ch.pins || []);
});

// 全文検索
app.get('/api/search', authMiddleware, async (req, res) => {
  const { q, channel } = req.query;
  if (!q || q.trim().length < 2) return res.status(400).json({ error: '検索ワードは2文字以上' });

  if (messagesCol) {
    const filter = { $text: { $search: q } };
    if (channel) filter.channelId = channel;
    const results = await messagesCol
      .find(filter, { projection: { score: { $meta: 'textScore' } } })
      .sort({ score: { $meta: 'textScore' } })
      .limit(20).toArray();
    return res.json(results);
  }
  // In-memory fallback
  const results = [];
  for (const ch of Object.values(channels)) {
    if (channel && ch.id !== channel) continue;
    for (const msg of ch.messages) {
      if (msg.type === 'text' && msg.content?.toLowerCase().includes(q.toLowerCase())) results.push(msg);
    }
  }
  res.json(results.slice(0, 20));
});

// DM 履歴
app.get('/api/dm/:roomId', authMiddleware, async (req, res) => {
  const { roomId } = req.params;
  const [u1, u2] = roomId.split('__');
  if (req.user.username !== u1 && req.user.username !== u2)
    return res.status(403).json({ error: 'Access denied' });
  if (dmsCol) return res.json(await dmsCol.find({ roomId }).sort({ timestamp: 1 }).limit(100).toArray());
  res.json(dmMessages[roomId] || []);
});

// ロール変更 (adminのみ)
app.put('/api/users/:username/role', authMiddleware, adminOnly, async (req, res) => {
  const { role } = req.body;
  if (!['admin','moderator','member'].includes(role)) return res.status(400).json({ error: '無効なロール' });
  const user = await Users.findOne({ usernameLower: req.params.username.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found' });
  await Users.updateOne({ usernameLower: req.params.username.toLowerCase() }, { $set: { role } });
  const sid = socketByUser[req.params.username];
  if (sid) io.to(sid).emit('role_changed', { role });
  io.emit('user_role_updated', { username: req.params.username, role });
  res.json({ ok: true, username: req.params.username, role });
});

app.get('/api/members', authMiddleware, async (req, res) => {
  const users = await Users.find();
  res.json(users.map(u => ({ id: u.id, username: u.username, avatar: u.avatar, role: u.role })));
});

app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  const users = await Users.find();
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, avatar: u.avatar })));
});

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    filename: req.file.originalname, url: `/uploads/${req.file.filename}`,
    mimetype: req.file.mimetype, size: req.file.size,
  });
});

// ── Socket.io ─────────────────────────────────────────────────────
io.use((socket, next) => {
  const user = verifyToken(socket.handshake.auth.token);
  if (!user) return next(new Error('Authentication error'));
  socket.user = user; next();
});

io.on('connection', async (socket) => {
  console.log(`[+] ${socket.user.username} connected`);
  const fullUser = await Users.findOne({ usernameLower: socket.user.username.toLowerCase() });
  socket.user.role   = fullUser?.role   || socket.user.role || 'member';
  socket.user.userId = fullUser?.id     || socket.user.id;

  onlineUsers[socket.id]            = { username: socket.user.username, userId: socket.user.userId, channelId: null, voiceChannelId: null };
  socketByUser[socket.user.username] = socket.id;
  broadcastOnlineUsers();

  // テキストチャンネル参加
  socket.on('join_channel', (channelId) => {
    if (!channels[channelId]) return;
    const prev = onlineUsers[socket.id]?.channelId;

    // 同じチャンネルへの再参加（再接続）は通知なしでルームだけ再登録
    if (prev === channelId) {
      socket.join(channelId);
      return;
    }

    if (prev) {
      socket.leave(prev);
      // 退出通知は履歴に保存せずリアルタイムのみ
      const leftMsg = buildMsg('system', `${socket.user.username} が退出しました`, prev, 'system');
      socket.to(prev).emit('message', leftMsg);
    }
    socket.join(channelId);
    onlineUsers[socket.id].channelId = channelId;
    // 参加通知は履歴に保存せず、他のユーザーへのリアルタイム通知のみ
    const sys = buildMsg('system', `${socket.user.username} が参加しました`, channelId, 'system');
    socket.to(channelId).emit('message', sys);
  });

  // メッセージ送信
  socket.on('send_message', async ({ channelId, content }) => {
    if (!channels[channelId] || !content?.trim()) return;
    const msg = buildMsg(socket.user.username, content.trim(), channelId, 'text');
    channels[channelId].messages.push(msg);
    if (messagesCol) messagesCol.insertOne({ ...msg }).catch(() => {});
    io.to(channelId).emit('message', msg);
    sendToDiscordViaBot(channelId, socket.user.username, content.trim()).catch(() => {});
  });

  // ファイル送信
  socket.on('send_file', async ({ channelId, fileInfo }) => {
    if (!channels[channelId] || !fileInfo) return;
    const msg = buildMsg(socket.user.username, fileInfo.filename, channelId, 'file', fileInfo);
    channels[channelId].messages.push(msg);
    if (messagesCol) messagesCol.insertOne({ ...msg }).catch(() => {});
    io.to(channelId).emit('message', msg);
    sendToDiscordViaBot(channelId, socket.user.username, null, fileInfo).catch(() => {});
  });

  // メッセージ編集
  socket.on('edit_message', async ({ msgId, channelId, content }) => {
    if (!channels[channelId] || !content?.trim()) return;
    const msg = channels[channelId].messages.find(m => m.id === msgId);
    if (!msg) return;
    if (msg.author !== socket.user.username && !['admin','moderator'].includes(socket.user.role)) return;
    msg.content  = content.trim();
    msg.edited   = true;
    msg.editedAt = new Date().toISOString();
    if (messagesCol) messagesCol.updateOne({ id: msgId }, { $set: { content: msg.content, edited: true, editedAt: msg.editedAt } }).catch(() => {});
    io.to(channelId).emit('message_edited', { msgId, channelId, content: msg.content, editedAt: msg.editedAt });
  });

  // メッセージ削除
  socket.on('delete_message', async ({ msgId, channelId }) => {
    if (!channels[channelId]) return;
    const msg = channels[channelId].messages.find(m => m.id === msgId);
    if (!msg) return;
    if (msg.author !== socket.user.username && !['admin','moderator'].includes(socket.user.role)) return;
    channels[channelId].messages = channels[channelId].messages.filter(m => m.id !== msgId);
    channels[channelId].pins     = (channels[channelId].pins || []).filter(p => p.id !== msgId);
    if (messagesCol) messagesCol.deleteOne({ id: msgId }).catch(() => {});
    if (pinsCol) pinsCol.deleteOne({ id: msgId, channelId }).catch(() => {});
    io.to(channelId).emit('message_deleted', { msgId, channelId });
  });

  // ピン留め
  socket.on('pin_message', async ({ msgId, channelId }) => {
    if (!channels[channelId] || !['admin','moderator'].includes(socket.user.role)) return;
    const msg = channels[channelId].messages.find(m => m.id === msgId);
    if (!msg || (channels[channelId].pins || []).find(p => p.id === msgId)) return;
    const pin = { ...msg, pinnedBy: socket.user.username, pinnedAt: new Date().toISOString() };
    channels[channelId].pins = channels[channelId].pins || [];
    channels[channelId].pins.push(pin);
    if (pinsCol) pinsCol.insertOne({ ...pin, channelId }).catch(() => {});
    io.to(channelId).emit('pin_update', { channelId, pins: channels[channelId].pins });
  });

  socket.on('unpin_message', async ({ msgId, channelId }) => {
    if (!channels[channelId] || !['admin','moderator'].includes(socket.user.role)) return;
    channels[channelId].pins = (channels[channelId].pins || []).filter(p => p.id !== msgId);
    if (pinsCol) pinsCol.deleteOne({ id: msgId, channelId }).catch(() => {});
    io.to(channelId).emit('pin_update', { channelId, pins: channels[channelId].pins });
  });

  // リアクション
  socket.on('add_reaction', ({ msgId, emoji, channelId }) => {
    if (!channels[channelId] || !msgId || !emoji) return;
    const msg = channels[channelId].messages.find(m => m.id === msgId);
    if (!msg) return;
    if (!msg.reactions) msg.reactions = {};
    if (!msg.reactions[emoji]) msg.reactions[emoji] = [];
    const users = msg.reactions[emoji];
    const idx   = users.indexOf(socket.user.username);
    if (idx === -1) users.push(socket.user.username);
    else { users.splice(idx,1); if(!users.length) delete msg.reactions[emoji]; }
    io.to(channelId).emit('reaction_update', { msgId, reactions: msg.reactions });
  });

  // タイピング
  socket.on('typing', ({ channelId, isTyping }) => {
    socket.to(channelId).emit('typing', { username: socket.user.username, isTyping });
  });

  // DM送信
  socket.on('send_dm', async ({ toUsername, content }) => {
    if (!content?.trim() || !toUsername) return;
    const roomId = [socket.user.username, toUsername].sort().join('__');
    const msg = {
      id: uuidv4(), author: socket.user.username, content: content.trim(),
      channelId: roomId, type: 'text', fileInfo: null,
      timestamp: new Date().toISOString(), isDM: true,
    };
    if (!dmMessages[roomId]) dmMessages[roomId] = [];
    dmMessages[roomId].push(msg);
    if (dmsCol) dmsCol.insertOne({ ...msg, roomId }).catch(() => {});
    socket.emit('dm_message', msg);
    const toSid = socketByUser[toUsername];
    if (toSid) io.to(toSid).emit('dm_message', msg);
  });

  // ボイスチャット参加
  socket.on('join_voice', (channelId) => {
    if (!VOICE_CHANNELS.includes(channelId)) return;
    const prevVoice = onlineUsers[socket.id]?.voiceChannelId;
    if (prevVoice) {
      if (voiceRooms[prevVoice]) delete voiceRooms[prevVoice][socket.id];
      socket.leave(`voice:${prevVoice}`);
      io.to(`voice:${prevVoice}`).emit('voice_user_left', { username: socket.user.username, socketId: socket.id, channelId: prevVoice });
    }
    if (!voiceRooms[channelId]) voiceRooms[channelId] = {};
    voiceRooms[channelId][socket.id] = { username: socket.user.username, userId: socket.user.userId };
    socket.join(`voice:${channelId}`);
    onlineUsers[socket.id].voiceChannelId = channelId;

    const existingUsers = Object.entries(voiceRooms[channelId])
      .filter(([sid]) => sid !== socket.id)
      .map(([sid, u]) => ({ ...u, socketId: sid }));

    socket.emit('voice_joined', { channelId, existingUsers });
    socket.to(`voice:${channelId}`).emit('voice_user_joined', {
      username: socket.user.username, userId: socket.user.userId, socketId: socket.id, channelId,
    });
    broadcastVoiceState();
  });

  socket.on('leave_voice', () => leaveVoice(socket));

  // WebRTC シグナリング リレー
  socket.on('voice_offer',  ({ to, offer })     => io.to(to).emit('voice_offer',  { from: socket.id, offer,     username: socket.user.username }));
  socket.on('voice_answer', ({ to, answer })    => io.to(to).emit('voice_answer', { from: socket.id, answer }));
  socket.on('voice_ice',    ({ to, candidate }) => io.to(to).emit('voice_ice',    { from: socket.id, candidate }));

  socket.on('disconnect', () => {
    console.log(`[-] ${socket.user.username} disconnected`);
    leaveVoice(socket);
    delete onlineUsers[socket.id];
    delete socketByUser[socket.user.username];
    broadcastOnlineUsers();
  });
});

// ── ヘルパー ──────────────────────────────────────────────────────
function leaveVoice(socket) {
  const channelId = onlineUsers[socket.id]?.voiceChannelId;
  if (!channelId) return;
  if (voiceRooms[channelId]) delete voiceRooms[channelId][socket.id];
  socket.leave(`voice:${channelId}`);
  if (onlineUsers[socket.id]) onlineUsers[socket.id].voiceChannelId = null;
  io.to(`voice:${channelId}`).emit('voice_user_left', { username: socket.user.username, socketId: socket.id, channelId });
  broadcastVoiceState();
}

function broadcastOnlineUsers() {
  io.emit('online_users', Object.values(onlineUsers).map(u => ({
    username: u.username, userId: u.userId, voiceChannelId: u.voiceChannelId || null,
  })));
}

function broadcastVoiceState() {
  const state = {};
  for (const [chId, room] of Object.entries(voiceRooms)) state[chId] = Object.values(room);
  io.emit('voice_state', state);
}

function buildMsg(author, content, channelId, type, fileInfo = null) {
  return { id: uuidv4(), author, content, channelId, type, fileInfo, timestamp: new Date().toISOString() };
}

// ── Start ─────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  connectMongo().catch(err => console.error('connectMongo error:', err));
  startDiscordBot();
});
