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

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-production';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'chatapp';

// Discord Webhook URLs per channel (設定は .env で行う)
// DISCORD_WEBHOOK_general=https://discord.com/api/webhooks/...
// DISCORD_WEBHOOK_random=https://discord.com/api/webhooks/...
// ※ チャンネル名をそのまま環境変数名に使う
function getDiscordWebhook(channelId) {
  return process.env[`DISCORD_WEBHOOK_${channelId}`] || process.env.DISCORD_WEBHOOK_DEFAULT || null;
}

// ── MongoDB ───────────────────────────────────────────────────────
let db;
let usersCol;

async function connectMongo() {
  if (!process.env.MONGO_URI) {
    throw new Error(
      '❌ MONGO_URI が設定されていません。\n' +
      'Render の Environment Variables に MONGO_URI (MongoDB Atlas の接続文字列) を追加してください。\n' +
      '例: mongodb+srv://<user>:<password>@cluster.mongodb.net/?retryWrites=true&w=majority'
    );
  }

  const client = new MongoClient(MONGO_URI, {
    serverSelectionTimeoutMS: 10000, // 10秒でタイムアウト（デフォルト30秒）
    connectTimeoutMS: 10000,
  });

  try {
    await client.connect();
    // 疎通確認
    await client.db('admin').command({ ping: 1 });
  } catch (err) {
    throw new Error(
      `❌ MongoDB に接続できません。\n` +
      `URI: ${MONGO_URI.replace(/:\/\/.*@/, '://<credentials>@')}\n` +
      `原因: ${err.message}\n\n` +
      `確認事項:\n` +
      `  1. MongoDB Atlas の Network Access で Render のIPを許可 (0.0.0.0/0 で全許可)\n` +
      `  2. MONGO_URI の username/password が正しいか\n` +
      `  3. Atlas クラスターが起動しているか`
    );
  }

  db = client.db(DB_NAME);
  usersCol = db.collection('users');
  await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
  console.log('✅ MongoDB connected');
}

// ── In-memory (channels & online users) ──────────────────────────
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

// ── Discord Webhook 送信 ──────────────────────────────────────────
async function sendToDiscord(channelId, username, content, fileInfo = null) {
  const webhookUrl = getDiscordWebhook(channelId);
  if (!webhookUrl) return; // Webhook未設定のチャンネルはスキップ

  try {
    const body = {
      username: `${username} (${channelId})`,
      avatar_url: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
    };

    if (fileInfo) {
      body.embeds = [{
        title: '📎 ' + fileInfo.filename,
        url: fileInfo.url,
        color: 0x5865F2,
        footer: { text: `#${channelId}` }
      }];
    } else {
      body.content = content;
    }

    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  } catch (err) {
    console.error('Discord webhook error:', err.message);
  }
}

// ── REST: Auth ────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20)
    return res.status(400).json({ error: 'Username must be 3-20 characters' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(),
    username,
    usernameLower: username.toLowerCase(),
    passwordHash,
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
    createdAt: new Date()
  };

  try {
    await usersCol.insertOne(user);
  } catch (e) {
    if (e.code === 11000)
      return res.status(409).json({ error: 'Username already taken' });
    throw e;
  }

  const token = generateToken(user);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await usersCol.findOne({ usernameLower: username?.toLowerCase() });
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

  const token = generateToken(user);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await usersCol.findOne({ usernameLower: req.user.username.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, avatar: user.avatar });
});

// ── REST: Channels ────────────────────────────────────────────────
app.get('/api/channels', authMiddleware, (req, res) => {
  res.json(Object.values(channels).map(c => ({ id: c.id, name: c.name })));
});

app.get('/api/channels/:id/messages', authMiddleware, (req, res) => {
  const ch = channels[req.params.id];
  if (!ch) return res.status(404).json({ error: 'Channel not found' });
  res.json(ch.messages.slice(-100));
});

// ── REST: File Upload ─────────────────────────────────────────────
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({
    filename:   req.file.originalname,
    url:        fileUrl,
    mimetype:   req.file.mimetype,
    size:       req.file.size,
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

  // テキストメッセージ → チャットに送信 + Discordへ転送
  socket.on('send_message', async ({ channelId, content }) => {
    if (!channels[channelId] || !content?.trim()) return;
    const msg = buildMessage(socket.user.username, content.trim(), channelId, 'text');
    channels[channelId].messages.push(msg);
    io.to(channelId).emit('message', msg);

    // Discord へ転送
    await sendToDiscord(channelId, socket.user.username, content.trim());
  });

  // ファイルメッセージ → チャットに送信 + Discordへ転送
  socket.on('send_file', async ({ channelId, fileInfo }) => {
    if (!channels[channelId] || !fileInfo) return;
    const msg = buildMessage(socket.user.username, fileInfo.filename, channelId, 'file', fileInfo);
    channels[channelId].messages.push(msg);
    io.to(channelId).emit('message', msg);

    // Discord へ転送（ファイル情報をEmbedで）
    await sendToDiscord(channelId, socket.user.username, null, fileInfo);
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
connectMongo().then(() => {
  server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);
});
