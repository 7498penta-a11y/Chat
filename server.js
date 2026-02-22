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

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-production';

// ── In-memory stores ──────────────────────────────────────────────
const users = {};    // { username: { id, username, passwordHash, avatar } }
const channels = {
  general:  { id: 'general',  name: 'general',  messages: [] },
  random:   { id: 'random',   name: 'random',   messages: [] },
  media:    { id: 'media',    name: 'media',    messages: [] },
  dev:      { id: 'dev',      name: 'dev',      messages: [] },
};
const onlineUsers = {}; // { socketId: { username, channelId } }

// ── Uploads dir ───────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// ── Multer storage ────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const ext  = path.extname(file.originalname);
    const name = uuidv4() + ext;
    cb(null, name);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
});

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
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  const user  = verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

// ── REST: Auth ────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  if (username.length < 3 || username.length > 20)
    return res.status(400).json({ error: 'Username must be 3-20 characters' });

  if (users[username.toLowerCase()])
    return res.status(409).json({ error: 'Username already taken' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(),
    username,
    passwordHash,
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
    createdAt: new Date().toISOString()
  };
  users[username.toLowerCase()] = user;
  const token = generateToken(user);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username?.toLowerCase()];
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

  const token = generateToken(user);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = users[req.user.username.toLowerCase()];
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
  res.json(ch.messages.slice(-100)); // last 100
});

// ── REST: File Upload ─────────────────────────────────────────────
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const fileUrl  = `/uploads/${req.file.filename}`;
  const fileInfo = {
    filename:     req.file.originalname,
    url:          fileUrl,
    mimetype:     req.file.mimetype,
    size:         req.file.size,
    uploadedBy:   req.user.username,
    uploadedAt:   new Date().toISOString()
  };
  res.json(fileInfo);
});

// ── Socket.io ─────────────────────────────────────────────────────
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const user  = verifyToken(token);
  if (!user) return next(new Error('Authentication error'));
  socket.user = user;
  next();
});

io.on('connection', (socket) => {
  console.log(`[+] ${socket.user.username} connected`);

  onlineUsers[socket.id] = { username: socket.user.username, channelId: null };
  io.emit('online_users', Object.values(onlineUsers).map(u => u.username));

  // Join channel
  socket.on('join_channel', (channelId) => {
    if (!channels[channelId]) return;

    // Leave old channel
    const prev = onlineUsers[socket.id]?.channelId;
    if (prev) socket.leave(prev);

    socket.join(channelId);
    onlineUsers[socket.id].channelId = channelId;

    // Notify channel
    const sysMsg = buildMessage('system', `${socket.user.username} joined #${channelId}`, channelId, 'system');
    channels[channelId].messages.push(sysMsg);
    socket.to(channelId).emit('message', sysMsg);
  });

  // Text message
  socket.on('send_message', ({ channelId, content }) => {
    if (!channels[channelId] || !content?.trim()) return;
    const msg = buildMessage(socket.user.username, content.trim(), channelId, 'text');
    channels[channelId].messages.push(msg);
    io.to(channelId).emit('message', msg);
  });

  // File message
  socket.on('send_file', ({ channelId, fileInfo }) => {
    if (!channels[channelId] || !fileInfo) return;
    const msg = buildMessage(socket.user.username, fileInfo.filename, channelId, 'file', fileInfo);
    channels[channelId].messages.push(msg);
    io.to(channelId).emit('message', msg);
  });

  // Typing
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
  return {
    id:        uuidv4(),
    author,
    content,
    channelId,
    type,       // 'text' | 'file' | 'system'
    fileInfo,
    timestamp:  new Date().toISOString()
  };
}

// ── Start ─────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
