require(‘dotenv’).config();
const express = require(‘express’);
const http    = require(‘http’);
const { Server } = require(‘socket.io’);
const multer  = require(‘multer’);
const bcrypt  = require(‘bcryptjs’);
const jwt     = require(‘jsonwebtoken’);
const { v4: uuidv4 } = require(‘uuid’);
const path    = require(‘path’);
const fs      = require(‘fs’);
const cors    = require(‘cors’);
const { MongoClient } = require(‘mongodb’);
const { Client, GatewayIntentBits, AttachmentBuilder } = require(‘discord.js’);

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: ‘*’, methods: [‘GET’,‘POST’] } });

const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || ‘super-secret-key-change-in-production’;
const MONGO_URI  = process.env.MONGO_URI  || ‘’;
const DB_NAME    = process.env.DB_NAME    || ‘chatapp’;

// .envで管理者ユーザーを指定 (ADMIN_USERS=alice,bob)
const ENV_ADMINS = new Set(
(process.env.ADMIN_USERS || ‘’).split(’,’).map(s => s.trim().toLowerCase()).filter(Boolean)
);

// 招待コード必須かどうか (INVITE_ONLY=true)
const INVITE_ONLY = process.env.INVITE_ONLY === ‘true’;

// ── Discord ──────────────────────────────────────────────────────
let discordBot = null;
const APP_CHANNELS_DEFAULT = [‘general’,‘random’,‘media’,‘dev’];
const discordToApp = {};

function getDiscordChannelId(appCh) {
return process.env[`DISCORD_CHANNEL_ID_${appCh}`] || null;
}

function discordMsgToApp(dMsg, appChannelId) {
const isOurBot = discordBot && dMsg.author?.id === discordBot.user?.id;
const isOtherBot = !isOurBot && dMsg.author?.bot;
let author, content;
if (isOurBot) {
const match = dMsg.content?.match(/^**[(.+?)]**: ([\s\S]*)$/);
if (match) { author = match[1]; content = match[2]; }
else { author = ‘Web User’; content = dMsg.content; }
} else if (isOtherBot) {
author = `${dMsg.author?.username} [Bot]`;
content = dMsg.content;
} else {
author = `${dMsg.author?.username} [Discord]`;
content = dMsg.content;
}
const attach = dMsg.attachments?.first();
if (attach) {
const isImage = attach.contentType?.startsWith(‘image/’) ?? /.(png|jpe?g|gif|webp)$/i.test(attach.name);
return { id: dMsg.id, author, content: attach.name, channelId: appChannelId, type: ‘file’,
fileInfo: { filename: attach.name, url: attach.url, mimetype: attach.contentType || (isImage ? ‘image/png’ : ‘application/octet-stream’), size: attach.size || 0 },
timestamp: dMsg.createdAt.toISOString(), fromDiscord: true };
}
return { id: dMsg.id, author, content: content || ‘’, channelId: appChannelId, type: ‘text’, fileInfo: null,
timestamp: dMsg.createdAt.toISOString(), fromDiscord: true };
}

async function fetchDiscordHistory(appChannelId, limit = 50) {
if (!discordBot) return null;
const discordChId = getDiscordChannelId(appChannelId);
if (!discordChId) return null;
try {
const ch = await discordBot.channels.fetch(discordChId);
if (!ch || !ch.isTextBased()) return null;
const fetched = await ch.messages.fetch({ limit });
const sorted = […fetched.values()].sort((a,b) => a.createdTimestamp - b.createdTimestamp);
return sorted.filter(m => m.content || m.attachments.size > 0).map(m => discordMsgToApp(m, appChannelId));
} catch (err) {
console.error(`[Discord履歴] #${appChannelId} 取得失敗:`, err.message);
return null;
}
}

async function sendToDiscordViaBot(appChannelId, username, content, fileInfo = null) {
if (!discordBot) return;
const discordChId = getDiscordChannelId(appChannelId);
if (!discordChId) return;
try {
const ch = await discordBot.channels.fetch(discordChId);
if (!ch?.isTextBased()) return;
if (fileInfo) {
const origName = fileInfo.filename || ‘file’;
const label = `**[${username}]**: 📎 ${origName}`;
let localPath = null;
if (fileInfo.url && !fileInfo.url.startsWith(‘http’)) {
const rel = fileInfo.url.startsWith(’/’) ? fileInfo.url.slice(1) : fileInfo.url;
localPath = path.join(__dirname, rel);
}
if (localPath && fs.existsSync(localPath)) {
const buffer = fs.readFileSync(localPath);
const attachment = new AttachmentBuilder(buffer, { name: origName });
await ch.send({ content: label, files: [attachment] }); return;
}
if (fileInfo.url?.startsWith(‘http’)) {
const isImg = fileInfo.mimetype?.startsWith(‘image/’) || /.(png|jpe?g|gif|webp)$/i.test(origName);
await ch.send(isImg ? `**[${username}]**:\n${fileInfo.url}` : `${label}\n${fileInfo.url}`); return;
}
await ch.send(`${label} (送信失敗)`);
} else {
await ch.send(`**[${username}]**: ${content}`);
}
} catch (err) { console.error(`[Bot→Discord] ❌ ${err.message}`); }
}

function startDiscordBot() {
const botToken = process.env.DISCORD_BOT_TOKEN;
if (!botToken) { console.warn(‘⚠️  DISCORD_BOT_TOKEN 未設定’); return; }
const bot = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });
bot.once(‘clientReady’, () => {
discordBot = bot;
console.log(`✅ Discord Bot: ${bot.user.tag}`);
Object.keys(channels).forEach(appCh => {
const id = getDiscordChannelId(appCh);
if (id) { discordToApp[id] = appCh; console.log(`  📌 #${id} ↔ #${appCh}`); }
});
});
bot.on(‘messageCreate’, (message) => {
if (message.author.id === bot.user?.id) return;
const appChannelId = discordToApp[message.channelId];
if (!appChannelId) return;
const msg = discordMsgToApp(message, appChannelId);
channels[appChannelId]?.messages.push(msg);
if (messagesCol) messagesCol.insertOne({ …msg }).catch(() => {});
io.to(appChannelId).emit(‘message’, msg);
});
bot.on(‘error’, err => console.error(’[Discord Bot]’, err.message));
bot.login(botToken).catch(err => console.error(‘❌ Discord Bot ログイン失敗:’, err.message));
}

// ── MongoDB ───────────────────────────────────────────────────────
let usersCol, messagesCol, dmsCol, pinsCol, channelsCol, invitesCol, bookmarksCol, sessionsCol, customEmojisCol;

async function connectMongo() {
if (!MONGO_URI) { console.warn(‘⚠️  MONGO_URI 未設定 → インメモリモード’); return; }
const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 8000 });
try {
await client.connect();
const db = client.db(DB_NAME);
usersCol      = db.collection(‘users’);
messagesCol   = db.collection(‘messages’);
dmsCol        = db.collection(‘dms’);
pinsCol       = db.collection(‘pins’);
channelsCol   = db.collection(‘channels’);
invitesCol    = db.collection(‘invites’);
bookmarksCol  = db.collection(‘bookmarks’);
sessionsCol   = db.collection(‘sessions’);
customEmojisCol = db.collection(‘custom_emojis’);
await usersCol.createIndex({ usernameLower: 1 }, { unique: true });
await messagesCol.createIndex({ content: ‘text’ });
await messagesCol.createIndex({ channelId: 1, timestamp: 1 });
await messagesCol.createIndex({ author: 1 });
await dmsCol.createIndex({ roomId: 1, timestamp: 1 });
await invitesCol.createIndex({ code: 1 }, { unique: true });
await invitesCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
await sessionsCol.createIndex({ userId: 1 });
const deleted = await messagesCol.deleteMany({ type: ‘system’ });
if (deleted.deletedCount > 0) console.log(`🧹 システムメッセージ ${deleted.deletedCount} 件削除`);
// 保存されたチャンネルを読み込む
const savedChannels = await channelsCol.find({}).toArray();
for (const ch of savedChannels) {
if (!channels[ch.id]) channels[ch.id] = { id: ch.id, name: ch.name, topic: ch.topic||’’, readonly: ch.readonly||false, messages: [], pins: [] };
else Object.assign(channels[ch.id], { topic: ch.topic||’’, readonly: ch.readonly||false });
}
console.log(‘✅ MongoDB connected’);
} catch (err) {
console.error(‘❌ MongoDB 接続失敗:’, err.message);
usersCol = messagesCol = dmsCol = pinsCol = channelsCol = invitesCol = bookmarksCol = sessionsCol = customEmojisCol = null;
}
}

// ── In-memory state ───────────────────────────────────────────────
const channels = {};
APP_CHANNELS_DEFAULT.forEach(id => {
channels[id] = { id, name: id, topic: ‘’, readonly: false, messages: [], pins: [] };
});

const dmMessages   = {};
const onlineUsers  = {};   // socketId → { username, userId, status }
const socketByUser = {};
const userStatus   = {};   // username → ‘online’|‘away’|‘busy’
const mutedUsers   = new Set();  // username
const bannedUsers  = new Set();  // username
const customEmojis = {};   // :name: → url

// ── In-memory users ───────────────────────────────────────────────
const inMemoryUsers = {};
const Users = {
async findOne(q) {
if (usersCol) return usersCol.findOne(q);
if (q.usernameLower !== undefined) return Object.values(inMemoryUsers).find(u => u.usernameLower === q.usernameLower) || null;
if (q.id) return Object.values(inMemoryUsers).find(u => u.id === q.id) || null;
return null;
},
async insertOne(doc) {
if (usersCol) return usersCol.insertOne(doc);
if (inMemoryUsers[doc.usernameLower]) { const e = new Error(‘dup’); e.code = 11000; throw e; }
inMemoryUsers[doc.usernameLower] = doc; return { insertedId: doc.id };
},
async updateOne(q, update) {
if (usersCol) return usersCol.updateOne(q, update);
const user = await this.findOne(q);
if (user && update.$set) Object.assign(user, update.$set);
},
async deleteOne(q) {
if (usersCol) return usersCol.deleteOne(q);
const user = await this.findOne(q);
if (user) delete inMemoryUsers[user.usernameLower];
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

// ── Uploads ───────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, ‘uploads’);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
const storage = multer.diskStorage({
destination: (req, file, cb) => cb(null, UPLOADS_DIR),
filename:    (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ── Middleware ─────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, ‘public’)));
app.use(’/uploads’, express.static(UPLOADS_DIR));
app.get(’/’, (req, res) => {
const f = path.join(__dirname, ‘public/index.html’);
fs.existsSync(f) ? res.sendFile(f) : res.status(404).send(‘Not found’);
});

// ── Auth helpers ──────────────────────────────────────────────────
function generateToken(user) {
return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: ‘7d’ });
}
function verifyToken(t) { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } }
function authMiddleware(req, res, next) {
const auth = req.headers.authorization;
if (!auth) return res.status(401).json({ error: ‘No token’ });
const user = verifyToken(auth.split(’ ’)[1]);
if (!user) return res.status(401).json({ error: ‘Invalid token’ });
req.user = user; next();
}
function adminOnly(req, res, next) {
if (req.user?.role !== ‘admin’) return res.status(403).json({ error: ‘管理者権限が必要です’ });
next();
}
function modOrAdmin(req, res, next) {
if (![‘admin’,‘moderator’].includes(req.user?.role)) return res.status(403).json({ error: ‘モデレーター以上の権限が必要です’ });
next();
}

// ── REST ──────────────────────────────────────────────────────────
app.get(’/health’, (req, res) => res.json({ status: ‘ok’, mongo: !!usersCol, discord: !!discordBot }));

// 登録
app.post(’/api/register’, async (req, res) => {
const { username, password, inviteCode } = req.body;
if (!username || !password) return res.status(400).json({ error: ‘ユーザー名とパスワードが必要です’ });
if (username.length < 3 || username.length > 20) return res.status(400).json({ error: ‘ユーザー名は3〜20文字’ });
if (/[^a-zA-Z0-9_-]/.test(username)) return res.status(400).json({ error: ‘ユーザー名に使える文字: 英数字・_・-’ });

// 招待制チェック
if (INVITE_ONLY) {
if (!inviteCode) return res.status(403).json({ error: ‘招待コードが必要です’, inviteRequired: true });
const invite = invitesCol
? await invitesCol.findOne({ code: inviteCode, used: false })
: null;
if (!invite) return res.status(403).json({ error: ‘無効または使用済みの招待コードです’ });
if (invite.expiresAt && new Date(invite.expiresAt) < new Date())
return res.status(403).json({ error: ‘招待コードの期限が切れています’ });
// 使用済みにする
if (invitesCol) await invitesCol.updateOne({ code: inviteCode }, { $set: { used: true, usedAt: new Date(), usedBy: username } });
}

const count = await Users.countDocuments();
// .envのADMIN_USERSまたは最初のユーザーはadmin
const isEnvAdmin = ENV_ADMINS.has(username.toLowerCase());
const role = (isEnvAdmin || count === 0) ? ‘admin’ : ‘member’;
const passwordHash = await bcrypt.hash(password, 10);
const user = {
id: uuidv4(), username, usernameLower: username.toLowerCase(), passwordHash, role,
avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
createdAt: new Date(), keywordNotifs: [],
};
try { await Users.insertOne(user); }
catch (e) { if (e.code === 11000) return res.status(409).json({ error: ‘このユーザー名は使われています’ }); throw e; }
res.json({ token: generateToken(user), user: { id: user.id, username: user.username, avatar: user.avatar, role: user.role } });
});

// ログイン
app.post(’/api/login’, async (req, res) => {
const { username, password } = req.body;
const user = await Users.findOne({ usernameLower: username?.toLowerCase() });
if (!user || !await bcrypt.compare(password, user.passwordHash))
return res.status(401).json({ error: ‘ユーザー名またはパスワードが違います’ });
if (bannedUsers.has(user.username)) return res.status(403).json({ error: ‘このアカウントはBANされています’ });

// .envのADMIN_USERSに含まれていればadminに昇格
if (ENV_ADMINS.has(user.usernameLower) && user.role !== ‘admin’) {
await Users.updateOne({ usernameLower: user.usernameLower }, { $set: { role: ‘admin’ } });
user.role = ‘admin’;
}

// セッション記録
const sessionEntry = { userId: user.id, username: user.username, ip: req.ip, ua: req.headers[‘user-agent’]||’’, loginAt: new Date() };
if (sessionsCol) sessionsCol.insertOne(sessionEntry).catch(() => {});

res.json({ token: generateToken(user), user: { id: user.id, username: user.username, avatar: user.avatar, role: user.role } });
});

// 自分の情報
app.get(’/api/me’, authMiddleware, async (req, res) => {
const user = await Users.findOne({ usernameLower: req.user.username.toLowerCase() });
if (!user) return res.status(404).json({ error: ‘User not found’ });
res.json({ id: user.id, username: user.username, avatar: user.avatar, role: user.role, keywordNotifs: user.keywordNotifs || [] });
});

// チャンネル一覧
app.get(’/api/channels’, authMiddleware, (req, res) => {
res.json(Object.values(channels).map(c => ({ id: c.id, name: c.name, type: ‘text’, topic: c.topic||’’, readonly: c.readonly||false })));
});

// チャンネル作成 (admin)
app.post(’/api/channels’, authMiddleware, adminOnly, async (req, res) => {
const { name, topic, readonly } = req.body;
if (!name || !/^[a-z0-9-_]+$/.test(name)) return res.status(400).json({ error: ‘チャンネル名は小文字英数字・-・_のみ’ });
if (channels[name]) return res.status(409).json({ error: ‘このチャンネル名は既に存在します’ });
const ch = { id: name, name, topic: topic||’’, readonly: readonly||false, messages: [], pins: [] };
channels[name] = ch;
if (channelsCol) channelsCol.insertOne({ id: name, name, topic: topic||’’, readonly: readonly||false }).catch(() => {});
io.emit(‘channel_updated’, { action: ‘created’, channel: { id: ch.id, name: ch.name, topic: ch.topic, readonly: ch.readonly, type: ‘text’ } });
res.json({ ok: true, channel: { id: ch.id, name: ch.name, topic: ch.topic, readonly: ch.readonly } });
});

// チャンネル更新 (admin)
app.put(’/api/channels/:id’, authMiddleware, adminOnly, async (req, res) => {
const ch = channels[req.params.id];
if (!ch) return res.status(404).json({ error: ‘Channel not found’ });
const { name, topic, readonly } = req.body;
if (topic !== undefined) ch.topic = topic;
if (readonly !== undefined) ch.readonly = readonly;
if (channelsCol) channelsCol.updateOne({ id: ch.id }, { $set: { topic: ch.topic, readonly: ch.readonly } }, { upsert: true }).catch(() => {});
io.emit(‘channel_updated’, { action: ‘updated’, channel: { id: ch.id, name: ch.name, topic: ch.topic, readonly: ch.readonly, type: ‘text’ } });
res.json({ ok: true });
});

// チャンネル削除 (admin)
app.delete(’/api/channels/:id’, authMiddleware, adminOnly, async (req, res) => {
const id = req.params.id;
if (APP_CHANNELS_DEFAULT.includes(id)) return res.status(400).json({ error: ‘デフォルトチャンネルは削除できません’ });
if (!channels[id]) return res.status(404).json({ error: ‘Channel not found’ });
delete channels[id];
if (channelsCol) channelsCol.deleteOne({ id }).catch(() => {});
if (messagesCol) messagesCol.deleteMany({ channelId: id }).catch(() => {});
io.emit(‘channel_updated’, { action: ‘deleted’, channelId: id });
res.json({ ok: true });
});

// メッセージ履歴
app.get(’/api/channels/:id/messages’, authMiddleware, async (req, res) => {
const channelId = req.params.id;
const ch = channels[channelId];
if (!ch) return res.status(404).json({ error: ‘Channel not found’ });
const limit  = Math.min(parseInt(req.query.limit)  || 50, 100);
const before = req.query.before; // タイムスタンプでページング

const filterSystem = msgs => msgs.filter(m => m.type !== ‘system’);
function dedup(msgs) {
const seenIds = new Set(), seenContent = new Map();
return msgs.filter(m => {
if (seenIds.has(m.id)) return false;
seenIds.add(m.id);
const key = `${m.author}|${m.type}|${m.content||''}`;
const ts = new Date(m.timestamp).getTime();
if (seenContent.has(key) && Math.abs(ts - seenContent.get(key)) < 10000) return false;
seenContent.set(key, ts); return true;
});
}

const discordHistory = await fetchDiscordHistory(channelId, limit);
if (discordHistory?.length > 0) {
const existingIds = new Set(ch.messages.map(m => m.id));
for (const msg of discordHistory) {
if (!existingIds.has(msg.id)) { ch.messages.push(msg); if (messagesCol) messagesCol.updateOne({ id: msg.id }, { $setOnInsert: msg }, { upsert: true }).catch(() => {}); }
}
}

let merged = […ch.messages];
if (messagesCol) {
const filter = { channelId, type: { $ne: ‘system’ } };
if (before) filter.timestamp = { $lt: before };
const dbMsgs = await messagesCol.find(filter).sort({ timestamp: 1 }).limit(limit * 2).toArray();
const existingIds = new Set(merged.map(m => m.id));
for (const m of dbMsgs) { if (!existingIds.has(m.id)) merged.push(m); }
}

let sorted = merged.sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
if (before) sorted = sorted.filter(m => m.timestamp < before);
res.json(dedup(filterSystem(sorted)).slice(-limit));
});

// ピン
app.get(’/api/channels/:id/pins’, authMiddleware, async (req, res) => {
const ch = channels[req.params.id];
if (!ch) return res.status(404).json({ error: ‘Channel not found’ });
if (pinsCol) return res.json(await pinsCol.find({ channelId: req.params.id }).sort({ pinnedAt: -1 }).toArray());
res.json(ch.pins || []);
});

// 検索（強化版: 日付・ユーザー・チャンネルフィルター）
app.get(’/api/search’, authMiddleware, async (req, res) => {
const { q, channel, author, from, to } = req.query;
if (!q || q.trim().length < 2) return res.status(400).json({ error: ‘検索ワードは2文字以上’ });

if (messagesCol) {
const filter = { $text: { $search: q } };
if (channel) filter.channelId = channel;
if (author)  filter.author    = new RegExp(author, ‘i’);
if (from || to) {
filter.timestamp = {};
if (from) filter.timestamp.$gte = from;
if (to)   filter.timestamp.$lte = to;
}
const results = await messagesCol
.find(filter, { projection: { score: { $meta: ‘textScore’ } } })
.sort({ score: { $meta: ‘textScore’ } }).limit(30).toArray();
return res.json(results);
}
const results = [];
for (const ch of Object.values(channels)) {
if (channel && ch.id !== channel) continue;
for (const msg of ch.messages) {
if (msg.type !== ‘text’) continue;
if (!msg.content?.toLowerCase().includes(q.toLowerCase())) continue;
if (author && !msg.author?.toLowerCase().includes(author.toLowerCase())) continue;
if (from && msg.timestamp < from) continue;
if (to   && msg.timestamp > to)   continue;
results.push(msg);
}
}
res.json(results.slice(0, 30));
});

// DM履歴
app.get(’/api/dm/:roomId’, authMiddleware, async (req, res) => {
const { roomId } = req.params;
const [u1,u2] = roomId.split(’__’);
if (req.user.username !== u1 && req.user.username !== u2) return res.status(403).json({ error: ‘Access denied’ });
if (dmsCol) return res.json(await dmsCol.find({ roomId }).sort({ timestamp: 1 }).limit(100).toArray());
res.json(dmMessages[roomId] || []);
});

// ロール変更 (admin)
app.put(’/api/users/:username/role’, authMiddleware, adminOnly, async (req, res) => {
const { role } = req.body;
if (![‘admin’,‘moderator’,‘member’].includes(role)) return res.status(400).json({ error: ‘無効なロール’ });
const user = await Users.findOne({ usernameLower: req.params.username.toLowerCase() });
if (!user) return res.status(404).json({ error: ‘User not found’ });
await Users.updateOne({ usernameLower: req.params.username.toLowerCase() }, { $set: { role } });
const sid = socketByUser[req.params.username];
if (sid) io.to(sid).emit(‘role_changed’, { role });
io.emit(‘user_role_updated’, { username: req.params.username, role });
res.json({ ok: true });
});

// BAN (admin/mod)
app.post(’/api/users/:username/ban’, authMiddleware, modOrAdmin, async (req, res) => {
const { username } = req.params;
if (username === req.user.username) return res.status(400).json({ error: ‘自分自身はBANできません’ });
const user = await Users.findOne({ usernameLower: username.toLowerCase() });
if (!user) return res.status(404).json({ error: ‘User not found’ });
if (user.role === ‘admin’) return res.status(403).json({ error: ‘管理者はBANできません’ });
bannedUsers.add(username);
await Users.updateOne({ usernameLower: username.toLowerCase() }, { $set: { banned: true } });
const sid = socketByUser[username];
if (sid) { io.to(sid).emit(‘force_logout’, { reason: ‘BANされました’ }); }
io.emit(‘user_banned’, { username });
res.json({ ok: true });
});

app.post(’/api/users/:username/unban’, authMiddleware, modOrAdmin, async (req, res) => {
bannedUsers.delete(req.params.username);
await Users.updateOne({ usernameLower: req.params.username.toLowerCase() }, { $set: { banned: false } });
io.emit(‘user_unbanned’, { username: req.params.username });
res.json({ ok: true });
});

// ミュート (admin/mod)
app.post(’/api/users/:username/mute’, authMiddleware, modOrAdmin, async (req, res) => {
const { username } = req.params;
if (username === req.user.username) return res.status(400).json({ error: ‘自分自身はミュートできません’ });
const user = await Users.findOne({ usernameLower: username.toLowerCase() });
if (user?.role === ‘admin’) return res.status(403).json({ error: ‘管理者はミュートできません’ });
mutedUsers.add(username);
await Users.updateOne({ usernameLower: username.toLowerCase() }, { $set: { muted: true } });
const sid = socketByUser[username];
if (sid) io.to(sid).emit(‘muted’, { reason: ‘ミュートされました’ });
res.json({ ok: true });
});

app.post(’/api/users/:username/unmute’, authMiddleware, modOrAdmin, async (req, res) => {
mutedUsers.delete(req.params.username);
await Users.updateOne({ usernameLower: req.params.username.toLowerCase() }, { $set: { muted: false } });
const sid = socketByUser[req.params.username];
if (sid) io.to(sid).emit(‘unmuted’, {});
res.json({ ok: true });
});

// メンバー一覧
app.get(’/api/members’, authMiddleware, async (req, res) => {
const users = await Users.find();
res.json(users.map(u => ({ id: u.id, username: u.username, avatar: u.avatar, role: u.role, banned: u.banned||false, muted: u.muted||false })));
});

app.get(’/api/users’, authMiddleware, adminOnly, async (req, res) => {
const users = await Users.find();
res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, avatar: u.avatar, banned: u.banned||false, muted: u.muted||false })));
});

// プロフィール更新（アバター）
app.put(’/api/profile/avatar’, authMiddleware, async (req, res) => {
const { avatar } = req.body;
if (!avatar) return res.status(400).json({ error: ‘avatar required’ });
await Users.updateOne({ usernameLower: req.user.username.toLowerCase() }, { $set: { avatar } });
io.emit(‘user_avatar_updated’, { username: req.user.username, avatar });
res.json({ ok: true, avatar });
});

// パスワード変更
app.put(’/api/profile/password’, authMiddleware, async (req, res) => {
const { currentPassword, newPassword } = req.body;
if (!currentPassword || !newPassword) return res.status(400).json({ error: ‘現在のパスワードと新しいパスワードが必要です’ });
if (newPassword.length < 6) return res.status(400).json({ error: ‘新しいパスワードは6文字以上にしてください’ });
const user = await Users.findOne({ usernameLower: req.user.username.toLowerCase() });
if (!user) return res.status(404).json({ error: ‘User not found’ });
if (!await bcrypt.compare(currentPassword, user.passwordHash)) return res.status(401).json({ error: ‘現在のパスワードが違います’ });
const passwordHash = await bcrypt.hash(newPassword, 10);
await Users.updateOne({ usernameLower: user.usernameLower }, { $set: { passwordHash } });
res.json({ ok: true });
});

// キーワード通知設定
app.put(’/api/profile/keywords’, authMiddleware, async (req, res) => {
const { keywords } = req.body;
if (!Array.isArray(keywords)) return res.status(400).json({ error: ‘keywords must be array’ });
const kws = keywords.map(k => k.trim().toLowerCase()).filter(Boolean).slice(0, 20);
await Users.updateOne({ usernameLower: req.user.username.toLowerCase() }, { $set: { keywordNotifs: kws } });
res.json({ ok: true, keywords: kws });
});

// ログイン履歴
app.get(’/api/profile/sessions’, authMiddleware, async (req, res) => {
if (!sessionsCol) return res.json([]);
const sessions = await sessionsCol.find({ userId: req.user.id }).sort({ loginAt: -1 }).limit(10).toArray();
res.json(sessions.map(s => ({ ip: s.ip, ua: s.ua, loginAt: s.loginAt })));
});

// ブックマーク
app.get(’/api/bookmarks’, authMiddleware, async (req, res) => {
if (bookmarksCol) return res.json(await bookmarksCol.find({ userId: req.user.id }).sort({ createdAt: -1 }).toArray());
res.json([]);
});

app.post(’/api/bookmarks’, authMiddleware, async (req, res) => {
const { msgId, channelId, content, author, timestamp } = req.body;
if (!msgId) return res.status(400).json({ error: ‘msgId required’ });
const bm = { id: uuidv4(), userId: req.user.id, msgId, channelId, content, author, timestamp, createdAt: new Date() };
if (bookmarksCol) await bookmarksCol.updateOne({ userId: req.user.id, msgId }, { $setOnInsert: bm }, { upsert: true });
res.json({ ok: true });
});

app.delete(’/api/bookmarks/:msgId’, authMiddleware, async (req, res) => {
if (bookmarksCol) await bookmarksCol.deleteOne({ userId: req.user.id, msgId: req.params.msgId });
res.json({ ok: true });
});

// 招待コード生成 (admin/mod)
app.post(’/api/invites’, authMiddleware, modOrAdmin, async (req, res) => {
const { expiresIn } = req.body; // 時間(h)
const code = uuidv4().split(’-’)[0].toUpperCase();
const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 3600000) : null;
const invite = { code, createdBy: req.user.username, createdAt: new Date(), expiresAt, used: false };
if (invitesCol) await invitesCol.insertOne(invite);
res.json({ code, expiresAt });
});

app.get(’/api/invites’, authMiddleware, modOrAdmin, async (req, res) => {
if (!invitesCol) return res.json([]);
res.json(await invitesCol.find({}).sort({ createdAt: -1 }).limit(20).toArray());
});

app.delete(’/api/invites/:code’, authMiddleware, modOrAdmin, async (req, res) => {
if (invitesCol) await invitesCol.deleteOne({ code: req.params.code });
res.json({ ok: true });
});

// カスタム絵文字
app.get(’/api/emojis’, authMiddleware, (req, res) => {
if (customEmojisCol) {
customEmojisCol.find({}).toArray().then(list => res.json(list)).catch(() => res.json(Object.entries(customEmojis).map(([name, url]) => ({ name, url }))));
} else {
res.json(Object.entries(customEmojis).map(([name, url]) => ({ name, url })));
}
});

app.post(’/api/emojis’, authMiddleware, modOrAdmin, upload.single(‘image’), async (req, res) => {
const { name } = req.body;
if (!name || !/^[a-z0-9_]+$/.test(name)) return res.status(400).json({ error: ‘絵文字名は小文字英数字・_のみ’ });
if (!req.file) return res.status(400).json({ error: ‘image required’ });
const url = `/uploads/${req.file.filename}`;
customEmojis[name] = url;
if (customEmojisCol) customEmojisCol.updateOne({ name }, { $set: { name, url } }, { upsert: true }).catch(() => {});
io.emit(‘custom_emoji_updated’, { name, url });
res.json({ ok: true, name, url });
});

app.delete(’/api/emojis/:name’, authMiddleware, modOrAdmin, async (req, res) => {
delete customEmojis[req.params.name];
if (customEmojisCol) customEmojisCol.deleteOne({ name: req.params.name }).catch(() => {});
io.emit(‘custom_emoji_deleted’, { name: req.params.name });
res.json({ ok: true });
});

// ファイルアップロード
app.post(’/api/upload’, authMiddleware, upload.single(‘file’), (req, res) => {
if (!req.file) return res.status(400).json({ error: ‘No file uploaded’ });
res.json({ filename: req.file.originalname, url: `/uploads/${req.file.filename}`, mimetype: req.file.mimetype, size: req.file.size });
});

// アカウント削除
app.delete(’/api/account’, authMiddleware, async (req, res) => {
const { password } = req.body;
const user = await Users.findOne({ usernameLower: req.user.username.toLowerCase() });
if (!user) return res.status(404).json({ error: ‘User not found’ });
if (!await bcrypt.compare(password, user.passwordHash)) return res.status(401).json({ error: ‘パスワードが違います’ });
if (user.role === ‘admin’) {
const allUsers = await Users.find();
const otherAdmins = allUsers.filter(u => u.role === ‘admin’ && u.id !== user.id);
if (otherAdmins.length === 0 && allUsers.length > 1) return res.status(400).json({ error: ‘唯一の管理者は削除できません’ });
}
if (usersCol) await usersCol.deleteOne({ id: user.id });
else delete inMemoryUsers[user.usernameLower];
res.json({ ok: true });
});

// ── Socket.io ─────────────────────────────────────────────────────
io.use((socket, next) => {
const user = verifyToken(socket.handshake.auth.token);
if (!user) return next(new Error(‘Authentication error’));
socket.user = user; next();
});

io.on(‘connection’, async (socket) => {
const fullUser = await Users.findOne({ usernameLower: socket.user.username.toLowerCase() });
if (!fullUser) return socket.disconnect();
if (fullUser.banned) { socket.emit(‘force_logout’, { reason: ‘BANされています’ }); return socket.disconnect(); }

socket.user.role   = fullUser.role   || ‘member’;
socket.user.userId = fullUser.id;

onlineUsers[socket.id]             = { username: socket.user.username, userId: socket.user.userId, status: userStatus[socket.user.username] || ‘online’ };
socketByUser[socket.user.username] = socket.id;
if (fullUser.muted) mutedUsers.add(socket.user.username);
broadcastOnlineUsers();

// カスタム絵文字を送信
socket.emit(‘custom_emojis’, Object.entries(customEmojis).map(([name,url]) => ({ name, url })));

// チャンネル参加
socket.on(‘join_channel’, (channelId) => {
if (!channels[channelId]) return;
const prev = onlineUsers[socket.id]?.channelId;
if (prev) socket.leave(prev);
socket.join(channelId);
onlineUsers[socket.id].channelId = channelId;
});

// ステータス変更
socket.on(‘set_status’, (status) => {
if (![‘online’,‘away’,‘busy’].includes(status)) return;
userStatus[socket.user.username] = status;
if (onlineUsers[socket.id]) onlineUsers[socket.id].status = status;
broadcastOnlineUsers();
});

// メッセージ送信
socket.on(‘send_message’, async ({ channelId, content, threadOf }) => {
if (!channels[channelId] || !content?.trim()) return;
if (mutedUsers.has(socket.user.username)) { socket.emit(‘error_msg’, { msg: ‘ミュートされているため送信できません’ }); return; }
const ch = channels[channelId];
if (ch.readonly && ![‘admin’,‘moderator’].includes(socket.user.role)) { socket.emit(‘error_msg’, { msg: ‘このチャンネルは読み取り専用です’ }); return; }
const msg = buildMsg(socket.user.username, content.trim(), channelId, ‘text’, null, threadOf || null);
ch.messages.push(msg);
if (messagesCol) messagesCol.insertOne({ …msg }).catch(() => {});
io.to(channelId).emit(‘message’, msg);
sendToDiscordViaBot(channelId, socket.user.username, content.trim()).catch(() => {});

```
// キーワード通知チェック
const allUsers = await Users.find();
for (const u of allUsers) {
  if (!u.keywordNotifs?.length || u.username === socket.user.username) continue;
  const lower = content.toLowerCase();
  const matched = u.keywordNotifs.find(kw => lower.includes(kw));
  if (matched) {
    const sid = socketByUser[u.username];
    if (sid) io.to(sid).emit('keyword_match', { keyword: matched, msg, channelId });
  }
}
```

});

// ファイル送信
socket.on(‘send_file’, async ({ channelId, fileInfo }) => {
if (!channels[channelId] || !fileInfo) return;
if (mutedUsers.has(socket.user.username)) { socket.emit(‘error_msg’, { msg: ‘ミュートされているため送信できません’ }); return; }
const ch = channels[channelId];
if (ch.readonly && ![‘admin’,‘moderator’].includes(socket.user.role)) { socket.emit(‘error_msg’, { msg: ‘このチャンネルは読み取り専用です’ }); return; }
const msg = buildMsg(socket.user.username, fileInfo.filename, channelId, ‘file’, fileInfo);
ch.messages.push(msg);
if (messagesCol) messagesCol.insertOne({ …msg }).catch(() => {});
io.to(channelId).emit(‘message’, msg);
sendToDiscordViaBot(channelId, socket.user.username, null, fileInfo).catch(() => {});
});

// メッセージ編集
socket.on(‘edit_message’, async ({ msgId, channelId, content }) => {
if (!channels[channelId] || !content?.trim()) return;
const msg = channels[channelId].messages.find(m => m.id === msgId);
if (!msg || (msg.author !== socket.user.username && ![‘admin’,‘moderator’].includes(socket.user.role))) return;
msg.content = content.trim(); msg.edited = true; msg.editedAt = new Date().toISOString();
if (messagesCol) messagesCol.updateOne({ id: msgId }, { $set: { content: msg.content, edited: true, editedAt: msg.editedAt } }).catch(() => {});
io.to(channelId).emit(‘message_edited’, { msgId, channelId, content: msg.content, editedAt: msg.editedAt });
});

// メッセージ削除
socket.on(‘delete_message’, async ({ msgId, channelId }) => {
if (!channels[channelId]) return;
const msg = channels[channelId].messages.find(m => m.id === msgId);
if (!msg || (msg.author !== socket.user.username && ![‘admin’,‘moderator’].includes(socket.user.role))) return;
channels[channelId].messages = channels[channelId].messages.filter(m => m.id !== msgId);
if (messagesCol) messagesCol.deleteOne({ id: msgId }).catch(() => {});
if (pinsCol) pinsCol.deleteOne({ id: msgId, channelId }).catch(() => {});
io.to(channelId).emit(‘message_deleted’, { msgId, channelId });
});

// ピン
socket.on(‘pin_message’, async ({ msgId, channelId }) => {
if (!channels[channelId] || ![‘admin’,‘moderator’].includes(socket.user.role)) return;
const msg = channels[channelId].messages.find(m => m.id === msgId);
if (!msg || channels[channelId].pins?.find(p => p.id === msgId)) return;
const pin = { …msg, pinnedBy: socket.user.username, pinnedAt: new Date().toISOString() };
channels[channelId].pins = channels[channelId].pins || [];
channels[channelId].pins.push(pin);
if (pinsCol) pinsCol.insertOne({ …pin, channelId }).catch(() => {});
io.to(channelId).emit(‘pin_update’, { channelId, pins: channels[channelId].pins });
});

socket.on(‘unpin_message’, async ({ msgId, channelId }) => {
if (!channels[channelId] || ![‘admin’,‘moderator’].includes(socket.user.role)) return;
channels[channelId].pins = (channels[channelId].pins || []).filter(p => p.id !== msgId);
if (pinsCol) pinsCol.deleteOne({ id: msgId, channelId }).catch(() => {});
io.to(channelId).emit(‘pin_update’, { channelId, pins: channels[channelId].pins });
});

// リアクション
socket.on(‘add_reaction’, ({ msgId, emoji, channelId }) => {
if (!channels[channelId]) return;
const msg = channels[channelId].messages.find(m => m.id === msgId);
if (!msg) return;
if (!msg.reactions) msg.reactions = {};
if (!msg.reactions[emoji]) msg.reactions[emoji] = [];
const idx = msg.reactions[emoji].indexOf(socket.user.username);
if (idx === -1) msg.reactions[emoji].push(socket.user.username);
else { msg.reactions[emoji].splice(idx,1); if (!msg.reactions[emoji].length) delete msg.reactions[emoji]; }
io.to(channelId).emit(‘reaction_update’, { msgId, reactions: msg.reactions });
});

// タイピング
socket.on(‘typing’, ({ channelId, isTyping }) => {
socket.to(channelId).emit(‘typing’, { username: socket.user.username, isTyping });
});

// DM送信
socket.on(‘send_dm’, async ({ toUsername, content }) => {
if (!content?.trim() || !toUsername) return;
if (mutedUsers.has(socket.user.username)) { socket.emit(‘error_msg’, { msg: ‘ミュートされているため送信できません’ }); return; }
const roomId = [socket.user.username, toUsername].sort().join(’__’);
const msg = { id: uuidv4(), author: socket.user.username, content: content.trim(), channelId: roomId, type: ‘text’, fileInfo: null, timestamp: new Date().toISOString(), isDM: true, readBy: [socket.user.username] };
if (!dmMessages[roomId]) dmMessages[roomId] = [];
dmMessages[roomId].push(msg);
if (dmsCol) dmsCol.insertOne({ …msg, roomId }).catch(() => {});
socket.emit(‘dm_message’, msg);
const toSid = socketByUser[toUsername];
if (toSid) io.to(toSid).emit(‘dm_message’, msg);
});

// DM既読
socket.on(‘dm_read’, ({ roomId, msgId }) => {
const msgs = dmMessages[roomId] || [];
const msg = msgs.find(m => m.id === msgId);
if (msg && !msg.readBy?.includes(socket.user.username)) {
if (!msg.readBy) msg.readBy = [];
msg.readBy.push(socket.user.username);
if (dmsCol) dmsCol.updateOne({ id: msgId }, { $addToSet: { readBy: socket.user.username } }).catch(() => {});
// 送信者に既読通知
const [u1,u2] = roomId.split(’__’);
const other = u1 === socket.user.username ? u2 : u1;
const sid = socketByUser[other];
if (sid) io.to(sid).emit(‘dm_read_update’, { roomId, msgId, readBy: msg.readBy });
}
});

socket.on(‘disconnect’, () => {
delete onlineUsers[socket.id];
if (socketByUser[socket.user.username] === socket.id) delete socketByUser[socket.user.username];
broadcastOnlineUsers();
});
});

function broadcastOnlineUsers() {
io.emit(‘online_users’, Object.values(onlineUsers).map(u => ({ username: u.username, userId: u.userId, status: u.status || ‘online’ })));
}

function buildMsg(author, content, channelId, type, fileInfo = null, threadOf = null) {
return { id: uuidv4(), author, content, channelId, type, fileInfo, threadOf, timestamp: new Date().toISOString() };
}

server.listen(PORT, () => {
console.log(`🚀 Server on http://localhost:${PORT}`);
connectMongo().catch(err => console.error(‘connectMongo error:’, err));
startDiscordBot();
});
