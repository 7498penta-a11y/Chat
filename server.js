require("dotenv").config(); // 環境変数を読み込み
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { Client, GatewayIntentBits } = require("discord.js");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- Discord Botのセットアップ ---
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent, // メッセージ内容を読むために必要
  ],
});

const DISCORD_CHANNEL_ID = process.env.DISCORD_CHANNEL_ID;

// Discord Botが準備完了した時
client.once("ready", () => {
  console.log(`Discord Bot Logged in as ${client.user.tag}`);
});

// --- Webサーバーの設定 ---
app.use(express.static("public")); // index.htmlがpublicフォルダにある場合

// ★ メッセージ履歴（メモリ保存）
let messages = [];

io.on("connection", (socket) => {
  console.log("Web user connected:", socket.id);

  // 接続時に履歴を送信
  socket.emit("chatHistory", messages);

  // ★ Webからメッセージが届いた時（Web -> Discord）
  socket.on("chatMessage", (msg) => {
    // 履歴に追加
    messages.push(msg);
    if (messages.length > 100) messages.shift();

    // Webの全員に配信
    io.emit("chatMessage", msg);

    // Discordにも送信
    const channel = client.channels.cache.get(DISCORD_CHANNEL_ID);
    if (channel) {
      // Discord側での表示形式: "ユーザー名: メッセージ"
      channel.send(`**${msg.username}**: ${msg.text}`).catch(console.error);
    }
  });

  socket.on("typing", (username) => {
    socket.broadcast.emit("typing", username);
  });

  socket.on("stopTyping", (username) => {
    socket.broadcast.emit("stopTyping", username);
  });
});

// --- Discordからメッセージが届いた時（Discord -> Web） ---
client.on("messageCreate", (message) => {
  // Bot自身のメッセージは無視（無限ループ防止）
  if (message.author.bot) return;

  // 指定のチャンネル以外は無視
  if (message.channelId !== DISCORD_CHANNEL_ID) return;

  const msgData = {
    username: message.author.username, // Discordのユーザー名
    text: message.content,
    timestamp: Date.now(),
    isDiscord: true // 判別用フラグ（任意）
  };

  // 履歴に追加
  messages.push(msgData);
  if (messages.length > 100) messages.shift();

  // Webクライアント全員に送信
  io.emit("chatMessage", msgData);
});

// サーバー起動
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Web Server running on http://localhost:${PORT}`);
});

// Botログイン
client.login(process.env.DISCORD_TOKEN);
