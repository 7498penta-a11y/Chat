const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// 静的ファイル（public フォルダ）
app.use(express.static("public"));

// ★ メッセージ履歴（メモリ保存）★
let messages = [];      // { username, text, time } など自由に

io.on("connection", (socket) => {
  console.log("user connected:", socket.id);

  // ★ 接続してきた人に履歴を送信
  socket.emit("chatHistory", messages);

  socket.on("chatMessage", (msg) => {
    // 受け取ったメッセージを履歴に追加
    messages.push(msg);

    // 履歴が増えすぎないように（直近100件だけ保持）
    if (messages.length > 100) messages.shift();

    // 全員に配信
    io.emit("chatMessage", msg);
  });

  socket.on("typing", (username) => {
    socket.broadcast.emit("typing", username);
  });

  socket.on("stopTyping", (username) => {
    socket.broadcast.emit("stopTyping", username);
  });

  socket.on("disconnect", () => {
    console.log("user disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
