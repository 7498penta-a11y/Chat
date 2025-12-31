const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// 静的ファイル（public フォルダ）
app.use(express.static("public"));

io.on("connection", (socket) => {
  console.log("user connected:", socket.id);

  socket.on("chatMessage", (msg) => {
    // 受け取ったメッセージを全員に配信
    io.emit("chatMessage", msg);
  });

  socket.on("disconnect", () => {
    console.log("user disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
