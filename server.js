const http = require('http');
const { Server } = require('socket.io');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
  res.end('Forest Robber server OK');
});

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const rooms = {};
const bannedNicks = new Set();

io.on('connection', (socket) => {
  socket.on('joinRoom', ({ roomId, nickname, skin }) => {
    if (!roomId) return;
    if (bannedNicks.has((nickname || '').toLowerCase())) {
      socket.emit('banned', { reason: 'Вы забанены владельцем' });
      socket.disconnect(true);
      return;
    }
    socket.join(roomId);
    socket.roomId = roomId;
    if (!rooms[roomId]) rooms[roomId] = { players: {} };
    rooms[roomId].players[socket.id] = {
      id: socket.id,
      nickname: nickname || 'Игрок',
      skin: skin || 'default',
      x: 1750, y: 1750, dir: 0, hp: 100, moving: false
    };
    socket.emit('roomState', rooms[roomId]);
    socket.to(roomId).emit('playerJoined', rooms[roomId].players[socket.id]);
  });

  socket.on('playerUpdate', (data) => {
    if (!socket.roomId) return;
    const room = rooms[socket.roomId];
    if (!room || !room.players[socket.id]) return;
    const p = room.players[socket.id];
    p.x = data.x; p.y = data.y; p.dir = data.dir;
    p.hp = data.hp; p.nickname = data.nickname || p.nickname;
    p.skin = data.skin || p.skin; p.moving = data.moving || false;
    socket.to(socket.roomId).emit('playerMoved', { id: socket.id, ...p });
  });

  socket.on('chatMessage', (data) => {
    if (!socket.roomId) return;
    const room = rooms[socket.roomId];
    if (!room || !room.players[socket.id]) return;
    const text = String(data.text || '').substring(0, 120).trim();
    if (!text) return;
    io.to(socket.roomId).emit('chatMessage', {
      id: socket.id,
      nickname: room.players[socket.id].nickname,
      text: text,
      time: Date.now()
    });
  });

  // АДМИН-ДЕЙСТВИЯ (только владелец)
  socket.on('adminAction', (data) => {
    if (!socket.roomId) return;
    const room = rooms[socket.roomId];
    if (!room) return;
    const myPlayer = room.players[socket.id];
    if (!myPlayer) return;
    const myNick = (myPlayer.nickname || '').toLowerCase().replace(/^@/, '').trim();
    if (myNick !== 'auqgestt') return;

    if (data.action === 'weather') {
      io.to(socket.roomId).emit('adminWeather', { weather: data.weather });
      return;
    }

    if (!data.targetId) return;
    const targetSocket = io.sockets.sockets.get(data.targetId);
    const target = room.players[data.targetId];
    if (!target || !targetSocket) return;

    if (data.action === 'giveCoins') {
      targetSocket.emit('adminGiveCoins', { amount: data.amount || 100 });
    } else if (data.action === 'kick') {
      targetSocket.emit('adminKicked', { reason: 'Вас выгнал владелец' });
      setTimeout(() => targetSocket.disconnect(true), 100);
    } else if (data.action === 'ban') {
      bannedNicks.add((target.nickname || '').toLowerCase());
      targetSocket.emit('adminBanned', { reason: 'Вы забанены владельцем' });
      setTimeout(() => targetSocket.disconnect(true), 100);
    }
  });

  socket.on('leaveRoom', () => {
    if (!socket.roomId) return;
    const room = rooms[socket.roomId];
    if (room) {
      delete room.players[socket.id];
      socket.to(socket.roomId).emit('playerLeft', socket.id);
      if (Object.keys(room.players).length === 0) delete rooms[socket.roomId];
    }
    socket.leave(socket.roomId);
    socket.roomId = null;
  });

  socket.on('disconnect', () => {
    if (!socket.roomId) return;
    const room = rooms[socket.roomId];
    if (room) {
      delete room.players[socket.id];
      socket.to(socket.roomId).emit('playerLeft', socket.id);
      if (Object.keys(room.players).length === 0) delete rooms[socket.roomId];
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
