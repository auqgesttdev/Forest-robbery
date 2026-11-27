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

io.on('connection', (socket) => {
  socket.on('joinRoom', ({ roomId, nickname, skin }) => {
    if (!roomId) return;
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
    console.log(`[${roomId}] ${nickname} joined. Players: ${Object.keys(rooms[roomId].players).length}`);
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