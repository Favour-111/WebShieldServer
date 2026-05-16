const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

const initializeSocket = (io) => {
  // Authenticate socket connections using JWT
  io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error('Authentication required'));
    }
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.id;
      next();
    } catch (err) {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    logger.info(`Socket connected: ${socket.id} (user: ${socket.userId})`);

    // Join user-specific room for targeted notifications
    socket.join(`user_${socket.userId}`);

    socket.on('scan:join', (scanId) => {
      socket.join(`scan_${scanId}`);
      logger.debug(`User ${socket.userId} joined scan room: ${scanId}`);
    });

    socket.on('scan:leave', (scanId) => {
      socket.leave(`scan_${scanId}`);
    });

    socket.on('disconnect', (reason) => {
      logger.info(`Socket disconnected: ${socket.id} - ${reason}`);
    });

    socket.on('error', (error) => {
      logger.error(`Socket error: ${error.message}`);
    });
  });
};

module.exports = { initializeSocket };
