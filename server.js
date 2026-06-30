require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const connectDB = require('./config/db');
const { initializeSocket } = require('./sockets/scan.socket');
const { setSocketIO } = require('./services/scanner.service');
const { errorHandler, notFoundHandler } = require('./middleware/error.middleware');
const { databaseReady } = require('./middleware/database.middleware');
const { apiLimiter } = require('./middleware/rateLimiter');
const logger = require('./utils/logger');

// Route imports
const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const scanRoutes = require('./routes/scan.routes');
const vulnerabilityRoutes = require('./routes/vulnerability.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const reportRoutes = require('./routes/report.routes');

const app = express();
const server = http.createServer(app);

const corsOptions = {
  origin(origin, callback) {
    return callback(null, origin || true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204,
};

// Socket.io setup
const io = new Server(server, {
  cors: {
    origin(origin, callback) {
      return callback(null, origin || true);
    },
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Initialize socket handlers
initializeSocket(io);
setSocketIO(io);

// Connect to MongoDB once during startup/cold start
connectDB().catch((error) => {
  logger.error(`Database initialization failed: ${error.message}`);
});

// Trust proxy — required for correct IP detection behind Nginx, Heroku, Railway, Render, etc.
app.set('trust proxy', 1);

// Security middleware
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
  })
);

// CORS
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Request parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));
}

// Rate limiting
app.use('/api/', apiLimiter);
app.use('/api', databaseReady);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'WebShield Scanner API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/reports', reportRoutes);

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

if (require.main === module) {
  server.listen(PORT, () => {
    logger.info(`
  ┌─────────────────────────────────────────┐
  │   WebShield Scanner API v1.0.0           │
  │   Running on port ${PORT}                    │
  │   Environment: ${process.env.NODE_ENV || 'development'}         │
  └─────────────────────────────────────────┘
  `);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    server.close(() => {
      logger.info('Server closed.');
      process.exit(0);
    });
  });

  process.on('unhandledRejection', (err) => {
    logger.error(`Unhandled Promise Rejection: ${err.message}`);
    server.close(() => process.exit(1));
  });
}

module.exports = { app, server };
