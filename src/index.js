import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import logger from './utils/logger.js'; // Asumo que tienes un logger con winston
import errorHandler from './middlewares/errorHandler.js';
import requestLogger from './middlewares/requestLogger.js';
import userRoutesV1 from './routes/userRoutes.js';
import systemApiKeyRoutesV1 from './routes/systemApiKeyRoutes.js'; // Descomentar si lo migras

const app = express();

app.use(
  cors({
    origin: [process.env.FRONTEND_URL, process.env.WORKBENCH_FRONTEND_URL],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  })
);
app.use(express.json());
app.use(requestLogger);

// Rutas principales del microservicio de Auth
app.use('/api/v1/users', userRoutesV1);
app.use('/api/v1/system-api-keys', systemApiKeyRoutesV1);

// Middleware de manejo de errores (siempre al final)
app.use(errorHandler);

const PORT = process.env.PORT || 3001; // Usamos el 3001 para que no choque con el backend viejo

const startServer = async () => {
  try {
    // Conexión a la BD (Asegúrate de tener MONGO_URI en tu .env)
    await mongoose.connect(process.env.MONGO_URI);
    logger.info('Connected to MongoDB (Auth Service)');

    const server = app.listen(PORT, () => {
      logger.info(`Auth Service running on port ${PORT}`);
    });

    const gracefulShutdown = () => {
      logger.info('Shutting down Auth Service...');
      server.close(() => {
        mongoose.connection.close(false, () => {
          logger.info('MongoDb connection closed.');
          process.exit(0);
        });
      });
    };

    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);
  } catch (error) {
    logger.error(`Error starting server: ${error.message}`);
    process.exit(1);
  }
};

startServer();