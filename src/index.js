import express from 'express';
import swaggerUi from 'swagger-ui-express';
import cors from 'cors';
import logger from './utils/logger.js';
import connectDB from './config/db.js';
import errorHandler from './middlewares/errorHandler.js';
import requestLogger from './middlewares/requestLogger.js';
import { auth } from './middlewares/auth.js';
import userRoutesV1 from './routes/v1/userRoutes.js';
import apiKeyRoutesV1 from './routes/v1/apiKeyRoutes.js';
import SwaggerParser from 'swagger-parser';


const app = express();

const allowedOrigins = [
  ...(process.env.AUTH_ALLOWED_ORIGINS || '').split(','),
  process.env.DESIGNER_FRONTEND_URL,
  process.env.WORKBENCH_FRONTEND_URL,
]
  .map((origin) => origin?.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error(`CORS origin not allowed: ${origin}`));
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  })
);
app.use(express.json());
app.use(requestLogger);
app.use(auth);

// Swagger
SwaggerParser.bundle('./api/openapi.yaml')
  .then((bundledDoc) => {
    app.use('/docs', swaggerUi.serve, swaggerUi.setup(bundledDoc));
  })
  .catch((error) => {
    console.error('Error bundling OAS file:', error);
  });

// Rutas principales del microservicio de Auth
app.use('/api/v1/users', userRoutesV1);
app.use('/api/v1/apikeys', apiKeyRoutesV1);

// Error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 3005;

const startServer = async () => {
  try {
    await connectDB();
    const server = app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
    });

    const gracefulShutdown = () => {
      logger.info('Shutting down server...');
      server.close(() => {
        logger.info('Server has been shut down');
        process.exit(0);
      });

      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);
  } catch (error) {
    logger.error(`Error starting server: ${error.message}`);
    process.exit(1);
  }
};

startServer();

export default app;
