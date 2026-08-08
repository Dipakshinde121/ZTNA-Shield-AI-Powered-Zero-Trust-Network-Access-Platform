// Import configuration first to initialize environment variables and prevent load-order bugs
import { PORT } from './config';
import express from 'express';
import cors from 'cors';
import authRoutes from './routes/authRoutes';
import deviceRoutes from './routes/deviceRoutes';
import gatewayRoutes from './routes/gatewayRoutes';
import adminRoutes from './routes/adminRoutes';

const app = express();

app.use(cors({
  origin: '*', // Allow all origins for local simulator development
  credentials: true
}));

app.use(express.json());

// Routes configuration
app.use('/api/auth', authRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/gateway', gatewayRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'ZTNA Shield Security Gateway online.' });
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`[SYSTEM] Zero Trust Network Access (ZTNA) Control Plane online on port ${PORT}`);
  });
}

export default app;
