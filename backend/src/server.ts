import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes';
import deviceRoutes from './routes/deviceRoutes';
import gatewayRoutes from './routes/gatewayRoutes';
import adminRoutes from './routes/adminRoutes';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

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

app.listen(PORT, () => {
  console.log(`[SYSTEM] Zero Trust Network Access (ZTNA) Control Plane online on port ${PORT}`);
});
