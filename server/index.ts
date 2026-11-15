import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import multer from 'multer';
import { EventEmitter } from 'events';
import { sentinelMiddleware } from './middleware';
import {
  assignUnownedAlertsToUser,
  closeDatabase,
  createUser,
  getAlerts,
  initializeDatabase,
  listAuditEvents,
  listAuthEvents,
  listUsers,
  recordAuditEvent,
  recordAuthEvent,
  updateAlertStatus,
  databaseHealthy,
  type AlertStatus,
  type UserRole,
} from './db';
import {
  authenticate,
  changePassword,
  ensureDefaultAdmin,
  hashPassword,
  issueToken,
  optionalAuth,
  requireAdmin,
  requireAuth,
  validatePassword,
} from './auth';
import { mountSimulations } from './simulationRoutes';
import { mountDefenseRoutes } from './defenseRoutes';
import { validLabLogin } from './labAuth';

const app = express();
const port = process.env.PORT || 3000;

// Setup in-memory event emitter for SSE
const eventBus = new EventEmitter();
// @ts-ignore
app.on('new-alert', (userId: number) => {
  eventBus.emit('alert', userId);
});

// Basic middleware
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173', credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

app.get('/health', async (_req, res) => {
  try { await databaseHealthy(); res.json({ status: 'ok', database: 'connected' }); }
  catch { res.status(503).json({ status: 'unavailable', database: 'disconnected' }); }
});

app.use(optionalAuth);

app.post('/auth/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    const user = await authenticate(username, password, req);
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    const { password_hash: _passwordHash, ...publicUser } = user;
    const token = issueToken(publicUser);
    res.cookie('sentinel_token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 8 * 60 * 60 * 1000,
    });
    return res.json({ token, user: publicUser });
  } catch (err) {
    console.error('Login failed:', err);
    return res.status(500).json({ error: 'Unable to sign in' });
  }
});

app.use(requireAuth);

app.get('/auth/me', (req: Request, res: Response) => {
  res.json({ user: req.authUser });
});

app.post('/auth/logout', async (req: Request, res: Response) => {
  try {
    await recordAuthEvent({
      userId: req.authUser!.id,
      username: req.authUser!.username,
      eventType: 'logout',
      sourceIp: req.ip || req.socket.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'] || '',
    });
    res.clearCookie('sentinel_token', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
    return res.status(204).end();
  } catch (err) {
    console.error('Logout audit failed:', err);
    return res.status(500).json({ error: 'Unable to sign out' });
  }
});

app.post('/auth/change-password', async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      return res.status(400).json({ error: 'Current and new passwords are required' });
    }
    if (!validatePassword(newPassword)) {
      return res.status(400).json({ error: 'New password must be at least 10 characters and contain letters and numbers' });
    }
    const changed = await changePassword(req.authUser!.id, currentPassword, newPassword);
    if (!changed) return res.status(401).json({ error: 'Current password is incorrect' });
    await recordAuditEvent({ actorUserId: req.authUser!.id, action: 'password_changed', entityType: 'user', entityId: req.authUser!.id, sourceIp: req.ip });
    return res.status(204).end();
  } catch (err) {
    console.error('Password change failed:', err);
    return res.status(500).json({ error: 'Unable to change password' });
  }
});

app.get('/auth/users', requireAdmin, async (_req: Request, res: Response) => {
  try {
    return res.json(await listUsers());
  } catch (err) {
    console.error('User list failed:', err);
    return res.status(500).json({ error: 'Unable to list users' });
  }
});

app.get('/auth/events', async (req: Request, res: Response) => {
  try {
    const allUsers = req.query.scope === 'all';
    if (allUsers && req.authUser!.role !== 'admin') return res.status(403).json({ error: 'Administrator access required' });
    return res.json(await listAuthEvents(req.authUser!, allUsers));
  } catch (err) {
    console.error('Login history failed:', err);
    return res.status(500).json({ error: 'Unable to load login history' });
  }
});

app.get('/audit-events', async (req: Request, res: Response) => {
  try {
    const allUsers = req.query.scope === 'all';
    if (allUsers && req.authUser!.role !== 'admin') return res.status(403).json({ error: 'Administrator access required' });
    return res.json(await listAuditEvents(req.authUser!, allUsers));
  } catch (err) {
    console.error('Audit log failed:', err);
    return res.status(500).json({ error: 'Unable to load audit log' });
  }
});

app.post('/auth/users', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { name, username: usernameInput, password, role = 'analyst' } = req.body || {};
    const username = typeof usernameInput === 'string' ? usernameInput.trim().toLowerCase() : '';
    const validRoles: UserRole[] = ['admin', 'analyst', 'viewer'];
    if (typeof name !== 'string' || !name.trim() || !/^[a-z0-9._-]{3,40}$/.test(username)) {
      return res.status(400).json({ error: 'A name and valid username are required' });
    }
    if (typeof password !== 'string' || !validatePassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 10 characters and contain letters and numbers' });
    }
    if (!validRoles.includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const user = await createUser({ name: name.trim(), username, passwordHash: await hashPassword(password), role });
    await recordAuditEvent({ actorUserId: req.authUser!.id, action: 'user_created', entityType: 'user', entityId: user.id, details: { username: user.username, role: user.role }, sourceIp: req.ip });
    return res.status(201).json(user);
  } catch (err: any) {
    if (err?.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    console.error('User creation failed:', err);
    return res.status(500).json({ error: 'Unable to create user' });
  }
});

mountSimulations(app);
mountDefenseRoutes(app);

// Multipart bodies must be parsed before Sentinel so the upload detector can inspect req.file.
app.use('/upload', upload.single('file'));

// --- SENTINEL MIDDLEWARE PIPELINE ---
app.use(sentinelMiddleware);

// --- TOY API ENDPOINTS ---

app.post('/login', (req: Request, res: Response) => {
  if (validLabLogin(req.body)) {
    res.json({ success: true, message: 'Lab authentication accepted' });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

app.get('/search', (req: Request, res: Response) => {
  const q = req.query.q || '';
  // Simulate DB search
  res.json({ results: [`Result for ${q}`] });
});
app.post('/search', (_req, res) => res.json({ results: [], message: 'JSON payload inspected' }));

app.get('/fetch', (req: Request, res: Response) => {
  const url = req.query.url;
  // Simulate fetching a remote resource
  res.json({ message: `Fetched from ${url} successfully.` });
});

app.post('/upload', (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({ message: `File ${req.file.originalname} uploaded successfully.` });
});

app.get('/profile/:id', (req: Request, res: Response) => {
  const id = req.params.id;
  // Simulate profile lookup
  res.json({ id, name: `User ${id}` });
});

// --- DASHBOARD API ENDPOINTS ---

// Fetch past alerts
app.get('/alerts', async (req: Request, res: Response) => {
  try {
    const allUsers = req.query.scope === 'all';
    if (allUsers && req.authUser!.role !== 'admin') return res.status(403).json({ error: 'Administrator access required' });
    const filterUserId = allUsers && typeof req.query.userId === 'string' ? Number(req.query.userId) : undefined;
    if (req.query.userId !== undefined && (!allUsers || !Number.isSafeInteger(filterUserId) || filterUserId! <= 0)) {
      return res.status(400).json({ error: 'User filtering requires all-user scope and a positive user ID' });
    }
    const alerts = await getAlerts(req.authUser!.id, { allUsers, filterUserId: Number.isFinite(filterUserId) ? filterUserId : undefined });
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

app.patch('/alerts/:id/status', async (req: Request, res: Response) => {
  try {
    if (req.authUser!.role === 'viewer') return res.status(403).json({ error: 'Only analysts and administrators can update alerts' });
    const alertId = Number(req.params.id);
    const status = req.body?.status as AlertStatus;
    if (!Number.isSafeInteger(alertId) || alertId <= 0 || !['open', 'acknowledged', 'resolved'].includes(status)) {
      return res.status(400).json({ error: 'A valid alert ID and status are required' });
    }
    const alert = await updateAlertStatus(alertId, status, req.authUser!, req.ip);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    req.app.emit('new-alert', alert.user_id);
    return res.json(alert);
  } catch (err) {
    console.error('Alert status update failed:', err);
    return res.status(500).json({ error: 'Unable to update alert' });
  }
});

// Server-Sent Events for real-time dashboard
app.get('/alerts/stream', (req: Request, res: Response) => {
  if (req.query.scope === 'all' && req.authUser!.role !== 'admin') {
    return res.status(403).json({ error: 'Administrator access required' });
  }
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders(); // flush the headers to establish SSE
  res.write(': connected\n\n');

  const onAlert = async (userId: number) => {
    const allUsers = req.query.scope === 'all' && req.authUser!.role === 'admin';
    if (!allUsers && userId !== req.authUser!.id) return;
    // The client reloads its selected scope on either a detection or status change.
    res.write(`data: ${JSON.stringify({ userId })}\n\n`);
  };

  eventBus.on('alert', onAlert);
  const heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 20_000);

  req.on('close', () => {
    eventBus.off('alert', onAlert);
    clearInterval(heartbeat);
    res.end();
  });
});

app.use((error: any, _req: Request, res: Response, _next: NextFunction) => {
  const invalidInput = error instanceof multer.MulterError || error.type === 'entity.parse.failed' || error.type === 'entity.too.large';
  res.status(invalidInput ? 400 : 500).json({ error: invalidInput ? 'Invalid or oversized request body/file' : 'Unexpected API error' });
});

async function startServer() {
  try {
    await initializeDatabase();
    const admin = await ensureDefaultAdmin();
    await assignUnownedAlertsToUser(admin.id);
    const server = app.listen(port, () => {
      console.log(`SentinelAPI server listening on http://localhost:${port}`);
      console.log('PostgreSQL connection and alerts table are ready.');
    });

    const shutdown = () => {
      server.close(() => {
        closeDatabase()
          .catch(err => console.error('Failed to close PostgreSQL pool:', err))
          .finally(() => process.exit(0));
      });
      server.closeAllConnections();
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  } catch (err) {
    console.error('Failed to initialize PostgreSQL:', err);
    process.exit(1);
  }
}

startServer();
