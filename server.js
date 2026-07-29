const express = require('express');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const TikTokModule = require('tiktok-live-connector');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const { Resend } = require('resend');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

const resend = new Resend(process.env.RESEND_API_KEY);
const TikTokLiveConnection = TikTokModule.TikTokLiveConnection || TikTokModule.WebcastPushConnection;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.SESSION_SECRET || !process.env.MONGO_URI) {
  throw new Error("FATAL ERROR: SESSION_SECRET et MONGO_URI sont obligatoires !");
}

const OVERLAY_TOKEN_SECRET = process.env.OVERLAY_TOKEN_SECRET || crypto.randomBytes(32).toString('hex');

app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/img', express.static(path.join(__dirname, 'img')));

const sessionMiddleware = session({
  name: '__Host-tokoverlay',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    ttl: 60 * 60 * 24 * 7
  }),
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
});
app.use(sessionMiddleware);

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

const mongoUri = process.env.MONGO_URI;
let db = null;
let vouchesGlobalCount = 0;

async function connectMongo() {
  try {
    const client = new MongoClient(mongoUri);
    await client.connect();
    db = client.db('tokoverlay_db');
    console.log("✅ Connecté à MongoDB Atlas avec succès !");

    await db.collection('users').createIndex({ email: 1 }, { unique: true }).catch(() => {});
    await db.collection('users').createIndex({ pseudo: 1 }, { unique: true }).catch(() => {});

    const compteur = await db.collection('compteurs').findOne({ _id: 'vouches' });
    vouchesGlobalCount = compteur?.total || 0;
  } catch (err) {
    console.error("❌ Erreur de connexion MongoDB :", err);
  }
}
connectMongo();

function normalizePseudo(value) {
  if (typeof value !== 'string') throw new Error('Pseudo invalide.');
  const pseudo = value.replace(/^@/, '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{2,24}$/.test(pseudo)) {
    throw new Error('Pseudo invalide.');
  }
  return pseudo;
}

function safeText(value, fallback = '') {
  return typeof value === 'string' ? value.trim() : fallback;
}

function signOverlayToken(pseudo) {
  const expiresAt = Date.now() + (1000 * 60 * 60 * 24 * 7);
  const payload = Buffer.from(JSON.stringify({ pseudo, expiresAt })).toString('base64url');
  const signature = crypto
    .createHmac('sha256', OVERLAY_TOKEN_SECRET)
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
}

function verifyOverlayToken(token, expectedPseudo) {
  if (typeof token !== 'string') return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;

  const expected = crypto
    .createHmac('sha256', OVERLAY_TOKEN_SECRET)
    .update(payload)
    .digest('base64url');

  if (
    signature.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  ) return false;

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.pseudo === expectedPseudo && data.expiresAt > Date.now();
  } catch {
    return false;
  }
}

function isAdmin(user) { return user && user.role === 'admin'; }
function canManage(user, pseudo) { return Boolean(user && (isAdmin(user) || user.pseudo === pseudo)); }

// ----------------------------------------------------
// ROUTES FRONTEND ET LANDING PAGE
// ----------------------------------------------------

app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect('/choix.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login.html', (req, res) => {
  if (req.session.user) {
    return res.redirect('/choix.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ----------------------------------------------------
// AUTHENTIFICATION
// ----------------------------------------------------

app.post('/register', async (req, res) => {
  let { pseudo, apiKey, email, password } = req.body;
  try {
    if (!db) return res.status(500).send("Base de données en cours de connexion.");
    email = safeText(email).toLowerCase();
    let pseudoNettoye;
    try { pseudoNettoye = normalizePseudo(pseudo); } catch { return res.redirect('/login.html?error=invalid_pseudo&tab=register'); }
    const cleanApiKey = safeText(apiKey);

    if (!cleanApiKey || !email || !password) {
      return res.redirect('/login.html?error=missing_fields&tab=register');
    }

    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne({
      $or: [{ email }, { pseudo: pseudoNettoye }]
    });

    if (existingUser) {
      if (existingUser.email === email) return res.redirect('/login.html?error=email_exists&tab=register');
      if (existingUser.pseudo === pseudoNettoye) return res.redirect('/login.html?error=pseudo_exists&tab=register');
    }

    const passwordHache = await bcrypt.hash(password, 10);
    const newUser = { 
      pseudo: pseudoNettoye, 
      apiKey: cleanApiKey, 
      email, 
      password: passwordHache, 
      role: 'streamer',
      totalDiamantsGlobal: 0 
    };
    await usersCollection.insertOne(newUser);
    
    await new Promise((resolve, reject) =>
      req.session.regenerate((error) => error ? reject(error) : resolve())
    );

    req.session.user = { id: newUser._id, pseudo: newUser.pseudo, email: newUser.email, role: newUser.role };
    await new Promise((resolve, reject) => req.session.save((err) => err ? reject(err) : resolve()));

    res.redirect('/choix.html');
  } catch (err) {
    res.status(500).send("Erreur serveur lors de l'inscription.");
  }
});

app.post('/login', async (req, res) => {
  let { pseudo, password } = req.body;
  try {
    if (!db) return res.status(500).send("Base de données en cours de connexion.");
    let pseudoNettoye;
    try { pseudoNettoye = normalizePseudo(pseudo); } catch { return res.redirect('/login.html?error=wrong_credentials'); }

    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ pseudo: pseudoNettoye });
    if (user && typeof password === 'string' && await bcrypt.compare(password, user.password)) {
      await new Promise((resolve, reject) =>
        req.session.regenerate((error) => error ? reject(error) : resolve())
      );
      req.session.user = { id: user._id, pseudo: user.pseudo, email: user.email, role: user.role || 'streamer' };
      await new Promise((resolve, reject) => req.session.save((err) => err ? reject(err) : resolve()));

      return res.redirect('/choix.html');
    }
    res.redirect('/login.html?error=wrong_credentials');
  } catch (err) {
    res.status(500).send("Erreur serveur.");
  }
});

app.get('/api/me', async (req, res) => {
  if (!req.session.user || !db) return res.status(401).json({ error: 'Non connecté' });
  try {
    const userDb = await db.collection('users').findOne({ email: req.session.user.email });
    if (!userDb) return res.status(401).json({ error: 'Utilisateur introuvable' });
    const overlayToken = signOverlayToken(userDb.pseudo);

    res.json({
      id: userDb._id,
      pseudo: userDb.pseudo,
      email: userDb.email,
      role: userDb.role || 'streamer',
      overlayToken: overlayToken
    });
  } catch {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('__Host-tokoverlay');
    res.redirect('/');
  });
});

// ----------------------------------------------------
// OVERLAYS & API DÉLÉGUÉS
// ----------------------------------------------------

app.get('/overlay/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'overlay.html')));
app.get('/overlay-vip/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vip-overlay.html')));
app.get('/elimination/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'elimination.html')));
app.get('/elimination-boucle/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'elimination-boucle.html')));
app.get('/encheres/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'controle-encheres.html')));
app.get('/statistiques/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'statistiques.html')));
app.get('/admin-live/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-live.html')));
app.get('/simulation/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'simulation.html')));

const connexionsActives = {};

io.on('connection', socket => {
  socket.on('rejoindre', async (payload = {}, ack = () => {}) => {
    try {
      const { pseudo, token } = payload;
      let pseudoNettoye = normalizePseudo(pseudo);
      const utilisateurConnecte = socket.request.session?.user;
      const allowed = canManage(utilisateurConnecte, pseudoNettoye) || verifyOverlayToken(token, pseudoNettoye);
      if (!allowed) return ack({ ok: false, error: 'Non autorisé.' });
      socket.join(`streamer:${pseudoNettoye}`);
      ack({ ok: true });
    } catch {
      ack({ ok: false, error: 'Invalide.' });
    }
  });
});

server.listen(PORT, () => console.log(`🚀 TokOverlay démarré sur le port ${PORT}`));