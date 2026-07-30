const express = require('express');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const TikTokModule = require('tiktok-live-connector');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');
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

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const name = parts.shift().trim();
      if (name) {
        list[name] = decodeURIComponent(parts.join('='));
      }
    });
  }
  return list;
}

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

function createRateLimiter({ windowMs = 15 * 60 * 1000, max = 15, message = "Trop de tentatives. Réessayez plus tard." }) {
  const requests = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of requests.entries()) {
      if (now > data.resetTime) {
        requests.delete(ip);
      }
    }
  }, 5 * 60 * 1000);

  return function (req, res, next) {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();

    let record = requests.get(ip);
    if (!record || now > record.resetTime) {
      record = { count: 1, resetTime: now + windowMs };
      requests.set(ip, record);
      return next();
    }

    record.count++;
    if (record.count > max) {
      return res.status(429).json({ error: message });
    }

    next();
  };
}

const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: "Trop de tentatives. Réessayez dans 15 minutes."
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

    await db.collection('remember_tokens').createIndex({ selector: 1 }, { unique: true }).catch(() => {});
    await db.collection('remember_tokens').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }).catch(() => {});

    const compteur = await db.collection('compteurs').findOne({ _id: 'vouches' });
    vouchesGlobalCount = compteur?.total || 0;
  } catch (err) {
    console.error("❌ Erreur de connexion MongoDB :", err);
  }
}
connectMongo();

async function checkRememberMe(req, res, next) {
  try {
    if (req.session && req.session.user) {
      return next();
    }

    const cookies = parseCookies(req);
    const cookieToken = cookies.remember_token;
    if (!cookieToken || !db) {
      return next();
    }

    const [selector, validator] = cookieToken.split(':');
    if (!selector || !validator) {
      return next();
    }

    const tokenDoc = await db.collection('remember_tokens').findOne({ selector });
    if (!tokenDoc || new Date() > tokenDoc.expiresAt) {
      res.clearCookie('remember_token', { path: '/' });
      return next();
    }

    const hashedValidator = crypto.createHash('sha256').update(validator).digest('hex');
    if (hashedValidator !== tokenDoc.validatorHash) {
      await db.collection('remember_tokens').deleteMany({ userId: tokenDoc.userId }).catch(() => {});
      res.clearCookie('remember_token', { path: '/' });
      return next();
    }

    const user = await db.collection('users').findOne({ _id: new ObjectId(tokenDoc.userId) });
    if (!user) {
      res.clearCookie('remember_token', { path: '/' });
      return next();
    }

    req.session.user = {
      id: user._id,
      pseudo: user.pseudo,
      email: user.email,
      role: user.role || 'streamer'
    };

    const newSelector = crypto.randomBytes(16).toString('hex');
    const newValidator = crypto.randomBytes(32).toString('hex');
    const newValidatorHash = crypto.createHash('sha256').update(newValidator).digest('hex');
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await db.collection('remember_tokens').updateOne(
      { _id: tokenDoc._id },
      { $set: { selector: newSelector, validatorHash: newValidatorHash, expiresAt } }
    );

    res.cookie('remember_token', `${newSelector}:${newValidator}`, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    next();
  } catch (err) {
    console.error("Erreur checkRememberMe :", err);
    next();
  }
}

app.use(checkRememberMe);

app.get('/', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/choix.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/index.html', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/choix.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login.html', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/choix.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/img', express.static(path.join(__dirname, 'img')));

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

function strictInteger(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) {
    throw new Error('Nombre invalide.');
  }
  return number;
}

function positiveInteger(value, fallback = 1) {
  const num = Number(value);
  return Number.isInteger(num) && num > 0 ? num : fallback;
}

function resolveUserId(d = {}, user = {}) {
  return safeText(
    user.displayId || d.uniqueId || user.userId || d.userId,
    `unknown:${crypto.randomUUID()}`
  );
}

function avatarFor(user = {}, nickname = 'Anonyme') {
  const avatarList = user?.avatarThumb?.urlList;
  if (Array.isArray(avatarList) && avatarList.length > 0 && typeof avatarList[0] === 'string') {
    return avatarList[0];
  }
  return `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
}

function isAdmin(user) { return user && user.role === 'admin'; }
function canManage(user, pseudo) { return Boolean(user && (isAdmin(user) || normalizePseudo(user.pseudo) === normalizePseudo(pseudo))); }

function signOverlayToken(pseudo) {
  const cleanPseudo = normalizePseudo(pseudo);
  const expiresAt = Date.now() + (1000 * 60 * 60 * 24 * 30);
  const payload = Buffer.from(JSON.stringify({ pseudo: cleanPseudo, expiresAt })).toString('base64url');
  const signature = crypto
    .createHmac('sha256', OVERLAY_TOKEN_SECRET)
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
}

function verifyOverlayToken(token, expectedPseudo) {
  if (typeof token !== 'string' || !token) return false;
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
    const tokenPseudo = normalizePseudo(data.pseudo);
    const targetPseudo = normalizePseudo(expectedPseudo);
    return tokenPseudo === targetPseudo && data.expiresAt > Date.now();
  } catch {
    return false;
  }
}

async function incrementerVouchGlobal() {
  vouchesGlobalCount += 1;
  if (db) {
    try {
      await db.collection('compteurs').updateOne(
        { _id: 'vouches' },
        { $inc: { total: 1 } },
        { upsert: true }
      );
    } catch (err) {
      console.error("Erreur incrémentation vouch :", err);
    }
  }
  io.emit('updateVouchGlobal', { vouches: vouchesGlobalCount });
}

const GIFTS_CATALOG_PATH = path.join(__dirname, 'public', 'gifts-catalog.json');
let giftsCatalogCache = null;

function reloadGiftsCatalog() {
  try {
    if (fs.existsSync(GIFTS_CATALOG_PATH)) {
      giftsCatalogCache = JSON.parse(fs.readFileSync(GIFTS_CATALOG_PATH, 'utf8'));
    }
  } catch (err) {
    console.error("Erreur chargement gifts-catalog.json :", err);
  }
}
reloadGiftsCatalog();

app.post('/register', authLimiter, async (req, res) => {
  let { pseudo, apiKey, email, password } = req.body;
  try {
    if (!db) return res.status(500).send("Base de données en cours de connexion.");
    email = safeText(email).toLowerCase();
    let pseudoNettoye;
    try {
      pseudoNettoye = normalizePseudo(pseudo);
    } catch {
      return res.redirect('/login.html?error=invalid_pseudo&tab=register');
    }
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

app.post('/login', authLimiter, async (req, res) => {
  let { pseudo, password, rememberMe } = req.body;
  try {
    if (!db) return res.status(500).send("Base de données en cours de connexion.");
    let pseudoNettoye;
    try {
      pseudoNettoye = normalizePseudo(pseudo);
    } catch {
      if (req.headers['content-type']?.includes('application/json')) {
        return res.status(401).json({ error: "Identifiants invalides." });
      }
      return res.redirect('/login.html?error=wrong_credentials');
    }

    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ pseudo: pseudoNettoye });
    if (user && typeof password === 'string' && await bcrypt.compare(password, user.password)) {
      await new Promise((resolve, reject) =>
        req.session.regenerate((error) => error ? reject(error) : resolve())
      );

      req.session.user = { id: user._id, pseudo: user.pseudo, email: user.email, role: user.role || 'streamer' };
      await new Promise((resolve, reject) => req.session.save((err) => err ? reject(err) : resolve()));

      if (rememberMe) {
        const selector = crypto.randomBytes(16).toString('hex');
        const validator = crypto.randomBytes(32).toString('hex');
        const validatorHash = crypto.createHash('sha256').update(validator).digest('hex');
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await db.collection('remember_tokens').insertOne({
          userId: user._id,
          selector,
          validatorHash,
          expiresAt,
          createdAt: new Date()
        });

        res.cookie('remember_token', `${selector}:${validator}`, {
          httpOnly: true,
          secure: isProduction,
          sameSite: 'lax',
          path: '/',
          maxAge: 30 * 24 * 60 * 60 * 1000
        });
      }

      if (req.headers['content-type']?.includes('application/json')) {
        return res.json({ success: true, redirect: '/choix.html' });
      }
      return res.redirect('/choix.html');
    }

    if (req.headers['content-type']?.includes('application/json')) {
      return res.status(401).json({ error: "Pseudo ou mot de passe incorrect." });
    }
    res.redirect('/login.html?error=wrong_credentials');
  } catch (err) {
    res.status(500).send("Erreur serveur.");
  }
});

async function effectuerDeconnexion(req, res) {
  try {
    const cookies = parseCookies(req);
    const cookieToken = cookies.remember_token;
    if (cookieToken && db) {
      const [selector] = cookieToken.split(':');
      if (selector) {
        await db.collection('remember_tokens').deleteOne({ selector }).catch(() => {});
      }
    }
  } catch {}

  res.clearCookie('remember_token', { path: '/' });
  req.session.destroy(() => {
    res.clearCookie('__Host-tokoverlay', { path: '/' });
    if (req.headers['content-type']?.includes('application/json')) {
      return res.json({ success: true });
    }
    res.redirect('/login.html');
  });
}

app.get('/logout', effectuerDeconnexion);
app.post('/logout', effectuerDeconnexion);

app.post('/api/forgot-password', authLimiter, async (req, res) => {
  let { email } = req.body;
  try {
    if (!db) return res.status(500).json({ error: "Base de données indisponible." });
    email = safeText(email).toLowerCase();
    
    const user = await db.collection('users').findOne({ email });
    if (!user) {
      return res.json({ success: true, message: "Si cet e-mail existe, un lien a été envoyé. Pensez à vérifier votre dossier Spams / Courriers indésirables." });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = Date.now() + 15 * 60 * 1000;

    await db.collection('users').updateOne(
      { email },
      { $set: { resetToken, resetExpires } }
    );

    const resetLink = `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}&email=${encodeURIComponent(email)}`;

    const { error } = await resend.emails.send({
      from: 'TokOverlay <onboarding@resend.dev>',
      to: [email],
      subject: 'Réinitialisation de votre mot de passe - TokOverlay',
      html: `
        <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; background: #f9f9f9; border-radius: 10px;">
          <h2 style="color: #6366f1;">Réinitialisation de mot de passe</h2>
          <p>Bonjour,</p>
          <p>Vous avez demandé la réinitialisation de votre mot de passe pour votre compte TokOverlay.</p>
          <p>Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe (ce lien est valable 15 minutes) :</p>
          <a href="${resetLink}" style="display: inline-block; padding: 12px 20px; background: #22d3ee; color: #000; font-weight: bold; text-decoration: none; border-radius: 5px; margin: 20px 0;">Réinitialiser mon mot de passe</a>
          <p>Si vous n'avez pas fait cette demande, vous pouvez ignorer cet e-mail.</p>
          <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
          <p style="font-size: 12px; color: #666;">TokOverlay - Tous droits réservés.</p>
        </div>
      `
    });

    if (error) {
      console.error("Erreur Resend :", error);
      return res.status(500).json({ error: "Erreur lors de l'envoi de l'e-mail." });
    }

    res.json({ success: true, message: "E-mail de réinitialisation envoyé avec succès ! Pensez à vérifier votre dossier Spams / Courriers indésirables." });
  } catch (err) {
    console.error("Erreur serveur forgot-password :", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post('/api/reset-password', async (req, res) => {
  let { email, token, newPassword } = req.body;
  try {
    if (!db) return res.status(500).json({ error: "Base de données indisponible." });
    email = safeText(email).toLowerCase();
    const cleanToken = safeText(token);

    if (!email || !cleanToken || !newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: "Données invalides ou mot de passe trop court (min 6 caractères)." });
    }

    const user = await db.collection('users').findOne({
      email,
      resetToken: cleanToken,
      resetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: "Lien de réinitialisation invalide ou expiré." });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.collection('users').updateOne(
      { email },
      { 
        $set: { password: hashedPassword },
        $unset: { resetToken: "", resetExpires: "" }
      }
    );

    res.json({ success: true, message: "Mot de passe mis à jour avec succès !" });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post('/api/contact', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Vous devez être connecté." });
  }

  const { type, message } = req.body;
  const user = req.session.user;

  if (!message || message.trim() === '') {
    return res.status(400).json({ error: "Le message ne peut pas être vide." });
  }

  try {
    await resend.emails.send({
      from: 'TokOverlay <onboarding@resend.dev>',
      to: ['gueganoscar@gmail.com'],
      subject: `[TokOverlay] ${type} de @${user.pseudo}`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background: #f4f4f5; border-radius: 10px; color: #18181b;">
          <h2 style="color: #6366f1;">Nouveau retour utilisateur (${type})</h2>
          <p><strong>Streamer :</strong> @${user.pseudo}</p>
          <p><strong>Email :</strong> ${user.email}</p>
          <hr style="border: none; border-top: 1px solid #e4e4e7; margin: 15px 0;">
          <p><strong>Message :</strong></p>
          <blockquote style="background: #ffffff; padding: 12px; border-left: 4px solid #6366f1; margin: 0; border-radius: 4px;">
            ${message.replace(/\n/g, '<br>')}
          </blockquote>
        </div>
      `
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Erreur envoi suggestion :", err);
    res.status(500).json({ error: "Erreur lors de l'envoi du message." });
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

app.post('/api/update-profile', async (req, res) => {
  let { pseudo, apiKey } = req.body;
  if (!req.session.user || !db) return res.status(401).json({ error: "Non autorisé" });
  try {
    let nvPseudo;
    try {
      nvPseudo = normalizePseudo(pseudo);
    } catch {
      return res.status(400).json({ error: "Pseudo invalide." });
    }

    const nvApiKey = safeText(apiKey);
    const updateData = { pseudo: nvPseudo };

    if (nvApiKey !== "") {
      updateData.apiKey = nvApiKey;
    }

    const conflict = await db.collection('users').findOne({
      pseudo: nvPseudo,
      email: { $ne: req.session.user.email }
    });

    if (conflict) {
      return res.status(409).json({ error: "Ce pseudo est déjà utilisé par un autre compte." });
    }

    await db.collection('users').updateOne(
      { email: req.session.user.email }, 
      { $set: updateData }
    );
    
    req.session.user.pseudo = nvPseudo;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get('/overlay/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'overlay.html')));
app.get('/overlay-vip/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vip-overlay.html')));
app.get('/layout/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'layout.html')));
app.get('/elimination/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'elimination.html')));
app.get('/elimination-boucle/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'elimination-boucle.html')));
app.get('/simulation/:username', (req, res) => {
  if (!req.session.user || !isAdmin(req.session.user)) {
    return res.redirect('/choix.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'simulation.html'));
});

app.get('/api/gifts/:username', async (req, res) => {
  try {
    const pseudo = normalizePseudo(req.params.username);
    if (!req.session.user || !canManage(req.session.user, pseudo)) {
      return res.status(401).json({ error: "Non autorisé" });
    }

    if (giftsCatalogCache && Array.isArray(giftsCatalogCache) && giftsCatalogCache.length > 0) {
      return res.json(giftsCatalogCache);
    }

    const data = connexionsActives[pseudo];
    if (data && data.connection && typeof data.connection.getAvailableGifts === 'function') {
      try {
        const liste = await data.connection.getAvailableGifts();
        const cadeaux = (Array.isArray(liste) ? liste : [])
          .map(g => ({
            name: safeText(g.name, 'Cadeau'),
            diamond_count: positiveInteger(g.diamond_count, 1),
            image: safeText(g.image?.url_list?.[0] || g.icon?.url_list?.[0], '')
          }))
          .filter(g => g.image)
          .sort((a, b) => a.diamond_count - b.diamond_count);

        if (cadeaux.length > 0) return res.json(cadeaux);
      } catch (err) {
        console.error('Erreur getAvailableGifts :', err);
      }
    }

    res.json([]);
  } catch {
    res.status(400).json({ error: "Requête invalide." });
  }
});

app.get('/api/test-vip/:username', (req, res) => {
  const pseudo = req.params.username;
  io.to(`streamer:${pseudo}`).emit('vip_alert', { username: "Testeur_VIP", giftName: "galaxy" });
  setTimeout(() => {
    io.to(`streamer:${pseudo}`).emit('roblox_pseudo', { username: "Testeur_VIP", message: "MonPseudoRoblox123" });
  }, 1000);
  res.send(`Test de simulation VIP lancé pour @${pseudo} ! Va voir ton overlay.`);
});

app.get('/encheres/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/login.html');
  try {
    const targetPseudo = normalizePseudo(req.params.username);
    if (req.session.user.pseudo !== targetPseudo) return res.redirect('/encheres/' + encodeURIComponent(req.session.user.pseudo));
  } catch {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'controle-encheres.html'));
});

app.get('/statistiques/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/login.html');
  try {
    const targetPseudo = normalizePseudo(req.params.username);
    if (req.session.user.pseudo !== targetPseudo) return res.redirect('/statistiques/' + encodeURIComponent(req.session.user.pseudo));
  } catch {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'statistiques.html'));
});

app.get('/admin-live/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/login.html');
  
  if (isAdmin(req.session.user)) {
    return res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
  }

  try {
    const targetPseudo = normalizePseudo(req.params.username);
    if (req.session.user.pseudo !== targetPseudo) {
      return res.redirect('/admin-live/' + encodeURIComponent(req.session.user.pseudo));
    }
  } catch {
    return res.redirect('/login.html');
  }
  
  res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
});

app.get('/api/admin/stats-globales', async (req, res) => {
  if (!req.session.user || !isAdmin(req.session.user)) {
    return res.status(403).json({ error: "Accès refusé. Réservé à l'administrateur." });
  }
  if (!db) return res.json({ streamers: [] });

  try {
    const streamers = await db.collection('users').find({}).project({ password: 0, apiKey: 0 }).toArray();
    
    const resultat = streamers.map(s => {
      const liveData = connexionsActives[s.pseudo];
      const isOnline = Boolean(liveData && liveData.connection && liveData.connection.isConnected);
      const diamantsSessionActuelle = liveData ? Object.values(liveData.gifters).reduce((sum, g) => sum + g.coins, 0) : 0;
      
      return {
        pseudo: s.pseudo,
        email: s.email,
        totalDiamantsGlobal: s.totalDiamantsGlobal || 0,
        diamantsSessionActuelle,
        enLigne: isOnline
      };
    });

    res.json({ streamers: resultat });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get('/vip-room', (req, res) => {
  if (!req.session.user || !isAdmin(req.session.user)) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'vip.html'));
});

app.get('/api/historique/:pseudo', async (req, res) => {
  try {
    const pseudo = normalizePseudo(req.params.pseudo);
    if (!req.session.user || !canManage(req.session.user, pseudo)) return res.status(401).json({ error: "Non autorisé" });
    if (!db) return res.json({ lives: [], encheres: [] });

    const lives = await db.collection('historique_lives').find({ pseudo }).sort({ fin: -1 }).limit(5).toArray();
    const encheres = await db.collection('historique_encheres').find({ pseudo }).sort({ date: -1 }).limit(5).toArray();
    res.json({ lives, encheres });
  } catch {
    res.status(400).json({ error: "Requête invalide." });
  }
});

app.get('/api/live-status/:pseudo', async (req, res) => {
  try {
    const pseudo = normalizePseudo(req.params.pseudo);
    if (!req.session.user || !canManage(req.session.user, pseudo)) {
      return res.status(403).json({ error: "Accès refusé." });
    }

    const data = connexionsActives[pseudo];
    const isOnline = Boolean(data && data.connection && data.connection.isConnected);
    
    res.json({ 
      online: isOnline,
      connected: Boolean(data)
    });
  } catch {
    res.status(400).json({ error: "Requête invalide." });
  }
});

app.get('/api/live-stats/:pseudo', async (req, res) => {
  try {
    const pseudo = normalizePseudo(req.params.pseudo);
    if (!req.session.user || !canManage(req.session.user, pseudo)) return res.status(401).json({ error: "Non autorisé" });
    
    const data = connexionsActives[pseudo];
    if (!data) return res.json({ totalDiamonds: 0, totalLikes: 0 });
    res.json({
      totalDiamonds: Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0),
      totalLikes: Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0)
    });
  } catch {
    res.status(400).json({ error: "Requête invalide." });
  }
});

// ----------------------------------------------------
// GESTION FLUX TIKTOK LIVE
// ----------------------------------------------------

const connexionsActives = {};
const ELIGIBLE_GIFTS = ["whale diving", "corgi", "swan", "galaxy", "donut"];
const waitingUsers = new Map();

setInterval(() => {
  const maintenant = Date.now();
  for (const [cle, expiration] of waitingUsers.entries()) {
    if (maintenant > expiration) {
      waitingUsers.delete(cle);
    }
  }
}, 5 * 60 * 1000);

function tirerRecompenseRoue(options) {
  if (!options || options.length === 0) return "Rien";
  const totalProb = options.reduce((sum, opt) => sum + (Number(opt.prob) || 0), 0);
  let random = Math.random() * totalProb;
  let current = 0;
  for (const opt of options) {
    current += (Number(opt.prob) || 0);
    if (random <= current) return opt.name;
  }
  return options[options.length - 1].name;
}

function arreterEcouteLive(pseudo, data, reason) {
  if (!data || data.closed) return;
  data.closed = true;

  if (data.refreshTimer) {
    clearInterval(data.refreshTimer);
    data.refreshTimer = null;
  }

  if (data.enchere?.minuteur) {
    clearTimeout(data.enchere.minuteur);
    data.enchere.minuteur = null;
  }

  if (data.elimination?.timer) clearInterval(data.elimination.timer);
  if (data.elimination?.openTimer) clearTimeout(data.elimination.openTimer);
  if (data.eliminationBoucle?.timer) clearTimeout(data.eliminationBoucle.timer);
  if (data.eliminationBoucle?.openTimer) clearTimeout(data.eliminationBoucle.openTimer);

  if (!data.historySaved) {
    data.historySaved = true;
    sauvegarderHistoriqueLive(pseudo, data);
  }

  try {
    if (data.connection) {
      data.connection.removeAllListeners();
      if (typeof data.connection.disconnect === 'function') {
        data.connection.disconnect();
      }
    }
  } catch {}

  if (connexionsActives[pseudo] === data) {
    delete connexionsActives[pseudo];
  }
  
  io.to(`streamer:${pseudo}`).emit('liveArrete', { reason });
}

function demarrerEcouteLive(pseudo, apiKey) {
  if (connexionsActives[pseudo]) return;

  const connection = new TikTokLiveConnection(pseudo, { signApiKey: apiKey });
  const data = {
    connection,
    closed: false,
    historySaved: false,
    refreshTimer: null,
    likers: Object.create(null), 
    gifters: Object.create(null), 
    enchere: null, 
    bestGift: null,
    elimination: null,
    eliminationBoucle: null,
    debutLive: new Date(), 
    derniereGagnantId: null, 
    vouchFait: false, 
    objectif: null,
    roue: { active: true, mode: 'gifts', cout: 10, giftName: '', options: [{name: "Gage 1", prob: 50}, {name: "100 Diamants", prob: 50}] },
    coffre: { actif: false, secret: '', devoiles: [], recompense: '', gagnant: null, dernierMessageGagnant: '' },
    pendingUpdates: { likers: false, gifters: false, stats: false, objectif: false }
  };
  connexionsActives[pseudo] = data;

  data.refreshTimer = setInterval(() => {
    if (connexionsActives[pseudo] !== data || data.closed) {
      clearInterval(data.refreshTimer);
      return;
    }
    const p = data.pendingUpdates;

    if (p.likers) {
      io.to(`streamer:${pseudo}`).emit('updateTopLikers', Object.values(data.likers).sort((a, b) => b.likes - a.likes).slice(0, 3));
      p.likers = false;
    }
    if (p.gifters) {
      io.to(`streamer:${pseudo}`).emit('updateTopGifters', Object.values(data.gifters).sort((a, b) => b.coins - a.coins).slice(0, 3));
      p.gifters = false;
    }
    if (p.stats) {
      const totalDiamonds = Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0);
      const totalLikes = Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0);
      io.to(`streamer:${pseudo}`).emit('updateStatsLive', { totalDiamonds, totalLikes });
      p.stats = false;
    }
    if (p.objectif && data.objectif) {
      io.to(`streamer:${pseudo}`).emit('updateObjectif', etatObjectif(pseudo));
      p.objectif = false;
    }
  }, 1000); 

  connection.connect().catch((err) => {
    console.error(`[TikTokLive] Erreur connexion pour @${pseudo}:`, err);
    io.to(`streamer:${pseudo}`).emit('erreurConnexion', "Impossible de se connecter au live.");
    arreterEcouteLive(pseudo, data, 'connect_error');
  });

  connection.once('error', (err) => {
    console.error(`[TikTokLive] Erreur runtime pour @${pseudo}:`, err);
    arreterEcouteLive(pseudo, data, 'error');
  });

  connection.on('like', (d = {}) => {
    if (data.closed) return;
    const user = d.user && typeof d.user === 'object' ? d.user : {};
    const id = resolveUserId(d, user);
    const nickname = safeText(user.nickname, 'Anonyme');
    const likes = positiveInteger(d.count, 1);
    const avatar = avatarFor(user, nickname);
    
    if (!data.likers[id]) data.likers[id] = { nickname, profilePictureUrl: avatar, likes: 0 };
    data.likers[id].likes += likes;
    
    data.pendingUpdates.likers = true;
    data.pendingUpdates.stats = true;
    if (data.objectif && data.objectif.metrique === 'likes') data.pendingUpdates.objectif = true;

    io.to(`streamer:${pseudo}`).emit('updateTopLikers', Object.values(data.likers).sort((a, b) => b.likes - a.likes).slice(0, 3));
  });

  connection.on('subscribe', (d = {}) => {
    if (data.closed) return;
    const user = d.user && typeof d.user === 'object' ? d.user : {};
    const nickname = safeText(user.nickname || d.nickname, 'Anonyme');

    if (data.roue && data.roue.mode === 'subs') {
      const optionGagnee = tirerRecompenseRoue(data.roue.options);
      const optionsPourOverlay = data.roue.options.map(o => o.name);
      io.to(`streamer:${pseudo}`).emit('tournerRoue', { gagnant: nickname, resultat: optionGagnee, allOptions: optionsPourOverlay });
    }
  });

  connection.on('gift', (d = {}) => {
    if (data.closed) return;
    if (d.gift?.type === 1 && !d.repeatEnd) return;
    const user = d.user && typeof d.user === 'object' ? d.user : {};
    const id = resolveUserId(d, user);
    const nickname = safeText(user.nickname || d.nickname, 'Anonyme');
    const username = safeText(user.uniqueId || d.uniqueId, nickname);
    const giftName = safeText(d.giftName || d.gift?.name, '').toLowerCase();

    if (ELIGIBLE_GIFTS.includes(giftName)) {
      if (!waitingUsers.has(`${pseudo}_${username}`)) {
        io.to(`streamer:${pseudo}`).emit('vip_alert', { username, giftName });
      }
      waitingUsers.set(`${pseudo}_${username}`, Date.now() + 90000);
    }
    
    const diamondCount = positiveInteger(d.gift?.diamondCount, 0);
    const repeatCount = positiveInteger(d.repeatCount, 1);
    const totalPieces = diamondCount * repeatCount;
    if (totalPieces === 0) return;
    
    const avatar = avatarFor(user, nickname);
    const giftIcon = safeText(d.gift?.icon?.urlList?.[0], 'https://via.placeholder.com/60');

    if (!data.gifters[id]) data.gifters[id] = { nickname, profilePictureUrl: avatar, coins: 0 };
    data.gifters[id].coins += totalPieces;
    
    if (db) {
      db.collection('users').updateOne(
        { pseudo: pseudo },
        { $inc: { totalDiamantsGlobal: totalPieces } },
        { upsert: true }
      ).catch(() => {});
    }
    
    traiterDonPourEnchere(pseudo, id, nickname, avatar, totalPieces);

    if (data.roue && data.roue.mode === 'gifts' && totalPieces >= (data.roue.cout || 1)) {
      if (!data.roue.giftName || giftName === data.roue.giftName.toLowerCase()) {
        const optionGagnee = tirerRecompenseRoue(data.roue.options);
        const optionsPourOverlay = data.roue.options.map(o => o.name);
        io.to(`streamer:${pseudo}`).emit('tournerRoue', { gagnant: nickname, resultat: optionGagnee, allOptions: optionsPourOverlay });
      }
    }
    
    if (data.elimination && data.elimination.actif && !data.elimination.locked && !data.elimination.gagnant && totalPieces >= data.elimination.cout) {
      const elim = data.elimination;
      const nombreEntrees = Math.floor(totalPieces / elim.cout);
      for (let i = 0; i < nombreEntrees; i++) {
        elim.places.push({ id, nickname, avatar, eliminated: false });
      }
      elim.totalCoins += totalPieces;
      elim.totalsParId[id] = (elim.totalsParId[id] || 0) + totalPieces;
      io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
    }

    if (data.eliminationBoucle && data.eliminationBoucle.actif && !data.eliminationBoucle.locked && !data.eliminationBoucle.gagnant && totalPieces >= data.eliminationBoucle.cout) {
      const elim = data.eliminationBoucle;
      const nombreEntrees = Math.floor(totalPieces / elim.cout);
      for (let i = 0; i < nombreEntrees; i++) {
        elim.places.push({ id, nickname, avatar, eliminated: false });
      }
      elim.totalCoins += totalPieces;
      elim.totalsParId[id] = (elim.totalsParId[id] || 0) + totalPieces;
      io.to(`streamer:${pseudo}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudo));
    }

    if (!data.bestGift || totalPieces > data.bestGift.montant) {
      data.bestGift = { pseudo: nickname, montant: totalPieces, icon: giftIcon };
      io.to(`streamer:${pseudo}`).emit('updateBestGift', data.bestGift); 
    }

    data.pendingUpdates.gifters = true;
    data.pendingUpdates.stats = true;
    if (data.objectif && data.objectif.metrique === 'diamants') data.pendingUpdates.objectif = true;

    io.to(`streamer:${pseudo}`).emit('updateTopGifters', Object.values(data.gifters).sort((a, b) => b.coins - a.coins).slice(0, 3));
    if (data.objectif) io.to(`streamer:${pseudo}`).emit('updateObjectif', etatObjectif(pseudo));
  });

  connection.on('chat', (d = {}) => {
    if (data.closed) return;
    const user = d.user && typeof d.user === 'object' ? d.user : {};
    const id = resolveUserId(d, user);
    const nickname = safeText(d.nickname || user.nickname, 'Anonyme');
    const username = safeText(user.uniqueId || d.uniqueId, nickname);
    const avatar = avatarFor(user, nickname);
    const message = safeText(d.comment || d.text || d.message || d.msg || d.content, '');

    const userKey = `${pseudo}_${username}`;
    if (waitingUsers.has(userKey)) {
      if (Date.now() <= waitingUsers.get(userKey)) {
        io.to(`streamer:${pseudo}`).emit('roblox_pseudo', { username, message });
      }
      waitingUsers.delete(userKey);
    }

    io.to(`streamer:${pseudo}`).emit('chatEnDirect', { nickname, avatar, message });

    if (data.enchere && data.enchere.dons[id]) {
      data.enchere.dons[id].dernierMessageChat = message;
    }

    if (data.coffre && data.coffre.actif && !data.coffre.gagnant) {
      const msgNettoye = message.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      const secretNettoye = data.coffre.secret.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      
      if (msgNettoye !== "" && msgNettoye === secretNettoye) {
        data.coffre.gagnant = { id, nickname, avatar };
        data.coffre.actif = false;
        
        io.to(`streamer:${pseudo}`).emit('updateCoffre', etatCoffrePublic(pseudo)); 
        io.to(`streamer:${pseudo}`).emit('coffreOuvert', etatCoffrePublic(pseudo)); 
      }
    } else if (data.coffre && data.coffre.gagnant && id === data.coffre.gagnant.id) {
      data.coffre.dernierMessageGagnant = message;
      io.to(`streamer:${pseudo}`).emit('updateMessageGagnantCoffre', { message }); 
    }

    if (data.elimination && data.elimination.gagnantId && id === data.elimination.gagnantId && !data.elimination.messageGagnant) {
      data.elimination.messageGagnant = message;
      io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
    }

    if (data.derniereGagnantId && id === data.derniereGagnantId) {
      io.to(`streamer:${pseudo}`).emit('updateMessageGagnant', { message });

      if (!data.vouchFait && message.toLowerCase() === 'vouch') {
        data.vouchFait = true;
        incrementerVouchGlobal();
        io.to(`streamer:${pseudo}`).emit('vouchConfirme', {});
      }
    }
  });

  connection.once('disconnect', () => arreterEcouteLive(pseudo, data, 'disconnect'));
  connection.once('streamEnd', () => arreterEcouteLive(pseudo, data, 'streamEnd'));
}

function etatCoffrePublic(pseudo) {
  const coffre = connexionsActives[pseudo]?.coffre;
  if (!coffre) return null;
  return {
    actif: coffre.actif,
    longueur: coffre.secret.length,
    devoiles: coffre.devoiles,
    caracteres: coffre.secret.split('').map((char, index) => coffre.devoiles[index] ? char : '_'),
    recompense: coffre.recompense,
    gagnant: coffre.gagnant,
    dernierMessageGagnant: coffre.dernierMessageGagnant,
    secretComplet: coffre.gagnant ? coffre.secret : null
  };
}

function sauvegarderHistoriqueLive(pseudo, customData = null) {
  const data = customData || connexionsActives[pseudo];
  if (!data || !db) return;

  const gifters = Object.values(data.gifters);
  const likers = Object.values(data.likers);
  const totalDiamants = gifters.reduce((s, g) => s + g.coins, 0);
  const totalLikes = likers.reduce((s, l) => s + l.likes, 0);
  const topDonateur = gifters.sort((a, b) => b.coins - a.coins)[0] || null;

  if (totalDiamants === 0 && totalLikes === 0) return;

  db.collection('historique_lives').insertOne({
    pseudo,
    debut: data.debutLive,
    fin: new Date(),
    totalDiamants,
    totalLikes,
    topDonateur: topDonateur ? { nickname: topDonateur.nickname, coins: topDonateur.coins } : null
  }).catch(() => {});
}

function demarrerEnchere(pseudo, dureeSecondes, snipeSecondes, miseMinimale) {
  const data = connexionsActives[pseudo];
  if (!data) return;
  if (data.enchere?.minuteur) {
    clearTimeout(data.enchere.minuteur);
    data.enchere.minuteur = null;
  }

  const enchere = {
    actif: true, phase: 'timer',
    snipeMs: snipeSecondes * 1000, miseMinimale: miseMinimale || 0,
    finTimestamp: Date.now() + dureeSecondes * 1000, dons: Object.create(null), minuteur: null,
    totalDiamantsEnchere: 0
  };
  data.enchere = enchere;
  programmerTransitionOuFin(pseudo, enchere);
  io.to(`streamer:${pseudo}`).emit('enchereDemarree', etatEnchere(pseudo));
}

function etatObjectif(pseudo) {
  const data = connexionsActives[pseudo];
  if (!data || !data.objectif) return null;
  const valeurActuelle = data.objectif.metrique === 'likes'
    ? Object.values(data.likers).reduce((s, l) => s + l.likes, 0)
    : Object.values(data.gifters).reduce((s, g) => s + g.coins, 0);
  return {
    label: data.objectif.label,
    metrique: data.objectif.metrique,
    cible: data.objectif.cible,
    valeurActuelle
  };
}

function etatElimination(pseudo) {
  const elim = connexionsActives[pseudo]?.elimination;
  if (!elim || !elim.actif) return { actif: false };
  return {
    actif: true,
    cout: elim.cout,
    giftImage: elim.giftImage,
    giftName: elim.giftName,
    locked: elim.locked,
    eliminationEnCours: elim.eliminationEnCours,
    totalCoins: elim.totalCoins,
    places: elim.places,
    openEndsAt: elim.openEndsAt,
    nextElimination: elim.nextElimination,
    gagnant: elim.gagnant,
    messageGagnant: elim.messageGagnant
  };
}

function etatEliminationBoucle(pseudo) {
  const elim = connexionsActives[pseudo]?.eliminationBoucle;
  if (!elim || !elim.actif) return { actif: false };
  return {
    actif: true,
    cout: elim.cout,
    giftImage: elim.giftImage,
    giftName: elim.giftName,
    locked: elim.locked,
    eliminationEnCours: elim.eliminationEnCours,
    totalCoins: elim.totalCoins,
    places: elim.places,
    openEndsAt: elim.openEndsAt,
    nextElimination: elim.nextElimination,
    gagnant: elim.gagnant,
    messageGagnant: elim.messageGagnant
  };
}

function processEliminationKill(pseudo, data) {
  const elim = data?.elimination;
  if (!elim || !elim.eliminationEnCours) return;

  const vivants = elim.places.filter(p => !p.eliminated);
  const joueursUniquesVivants = new Set(vivants.map(p => p.id));

  if (joueursUniquesVivants.size <= 1) {
    if (elim.timer) { clearInterval(elim.timer); elim.timer = null; }
    elim.eliminationEnCours = false;
    elim.nextElimination = null;

    const survivant = vivants[0];
    if (survivant) {
      elim.gagnantId = survivant.id;
      elim.gagnant = {
        nickname: survivant.nickname,
        avatar: survivant.avatar,
        coins: elim.totalsParId[survivant.id] || 0
      };
    }

    io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
    return;
  }

  const idx = Math.floor(Math.random() * vivants.length);
  vivants[idx].eliminated = true;
  elim.nextElimination = Date.now() + (5 * 1000);
  io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
}

function processBoucleKill(pseudo, data) {
  const elim = data?.eliminationBoucle;
  if (!elim || !elim.eliminationEnCours) return;

  const vivants = elim.places.filter(p => !p.eliminated);
  const joueursUniquesVivants = new Set(vivants.map(p => p.id));

  if (joueursUniquesVivants.size <= 1) {
    if (elim.timer) { clearTimeout(elim.timer); elim.timer = null; }
    elim.eliminationEnCours = false;
    elim.nextElimination = null;

    const survivant = vivants[0];
    if (survivant) {
      elim.gagnantId = survivant.id;
      elim.gagnant = {
        id: survivant.id,
        nickname: survivant.nickname,
        avatar: survivant.avatar,
        coins: elim.totalsParId[survivant.id] || 0
      };
    }

    io.to(`streamer:${pseudo}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudo));
    return;
  }

  const idx = Math.floor(Math.random() * vivants.length);
  vivants[idx].eliminated = true;

  const restantsVivants = elim.places.filter(p => !p.eliminated);
  const joueursUniquesRestants = new Set(restantsVivants.map(p => p.id));

  if (joueursUniquesRestants.size > 1) {
    elim.locked = false;
    elim.eliminationEnCours = false;
    elim.openEndsAt = Date.now() + (elim.tempsOuverture * 1000);
    elim.nextElimination = null;
    io.to(`streamer:${pseudo}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudo));

    if (elim.timer) clearTimeout(elim.timer);
    elim.timer = setTimeout(() => {
      if (elim && !elim.gagnant) {
        elim.locked = true;
        elim.eliminationEnCours = true;
        elim.openEndsAt = null;
        elim.nextElimination = null;
        io.to(`streamer:${pseudo}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudo));
        processBoucleKill(pseudo, data);
      }
    }, elim.tempsOuverture * 1000);
  } else {
    processBoucleKill(pseudo, data);
  }
}

function etatEnchere(pseudo) {
  const enchere = connexionsActives[pseudo]?.enchere;
  if (!enchere) return null;
  return {
    phase: enchere.phase,
    tempsRestant: Math.max(enchere.finTimestamp - Date.now(), 0),
    snipeMs: enchere.snipeMs,
    miseMinimale: enchere.miseMinimale,
    classement: Object.values(enchere.dons).sort((a, b) => b.coins - a.coins).slice(0, 3),
    totalDiamantsEnchere: enchere.totalDiamantsEnchere
  };
}

function programmerTransitionOuFin(pseudo, enchere) {
  const data = connexionsActives[pseudo];
  if (!data || !data.enchere || data.enchere !== enchere) return;
  
  if (enchere.minuteur) {
    clearTimeout(enchere.minuteur);
    enchere.minuteur = null;
  }
  const delai = Math.max(enchere.finTimestamp - Date.now(), 0);

  enchere.minuteur = setTimeout(() => {
    const currentData = connexionsActives[pseudo];
    if (!currentData || currentData.enchere !== enchere || !enchere.actif) return;

    if (enchere.phase === 'timer') {
      enchere.phase = 'snipe';
      enchere.finTimestamp = Date.now() + enchere.snipeMs;
      io.to(`streamer:${pseudo}`).emit('updateEnchere', etatEnchere(pseudo));
      programmerTransitionOuFin(pseudo, enchere);
    } else {
      terminerEnchere(pseudo);
    }
  }, isNaN(delai) || delai < 0 ? 1000 : delai);
}

function traiterDonPourEnchere(pseudo, id, nickname, avatar, totalPieces) {
  const enchere = connexionsActives[pseudo]?.enchere;
  if (!enchere || !enchere.actif) return;

  if (!enchere.dons[id]) enchere.dons[id] = { id, nickname, profilePictureUrl: avatar, coins: 0, dernierMessageChat: '' };
  enchere.dons[id].coins += totalPieces;
  enchere.totalDiamantsEnchere += totalPieces;

  const restant = enchere.finTimestamp - Date.now();
  if (enchere.phase === 'snipe' || restant <= enchere.snipeMs) {
    enchere.phase = 'snipe';
    enchere.finTimestamp = Date.now() + enchere.snipeMs;
    programmerTransitionOuFin(pseudo, enchere);
  }

  io.to(`streamer:${pseudo}`).emit('updateEnchere', etatEnchere(pseudo));
}

function terminerEnchere(pseudo) {
  const enchere = connexionsActives[pseudo]?.enchere;
  if (!enchere) return;

  const donsValides = Object.values(enchere.dons).filter(don => don.coins >= enchere.miseMinimale).sort((a, b) => b.coins - a.coins);
  
  if (donsValides.length >= 2 && donsValides[0].coins === donsValides[1].coins) {
    enchere.phase = 'timer';
    enchere.finTimestamp = Date.now() + 30000;
    io.to(`streamer:${pseudo}`).emit('egaliteEnchere', { message: "Égalité ! +30s ajoutées !" });
    programmerTransitionOuFin(pseudo, enchere);
    io.to(`streamer:${pseudo}`).emit('updateEnchere', etatEnchere(pseudo));
    return;
  }

  enchere.actif = false;
  const gagnant = donsValides[0] || null;

  const data = connexionsActives[pseudo];
  if (data) {
    data.derniereGagnantId = gagnant?.id || null;
    data.vouchFait = false;
  }

  if (db) {
    db.collection('historique_encheres').insertOne({
      pseudo,
      date: new Date(),
      gagnant: gagnant ? { nickname: gagnant.nickname, coins: gagnant.coins } : null,
      totalDiamantsEnchere: enchere.totalDiamantsEnchere,
      classement: donsValides.slice(0, 3).map(u => ({ nickname: u.nickname, coins: u.coins }))
    }).catch(() => {});
  }

  io.to(`streamer:${pseudo}`).emit('enchereTerminee', { 
    gagnant, 
    classement: donsValides.slice(0, 3),
    totalDiamantsEnchere: enchere.totalDiamantsEnchere 
  });
}

// ----------------------------------------------------
// SOCKET.IO EVENT HANDLERS
// ----------------------------------------------------

io.on('connection', socket => {

  socket.on('simulerMessageTest', (payload = {}) => {
    try {
      const { pseudo, senderPseudo, message } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);

      // VÉRIFICATION STRICTE ADMIN
      if (!isAdmin(socket.request.session?.user)) return;

      const data = connexionsActives[pseudoNettoye];
      if (!data) return;
      // ... suite inchangée ...

      const id = `simul_${senderPseudo}`;
      const nickname = senderPseudo;
      const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
      const totalPieces = positiveInteger(coins, 10);

      if (!data.gifters[id]) data.gifters[id] = { nickname, profilePictureUrl: avatar, coins: 0 };
      data.gifters[id].coins += totalPieces;

      traiterDonPourEnchere(pseudoNettoye, id, nickname, avatar, totalPieces);

      if (data.elimination && data.elimination.actif && !data.elimination.locked && !data.elimination.gagnant) {
        const elim = data.elimination;
        const nombreEntrees = Math.floor(totalPieces / elim.cout);
        for (let i = 0; i < nombreEntrees; i++) {
          elim.places.push({ id, nickname, avatar, eliminated: false });
        }
        elim.totalCoins += totalPieces;
        elim.totalsParId[id] = (elim.totalsParId[id] || 0) + totalPieces;
        io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
      }

      if (data.eliminationBoucle && data.eliminationBoucle.actif && !data.eliminationBoucle.locked && !data.eliminationBoucle.gagnant) {
        const elim = data.eliminationBoucle;
        const nombreEntrees = Math.floor(totalPieces / elim.cout);
        for (let i = 0; i < nombreEntrees; i++) {
          elim.places.push({ id, nickname, avatar, eliminated: false });
        }
        elim.totalCoins += totalPieces;
        elim.totalsParId[id] = (elim.totalsParId[id] || 0) + totalPieces;
        io.to(`streamer:${pseudoNettoye}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudoNettoye));
      }

      const giftIcon = 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/5ea6ceee6885dfb90c910fae1ba1c1bb~tplv-obj.png';
      if (!data.bestGift || totalPieces > data.bestGift.montant) {
        data.bestGift = { pseudo: nickname, montant: totalPieces, icon: giftIcon };
        io.to(`streamer:${pseudoNettoye}`).emit('updateBestGift', data.bestGift);
      }

      io.to(`streamer:${pseudoNettoye}`).emit('updateTopGifters', Object.values(data.gifters).sort((a, b) => b.coins - a.coins).slice(0, 3));
      
      const totalDiamonds = Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0);
      const totalLikes = Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0);
      io.to(`streamer:${pseudoNettoye}`).emit('updateStatsLive', { totalDiamonds, totalLikes });

    } catch (err) {
      console.error("Erreur simulation cadeau :", err);
    }
  });

  socket.on('simulerMessageTest', (payload = {}) => {
    try {
      const { pseudo, senderPseudo, message } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);

      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      if (!data) return;

      const id = `simul_${senderPseudo}`;
      const nickname = safeText(senderPseudo, 'Anonyme');
      const avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
      const texte = safeText(message, '');
      if (!texte) return;

      io.to(`streamer:${pseudoNettoye}`).emit('chatEnDirect', { nickname, avatar, message: texte });

      if (data.enchere && data.enchere.dons[id]) {
        data.enchere.dons[id].dernierMessageChat = texte;
      }

      if (data.coffre && data.coffre.actif && !data.coffre.gagnant) {
        const msgNettoye = texte.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
        const secretNettoye = data.coffre.secret.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");

        if (msgNettoye !== "" && msgNettoye === secretNettoye) {
          data.coffre.gagnant = { id, nickname, avatar };
          data.coffre.actif = false;

          io.to(`streamer:${pseudoNettoye}`).emit('updateCoffre', etatCoffrePublic(pseudoNettoye));
          io.to(`streamer:${pseudoNettoye}`).emit('coffreOuvert', etatCoffrePublic(pseudoNettoye));
        }
      } else if (data.coffre && data.coffre.gagnant && id === data.coffre.gagnant.id) {
        data.coffre.dernierMessageGagnant = texte;
        io.to(`streamer:${pseudoNettoye}`).emit('updateMessageGagnantCoffre', { message: texte });
      }

      if (data.elimination && data.elimination.gagnantId && id === data.elimination.gagnantId && !data.elimination.messageGagnant) {
        data.elimination.messageGagnant = texte;
        io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
      }

      if (data.derniereGagnantId && id === data.derniereGagnantId) {
        io.to(`streamer:${pseudoNettoye}`).emit('updateMessageGagnant', { message: texte });

        if (!data.vouchFait && texte.toLowerCase() === 'vouch') {
          data.vouchFait = true;
          incrementerVouchGlobal();
          io.to(`streamer:${pseudoNettoye}`).emit('vouchConfirme', {});
        }
      }

    } catch (err) {
      console.error("Erreur simulation message :", err);
    }
  });

  socket.on('rejoindre', async (payload = {}, ack = () => {}) => {
    try {
      const { pseudo, token, type } = payload;
      let pseudoNettoye;
      try {
        pseudoNettoye = normalizePseudo(pseudo);
      } catch {
        return ack({ ok: false, error: 'Pseudo invalide.' });
      }

      const utilisateurConnecte = socket.request.session?.user;
      const allowed = canManage(utilisateurConnecte, pseudoNettoye)
        || verifyOverlayToken(token, pseudoNettoye);

      if (!allowed) {
        console.warn(`[Socket.IO] Accès refusé pour rejoindre @${pseudoNettoye} (Token ou Session invalide)`);
        return ack({ ok: false, error: 'Authentification invalide.' });
      }

      if (!db) return ack({ ok: false, error: 'Base de données indisponible.' });
      const utilisateur = await db.collection('users').findOne({ pseudo: pseudoNettoye });
      if (!utilisateur) {
        return ack({ ok: false, error: 'Streamer inconnu.' });
      }

      socket.join(`streamer:${pseudoNettoye}`);
      demarrerEcouteLive(pseudoNettoye, utilisateur.apiKey);
      ack({ ok: true });

      // ENVOI IMMÉDIAT DU NOMBRE DE VOUCHS GLOBAL
      socket.emit('initVouch', { vouches: vouchesGlobalCount });
      socket.emit('updateVouchGlobal', { vouches: vouchesGlobalCount });

      // ENVOI IMMÉDIAT ET SYNCHRONE DES DONNÉES TEMPS RÉEL AU REJOIGNANT
      const data = connexionsActives[pseudoNettoye];
      if (data) {
        const topGifters = Object.values(data.gifters).sort((a, b) => b.coins - a.coins).slice(0, 3);
        const topLikers = Object.values(data.likers).sort((a, b) => b.likes - a.likes).slice(0, 3);
        socket.emit('updateTopGifters', topGifters);
        socket.emit('updateTopLikers', topLikers);

        const totalDiamonds = Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0);
        const totalLikes = Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0);
        socket.emit('updateStatsLive', { totalDiamonds, totalLikes });

        if (data.enchere && data.enchere.actif) {
          socket.emit('enchereDemarree', etatEnchere(pseudoNettoye));
          socket.emit('updateEnchere', etatEnchere(pseudoNettoye));
        }

        if (data.bestGift) socket.emit('updateBestGift', data.bestGift);
        if (data.objectif) socket.emit('updateObjectif', etatObjectif(pseudoNettoye));
        if (data.coffre) socket.emit('updateCoffre', etatCoffrePublic(pseudoNettoye));

        if (type === 'elimination-boucle') {
          if (data.eliminationBoucle) socket.emit('updateEliminationBoucle', etatEliminationBoucle(pseudoNettoye));
        } else {
          if (data.elimination) socket.emit('updateElimination', etatElimination(pseudoNettoye));
        }
      }
    } 
    catch (err) {
      console.error('[Socket.IO] Erreur dans rejoindre:', err);
      ack({ ok: false, error: 'Requête invalide.' });
    }
  });

  socket.on('configurerElimination', (payload = {}) => {
    try {
      const { pseudo, cout, intervalle, tempsOuverture, giftImage, giftName } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      if (!data) return;

      if (data.elimination?.timer) clearInterval(data.elimination.timer);
      if (data.elimination?.openTimer) clearTimeout(data.elimination.openTimer);

      const openTimeSec = positiveInteger(tempsOuverture, 30);

      data.elimination = {
        actif: true,
        cout: positiveInteger(cout, 1),
        giftImage: safeText(giftImage, ''),
        giftName: safeText(giftName, ''),
        intervalle: positiveInteger(intervalle, 5),
        locked: false,
        eliminationEnCours: false,
        places: [],
        totalCoins: 0,
        totalsParId: Object.create(null),
        openEndsAt: Date.now() + (openTimeSec * 1000),
        openTimer: null,
        nextElimination: null,
        timer: null,
        gagnant: null,
        gagnantId: null,
        messageGagnant: ''
      };

      data.elimination.openTimer = setTimeout(() => {
        if (data.elimination && !data.elimination.locked) {
          data.elimination.locked = true;
          data.elimination.eliminationEnCours = true;
          if (data.elimination.timer) clearInterval(data.elimination.timer);
          data.elimination.nextElimination = Date.now() + (5 * 1000);
          data.elimination.timer = setInterval(() => processEliminationKill(pseudoNettoye, data), 5000);
          
          io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
        }
      }, openTimeSec * 1000);

      io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
    } catch {}
  });

  socket.on('configurerEliminationBoucle', (payload = {}) => {
    try {
      const { pseudo, cout, tempsOuverture, giftImage, giftName } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      if (!data) return;

      if (data.eliminationBoucle?.timer) clearTimeout(data.eliminationBoucle.timer);
      if (data.eliminationBoucle?.openTimer) clearTimeout(data.eliminationBoucle.openTimer);

      const openTimeSec = positiveInteger(tempsOuverture, 30);

      data.eliminationBoucle = {
        actif: true,
        cout: positiveInteger(cout, 1),
        giftImage: safeText(giftImage, ''),
        giftName: safeText(giftName, ''),
        locked: false,
        eliminationEnCours: false,
        places: [],
        totalCoins: 0,
        totalsParId: Object.create(null),
        tempsOuverture: openTimeSec,
        openEndsAt: Date.now() + (openTimeSec * 1000),
        openTimer: null,
        nextElimination: null,
        timer: null,
        gagnant: null,
        gagnantId: null,
        messageGagnant: ''
      };

      data.eliminationBoucle.openTimer = setTimeout(() => {
        if (data.eliminationBoucle && !data.eliminationBoucle.locked) {
          data.eliminationBoucle.locked = true;
          data.eliminationBoucle.eliminationEnCours = true;
          data.eliminationBoucle.openEndsAt = null;
          data.eliminationBoucle.nextElimination = null;
          if (data.eliminationBoucle.timer) clearTimeout(data.eliminationBoucle.timer);

          io.to(`streamer:${pseudoNettoye}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudoNettoye));
          processBoucleKill(pseudoNettoye, data);
        }
      }, openTimeSec * 1000);

      io.to(`streamer:${pseudoNettoye}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudoNettoye));
    } catch {}
  });

  socket.on('updateEliminationSettings', (payload = {}) => {
    try {
      const { pseudo, cout, intervalle, giftImage, giftName } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      const elim = data?.elimination;
      if (!elim) return;

      if (cout !== undefined && cout !== '') elim.cout = positiveInteger(cout, elim.cout);
      if (giftImage !== undefined && giftImage !== '') elim.giftImage = safeText(giftImage, elim.giftImage);
      if (giftName !== undefined) elim.giftName = safeText(giftName, elim.giftName);

      if (intervalle !== undefined && intervalle !== '') {
        elim.intervalle = positiveInteger(intervalle, elim.intervalle);

        if (elim.eliminationEnCours && elim.timer) {
          clearInterval(elim.timer);
          elim.nextElimination = Date.now() + (elim.intervalle * 1000);
          elim.timer = setInterval(() => processEliminationKill(pseudoNettoye, data), elim.intervalle * 1000);
        }
      }

      io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
    } catch {}
  });

  socket.on('updateEliminationBoucleSettings', (payload = {}) => {
    try {
      const { pseudo, cout, giftImage, giftName } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      const elim = data?.eliminationBoucle;
      if (!elim) return;

      if (cout !== undefined && cout !== '') elim.cout = positiveInteger(cout, elim.cout);
      if (giftImage !== undefined && giftImage !== '') elim.giftImage = safeText(giftImage, elim.giftImage);
      if (giftName !== undefined) elim.giftName = safeText(giftName, elim.giftName);

      io.to(`streamer:${pseudoNettoye}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudoNettoye));
    } catch {}
  });

  socket.on('actionElimination', (payload = {}) => {
    try {
      const { pseudo, action } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      const elim = data?.elimination;
      if (!elim) return;

      if (action === 'lock') {
        elim.locked = true;
        if (elim.openTimer) { clearTimeout(elim.openTimer); elim.openTimer = null; }
      } else if (action === 'start_kill') {
        if (elim.gagnant) return;
        elim.locked = true;
        elim.eliminationEnCours = true;
        if (elim.openTimer) { clearTimeout(elim.openTimer); elim.openTimer = null; }
        if (elim.timer) clearInterval(elim.timer);
        elim.nextElimination = Date.now() + (5 * 1000);
        elim.timer = setInterval(() => processEliminationKill(pseudoNettoye, data), 5000);
      } else if (action === 'stop_kill') {
        elim.eliminationEnCours = false;
        if (elim.timer) { clearInterval(elim.timer); elim.timer = null; }
        elim.nextElimination = null;
      } else if (action === 'reset') {
        if (elim.timer) clearInterval(elim.timer);
        if (elim.openTimer) clearInterval(elim.openTimer);
        data.elimination = null;
        io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', { actif: false });
        return;
      }

      io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
    } catch {}
  });

  socket.on('actionEliminationBoucle', (payload = {}) => {
    try {
      const { pseudo, action } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      const elim = data?.eliminationBoucle;
      if (!elim) return;

      if (action === 'pause') {
        elim.eliminationEnCours = false;
        if (elim.timer) { clearTimeout(elim.timer); elim.timer = null; }
      } else if (action === 'resume') {
        if (elim.gagnant) return;
        elim.locked = false;
        elim.eliminationEnCours = false;
        elim.openEndsAt = Date.now() + (elim.tempsOuverture * 1000);
        elim.nextElimination = null;
        if (elim.timer) clearTimeout(elim.timer);
        elim.timer = setTimeout(() => {
          if (elim && !elim.gagnant) {
            elim.locked = true;
            elim.eliminationEnCours = true;
            elim.openEndsAt = null;
            elim.nextElimination = null;
            io.to(`streamer:${pseudoNettoye}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudoNettoye));
            processBoucleKill(pseudoNettoye, data);
          }
        }, elim.tempsOuverture * 1000);
      } else if (action === 'reset') {
        if (elim.timer) clearTimeout(elim.timer);
        if (elim.openTimer) clearInterval(elim.openTimer);
        data.eliminationBoucle = null;
        io.to(`streamer:${pseudoNettoye}`).emit('updateEliminationBoucle', { actif: false });
        return;
      }

      io.to(`streamer:${pseudoNettoye}`).emit('updateEliminationBoucle', etatEliminationBoucle(pseudoNettoye));
    } catch {}
  });

  socket.on('configurerRoue', (payload = {}) => {
    try {
      const { pseudo, mode, cout, giftImage, giftName, options } = payload;
      const user = socket.request.session?.user;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(user, pseudoNettoye)) return;
      
      const data = connexionsActives[pseudoNettoye];
      if (data) {
        data.roue.mode = mode || 'gifts';
        data.roue.cout = positiveInteger(cout, 1);
        data.roue.giftImage = safeText(giftImage, '');
        data.roue.giftName = safeText(giftName, '');
        
        if (Array.isArray(options)) {
          data.roue.options = options.map(opt => ({
            name: safeText(opt.name).slice(0, 80),
            prob: positiveInteger(opt.prob, 10)
          })).filter(o => o.name !== '');
        }
      }
    } catch {}
  });

  socket.on('forcerTournerRoue', (payload = {}) => {
    try {
      const { pseudo } = payload;
      const user = socket.request.session?.user;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(user, pseudoNettoye)) return;
      const data = connexionsActives[pseudoNettoye];
      if (data && data.roue && Array.isArray(data.roue.options) && data.roue.options.length > 0) {
        const optionGagnee = tirerRecompenseRoue(data.roue.options);
        const optionsPourOverlay = data.roue.options.map(o => o.name);
        io.to(`streamer:${pseudoNettoye}`).emit('tournerRoue', { gagnant: "Test Admin", resultat: optionGagnee, allOptions: optionsPourOverlay });
      }
    } catch {}
  });

  socket.on('demarrerEnchere', (payload = {}) => {
    try {
      const { pseudo, dureeSecondes, snipeSecondes, miseMinimale } = payload;
      const utilisateurConnecte = socket.request.session?.user;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(utilisateurConnecte, pseudoNettoye)) return;

      const duree = strictInteger(dureeSecondes, { min: 5, max: 86400 });
      const snipe = strictInteger(snipeSecondes, { min: 1, max: 3600 });
      const min = strictInteger(miseMinimale, { min: 0, max: 1000000 });

      if (connexionsActives[pseudoNettoye]) demarrerEnchere(pseudoNettoye, duree, snipe, min);
    } catch {}
  });

  socket.on('definirObjectif', (payload = {}) => {
    try {
      const { pseudo, cible, metrique, label } = payload;
      const utilisateurConnecte = socket.request.session?.user;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(utilisateurConnecte, pseudoNettoye)) return;
      const data = connexionsActives[pseudoNettoye];
      if (!data) return;

      const cibleNombre = strictInteger(cible, { min: 1, max: 10000000 });

      data.objectif = {
        cible: cibleNombre,
        metrique: metrique === 'likes' ? 'likes' : 'diamants',
        label: safeText(label, 'Objectif du live').slice(0, 60)
      };
      io.to(`streamer:${pseudoNettoye}`).emit('updateObjectif', etatObjectif(pseudoNettoye));
    } catch {}
  });

  socket.on('configurerCoffre', (payload = {}) => {
    try {
      const { pseudo, secret, recompense } = payload;
      const utilisateurConnecte = socket.request.session?.user;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(utilisateurConnecte, pseudoNettoye)) return;
      const data = connexionsActives[pseudoNettoye];
      if (!data) return;

      const cleanSecret = safeText(secret);
      if (!cleanSecret || cleanSecret.length > 30) return;

      data.coffre = {
        actif: true,
        secret: cleanSecret,
        devoiles: new Array(cleanSecret.length).fill(false),
        recompense: safeText(recompense, '').slice(0, 50),
        gagnant: null,
        dernierMessageGagnant: ''
      };
      io.to(`streamer:${pseudoNettoye}`).emit('updateCoffre', etatCoffrePublic(pseudoNettoye));
    } catch {}
  });

  socket.on('devoilerCharHasard', (payload = {}) => {
    try {
      const { pseudo } = payload;
      const utilisateurConnecte = socket.request.session?.user;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(utilisateurConnecte, pseudoNettoye)) return;
      const coffre = connexionsActives[pseudoNettoye]?.coffre;
      if (!coffre || !coffre.actif) return;

      const indicesNonDevoiles = coffre.devoiles.map((dev, idx) => dev ? -1 : idx).filter(idx => idx !== -1);
      if (indicesNonDevoiles.length > 0) {
        const idxChoisi = indicesNonDevoiles[Math.floor(Math.random() * indicesNonDevoiles.length)];
        coffre.devoiles[idxChoisi] = true;
        io.to(`streamer:${pseudoNettoye}`).emit('updateCoffre', etatCoffrePublic(pseudoNettoye));
      }
    } catch {}
  });

  socket.on('devoilerCharIndex', (payload = {}) => {
    try {
      const { pseudo, index } = payload;
      const utilisateurConnecte = socket.request.session?.user;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(utilisateurConnecte, pseudoNettoye)) return;
      const coffre = connexionsActives[pseudoNettoye]?.coffre;
      if (!coffre || !coffre.actif) return;

      const idxArr = strictInteger(index, { min: 1, max: 100 }) - 1;
      if (idxArr >= 0 && idxArr < coffre.devoiles.length) {
        coffre.devoiles[idxArr] = true;
        io.to(`streamer:${pseudoNettoye}`).emit('updateCoffre', etatCoffrePublic(pseudoNettoye));
      }
    } catch {}
  });
});

server.listen(PORT, () => console.log(`🚀 TokOverlay démarré sur le port ${PORT}`));