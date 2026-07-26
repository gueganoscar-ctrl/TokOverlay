const express = require('express');
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

if (!process.env.SESSION_SECRET || !process.env.MONGO_URI) throw new Error("FATAL ERROR: SESSION_SECRET et MONGO_URI sont obligatoires !");
const OVERLAY_TOKEN_SECRET = process.env.OVERLAY_TOKEN_SECRET || crypto.randomBytes(32).toString('hex');

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/img', express.static(path.join(__dirname, 'img')));

const sessionMiddleware = session({
  name: '__Host-tokoverlay', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, rolling: true,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI, ttl: 60 * 60 * 24 * 7 }),
  cookie: { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/', maxAge: 1000 * 60 * 60 * 24 * 7 }
});
app.use(sessionMiddleware);
io.use((socket, next) => { sessionMiddleware(socket.request, {}, next); });

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
  } catch (err) { console.error("❌ Erreur de connexion MongoDB :", err); }
}
connectMongo();

function normalizePseudo(value) {
  if (typeof value !== 'string') throw new Error('Pseudo invalide.');
  const pseudo = value.replace(/^@/, '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{2,24}$/.test(pseudo)) throw new Error('Pseudo invalide.');
  return pseudo;
}

function safeText(value, fallback = '') { return typeof value === 'string' ? value.trim() : fallback; }
function strictInteger(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new Error('Nombre invalide.');
  return number;
}
function positiveInteger(value, fallback = 1) { const num = Number(value); return Number.isInteger(num) && num > 0 ? num : fallback; }
function resolveUserId(d = {}, user = {}) { return safeText(user.displayId || d.uniqueId || user.userId || d.userId, `unknown:${crypto.randomUUID()}`); }
function avatarFor(user = {}, nickname = 'Anonyme') {
  const avatarList = user?.avatarThumb?.urlList;
  if (Array.isArray(avatarList) && avatarList.length > 0 && typeof avatarList[0] === 'string') return avatarList[0];
  return `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
}
function isAdmin(user) { return user && user.role === 'admin'; }
function canManage(user, pseudo) { return Boolean(user && (isAdmin(user) || user.pseudo === pseudo)); }

function signOverlayToken(pseudo) {
  const expiresAt = Date.now() + (1000 * 60 * 60 * 24 * 7);
  const payload = Buffer.from(JSON.stringify({ pseudo, expiresAt })).toString('base64url');
  const signature = crypto.createHmac('sha256', OVERLAY_TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifyOverlayToken(token, expectedPseudo) {
  if (typeof token !== 'string') return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;
  const expected = crypto.createHmac('sha256', OVERLAY_TOKEN_SECRET).update(payload).digest('base64url');
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.pseudo === expectedPseudo && data.expiresAt > Date.now();
  } catch { return false; }
}

app.post('/register', async (req, res) => {
  let { pseudo, apiKey, email, password } = req.body;
  try {
    email = safeText(email).toLowerCase();
    let pseudoNettoye;
    try { pseudoNettoye = normalizePseudo(pseudo); } catch { return res.redirect('/?error=invalid_pseudo'); }
    if (!safeText(apiKey) || !email || !password) return res.redirect('/?error=missing_fields');

    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne({ $or: [{ email }, { pseudo: pseudoNettoye }] });
    if (existingUser) return res.redirect('/?error=pseudo_exists');

    const passwordHache = await bcrypt.hash(password, 10);
    const newUser = { pseudo: pseudoNettoye, apiKey: safeText(apiKey), email, password: passwordHache, role: 'streamer', totalDiamantsGlobal: 0 };
    await usersCollection.insertOne(newUser);
    
    await new Promise((resolve, reject) => req.session.regenerate((err) => err ? reject(err) : resolve()));
    req.session.user = { id: newUser._id, pseudo: newUser.pseudo, email: newUser.email, role: newUser.role };
    await new Promise((resolve, reject) => req.session.save((err) => err ? reject(err) : resolve()));
    res.redirect('/choix.html');
  } catch (err) { res.status(500).send("Erreur serveur."); }
});

app.post('/login', async (req, res) => {
  let { pseudo, password } = req.body;
  try {
    let pseudoNettoye;
    try { pseudoNettoye = normalizePseudo(pseudo); } catch { return res.redirect('/?error=wrong_credentials'); }
    const user = await db.collection('users').findOne({ pseudo: pseudoNettoye });
    if (user && typeof password === 'string' && await bcrypt.compare(password, user.password)) {
      await new Promise((resolve, reject) => req.session.regenerate((err) => err ? reject(err) : resolve()));
      req.session.user = { id: user._id, pseudo: user.pseudo, email: user.email, role: user.role || 'streamer' };
      await new Promise((resolve, reject) => req.session.save((err) => err ? reject(err) : resolve()));
      return res.redirect('/choix.html');
    }
    res.redirect('/?error=wrong_credentials');
  } catch (err) { res.status(500).send("Erreur serveur."); }
});

app.get('/api/me', async (req, res) => {
  if (!req.session.user || !db) return res.status(401).json({ error: 'Non connecté' });
  const userDb = await db.collection('users').findOne({ email: req.session.user.email });
  if (!userDb) return res.status(401).json({ error: 'Utilisateur introuvable' });
  res.json({ id: userDb._id, pseudo: userDb.pseudo, email: userDb.email, role: userDb.role || 'streamer', overlayToken: signOverlayToken(userDb.pseudo) });
});

app.get('/api/gifts/:username', async (req, res) => {
  const catalogGifts = [
    { name: 'Rose', diamond_count: 1, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/5ea6ceee6885dfb90c910fae1ba1c1bb~tplv-obj.png' },
    { name: 'TikTok', diamond_count: 1, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/a7aa3ba2393279148d2d667c2d1b82e4~tplv-obj.png' },
    { name: 'Finger Heart', diamond_count: 5, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/7065969116668791557~tplv-obj.png' },
    { name: 'Mini Speaker', diamond_count: 1, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/8e42f9e4226d9c63d58d343411b5e58c~tplv-obj.png' },
    { name: 'Ice Cream', diamond_count: 1, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/eb9b6348efd46a895b6c935b6727c943~tplv-obj.png' },
    { name: 'Perfume', diamond_count: 20, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/6696efb2d29486cd5d9a941f12ff1dc5~tplv-obj.png' },
    { name: 'Doughnut', diamond_count: 30, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/6911928092264909574~tplv-obj.png' },
    { name: 'Cap', diamond_count: 99, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/38c3e60124ca255554f6c449174092b3~tplv-obj.png' },
    { name: 'Confetti', diamond_count: 100, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/c3ec78e4726cdb8ff23467f5dfcd3613~tplv-obj.png' },
    { name: 'Love Letter', diamond_count: 100, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/a0c44a2c0709f18a5996fec203bf182d~tplv-obj.png' },
    { name: 'Tea Time', diamond_count: 50, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/7011287955523179526~tplv-obj.png' },
    { name: 'Glove', diamond_count: 150, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/7011288214324203782~tplv-obj.png' },
    { name: 'Corgi', diamond_count: 299, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/1a5e12ecaf4f3dce39c4d93ee8a49c25~tplv-obj.png' },
    { name: 'Swan', diamond_count: 699, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/b0870932822a10cb55ed703c734898fc~tplv-obj.png' },
    { name: 'Yacht', diamond_count: 9999, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/148386a3bcf447f7d1428f5223078a63~tplv-obj.png' },
    { name: 'Galaxy', diamond_count: 1000, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/8e6c70281b37803db02ce1e3eb8c2786~tplv-obj.png' },
    { name: 'Interstellar', diamond_count: 10000, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/8e6c70281b37803db02ce1e3eb8c2786~tplv-obj.png' },
    { name: 'Falcon', diamond_count: 10999, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/6201a073f00155b958c2cb41257ab6b8~tplv-obj.png' },
    { name: 'Phoenix', diamond_count: 25999, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/7011295982821143814~tplv-obj.png' },
    { name: 'Lion', diamond_count: 29999, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/ada635cc98d023f06dd95c02bbf9dd9d~tplv-obj.png' },
    { name: 'Dragon Flame', diamond_count: 26999, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/7027581223963428357~tplv-obj.png' },
    { name: 'Zeus', diamond_count: 34999, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/7106093847250635525~tplv-obj.png' },
    { name: 'Universe', diamond_count: 34999, image: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/289fa3ec677e1bf3b4629471d248b1aa~tplv-obj.png' }
  ];
  res.json(catalogGifts);
});

app.post('/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('__Host-tokoverlay'); res.json({ success: true }); }); });
app.get('/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('__Host-tokoverlay'); res.redirect('/'); }); });

app.get('/overlay/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'overlay.html')));
app.get('/overlay-vip/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vip-overlay.html')));
app.get('/elimination/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'elimination.html')));
app.get('/layout/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'layout.html')));

app.get('/encheres/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'controle-encheres.html'));
});
app.get('/statistiques/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'statistiques.html'));
});
app.get('/admin-live/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
});
app.get('/vip-room', (req, res) => {
  if (!req.session.user || !isAdmin(req.session.user)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'vip.html'));
});
app.get('/api/live-status/:pseudo', async (req, res) => {
  try {
    const pseudo = normalizePseudo(req.params.pseudo);
    const data = connexionsActives[pseudo];
    res.json({ online: !!(data && data.connection && data.connection.isConnected) });
  } catch { res.status(400).json({ error: "Invalide." }); }
});

const connexionsActives = {};

function arreterEcouteLive(pseudo, data, reason) {
  if (!data || data.closed) return;
  data.closed = true;
  if (data.elimination?.timer) clearTimeout(data.elimination.timer);
  if (data.elimination?.openTimer) clearTimeout(data.elimination.openTimer);
  try { if (data.connection) data.connection.disconnect(); } catch {}
  delete connexionsActives[pseudo];
}

function demarrerEcouteLive(pseudo, apiKey) {
  if (connexionsActives[pseudo]) return;
  const connection = new TikTokLiveConnection(pseudo, { signApiKey: apiKey });
  const data = {
    connection, closed: false,
    gifters: Object.create(null),
    elimination: { 
      actif: false, cout: 1, intervalle: 5, tempsOuverture: 60,
      giftImage: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/5ea6ceee6885dfb90c910fae1ba1c1bb~tplv-obj.png', 
      locked: false, eliminationEnCours: false, totalCoins: 0, places: [], 
      timer: null, openTimer: null, nextElimination: null, openEndsAt: null, gagnant: null, messageGagnant: '' 
    }
  };
  connexionsActives[pseudo] = data;

  connection.connect().catch(() => arreterEcouteLive(pseudo, data, 'connect_error'));

  connection.on('gift', (d = {}) => {
    if (data.closed || (d.gift?.type === 1 && !d.repeatEnd)) return;
    const user = d.user || {};
    const id = resolveUserId(d, user);
    const nickname = safeText(user.nickname || d.nickname, 'Anonyme');
    const totalPieces = positiveInteger(d.gift?.diamondCount, 0) * positiveInteger(d.repeatCount, 1);
    if (totalPieces === 0) return;
    
    const avatar = avatarFor(user, nickname);
    if (!data.gifters[id]) data.gifters[id] = { nickname, profilePictureUrl: avatar, coins: 0 };
    data.gifters[id].coins += totalPieces;

    const elim = data.elimination;
    if (elim && elim.actif && !elim.locked && !elim.gagnant) {
      const nbPlaces = Math.floor(totalPieces / elim.cout);
      if (nbPlaces > 0) {
        for (let i = 0; i < nbPlaces; i++) elim.places.push({ id, nickname, avatar, eliminated: false });
        elim.totalCoins += totalPieces;
        io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
      }
    }
  });

  connection.on('chat', (d = {}) => {
    if (data.closed) return;
    const user = d.user || {};
    const id = resolveUserId(d, user);
    const message = safeText(d.comment || d.text || d.message || d.msg || d.content, '');
    if (data.elimination && data.elimination.gagnant && id === data.elimination.gagnant.id) {
      data.elimination.messageGagnant = message;
      io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
    }
  });

  connection.once('disconnect', () => arreterEcouteLive(pseudo, data, 'disconnect'));
  connection.once('streamEnd', () => arreterEcouteLive(pseudo, data, 'streamEnd'));
}

function etatElimination(pseudo) {
  const elim = connexionsActives[pseudo]?.elimination;
  if (!elim) return null;
  return {
    actif: elim.actif, cout: elim.cout, locked: elim.locked,
    eliminationEnCours: elim.eliminationEnCours, totalCoins: elim.totalCoins,
    places: elim.places, giftImage: elim.giftImage, nextElimination: elim.nextElimination,
    openEndsAt: elim.openEndsAt, gagnant: elim.gagnant, messageGagnant: elim.messageGagnant
  };
}

io.on('connection', socket => {
  socket.on('rejoindre', async (payload = {}) => {
    try {
      const { pseudo, token } = payload;
      let pseudoNettoye = normalizePseudo(pseudo);
      const utilisateurConnecte = socket.request.session?.user;
      if (!canManage(utilisateurConnecte, pseudoNettoye) && !verifyOverlayToken(token, pseudoNettoye)) return;

      const utilisateur = await db.collection('users').findOne({ pseudo: pseudoNettoye });
      if (!utilisateur) return;

      socket.join(`streamer:${pseudoNettoye}`);
      demarrerEcouteLive(pseudoNettoye, utilisateur.apiKey);
      
      const data = connexionsActives[pseudoNettoye];
      if (data && data.elimination) socket.emit('updateElimination', etatElimination(pseudoNettoye));
    } catch {}
  });

  socket.on('configurerElimination', (payload = {}) => {
    try {
      const { pseudo, cout, intervalle, tempsOuverture, giftImage } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;
      
      const data = connexionsActives[pseudoNettoye];
      if (data) {
        if (data.elimination?.timer) clearInterval(data.elimination.timer);
        if (data.elimination?.openTimer) clearTimeout(data.elimination.openTimer);
        
        const openTimeSec = positiveInteger(tempsOuverture, 30);

        data.elimination = {
          actif: true, cout: positiveInteger(cout, 1), intervalle: positiveInteger(intervalle, 5),
          tempsOuverture: openTimeSec,
          giftImage: safeText(giftImage, 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/5ea6ceee6885dfb90c910fae1ba1c1bb~tplv-obj.png'),
          locked: false, eliminationEnCours: false, totalCoins: 0, places: [], 
          timer: null, openTimer: null, nextElimination: null, 
          openEndsAt: Date.now() + (openTimeSec * 1000), gagnant: null, messageGagnant: ''
        };

        // Timer de fermeture des inscriptions
        data.elimination.openTimer = setTimeout(() => {
          if (data.elimination && !data.elimination.locked) {
            data.elimination.locked = true;
            data.elimination.openEndsAt = null;
            io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
          }
        }, openTimeSec * 1000);

        io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
      }
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
        elim.openEndsAt = null;
        if (elim.openTimer) clearTimeout(elim.openTimer);
      } else if (action === 'start_kill') {
        if (elim.gagnant) return;
        elim.locked = true; elim.openEndsAt = null; elim.eliminationEnCours = true;
        if (elim.openTimer) clearTimeout(elim.openTimer);
        if (elim.timer) clearInterval(elim.timer);
        
        elim.nextElimination = Date.now() + (elim.intervalle * 1000);
        elim.timer = setInterval(() => { processEliminationKill(pseudoNettoye, data); }, elim.intervalle * 1000);
      } else if (action === 'stop_kill') {
        elim.eliminationEnCours = false;
        if (elim.timer) { clearInterval(elim.timer); elim.timer = null; }
        elim.nextElimination = null;
      } else if (action === 'reset') {
        if (elim.timer) clearInterval(elim.timer);
        if (elim.openTimer) clearTimeout(elim.openTimer);
        elim.actif = false; elim.places = []; elim.totalCoins = 0; elim.nextElimination = null; elim.openEndsAt = null; elim.gagnant = null; elim.messageGagnant = '';
      }
      io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
    } catch {}
  });

  function processEliminationKill(pseudoNettoye, data) {
    const elim = data.elimination;
    const vivants = elim.places.filter(p => !p.eliminated);
    const uniqueVivantsIds = [...new Set(vivants.map(p => p.id))];

    if (uniqueVivantsIds.length > 1) {
      const indexMort = Math.floor(Math.random() * vivants.length);
      vivants[indexMort].eliminated = true;
      
      // On prépare le prochain tick en ajoutant l'intervalle après la fin de l'animation
      elim.nextElimination = Date.now() + (elim.intervalle * 1000) + 2000; 

      const vivantsApres = elim.places.filter(p => !p.eliminated);
      const uniqueApresIds = [...new Set(vivantsApres.map(p => p.id))];

      if (uniqueApresIds.length === 1 && elim.places.length > 1) {
        clearInterval(elim.timer); elim.timer = null; elim.eliminationEnCours = false; elim.nextElimination = null;
        elim.gagnant = vivantsApres[0];
        const userGlobal = data.gifters[elim.gagnant.id];
        elim.gagnant.coins = userGlobal ? userGlobal.coins : elim.totalCoins;
      }
    } else {
      clearInterval(elim.timer); elim.timer = null; elim.eliminationEnCours = false; elim.nextElimination = null;
      if (uniqueVivantsIds.length === 1 && elim.places.length > 1) {
        elim.gagnant = vivants[0];
        const userGlobal = data.gifters[elim.gagnant.id];
        elim.gagnant.coins = userGlobal ? userGlobal.coins : elim.totalCoins;
      }
    }
    io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
  }
});

server.listen(PORT, () => console.log(`🚀 TokOverlay démarré sur le port ${PORT}`));