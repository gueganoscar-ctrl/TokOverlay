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

async function incrementerVouchGlobal() {
  vouchesGlobalCount += 1;
  if (db) await db.collection('compteurs').updateOne({ _id: 'vouches' }, { $inc: { total: 1 } }, { upsert: true }).catch(() => {});
  io.emit('updateVouchGlobal', { vouches: vouchesGlobalCount });
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

app.post('/api/forgot-password', async (req, res) => {
  let { email } = req.body;
  try {
    if (!db) return res.status(500).json({ error: "Base de données indisponible." });
    email = safeText(email).toLowerCase();
    const user = await db.collection('users').findOne({ email });
    if (!user) return res.json({ success: true, message: "Si cet e-mail existe, un lien a été envoyé." });
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = Date.now() + 15 * 60 * 1000;
    await db.collection('users').updateOne({ email }, { $set: { resetToken, resetExpires } });
    const resetLink = `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}&email=${encodeURIComponent(email)}`;
    const { error } = await resend.emails.send({
      from: 'TokOverlay <onboarding@resend.dev>', to: [email], subject: 'Réinitialisation de votre mot de passe - TokOverlay',
      html: `<div style="font-family: Arial; padding: 20px;"><h2>Réinitialisation</h2><a href="${resetLink}">Réinitialiser mon mot de passe</a></div>`
    });
    if (error) return res.status(500).json({ error: "Erreur lors de l'envoi de l'e-mail." });
    res.json({ success: true, message: "E-mail de réinitialisation envoyé avec succès !" });
  } catch (err) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.post('/api/reset-password', async (req, res) => {
  let { email, token, newPassword } = req.body;
  try {
    email = safeText(email).toLowerCase();
    const cleanToken = safeText(token);
    if (!email || !cleanToken || !newPassword || newPassword.length < 6) return res.status(400).json({ error: "Données invalides." });
    const user = await db.collection('users').findOne({ email, resetToken: cleanToken, resetExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ error: "Lien de réinitialisation invalide ou expiré." });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection('users').updateOne({ email }, { $set: { password: hashedPassword }, $unset: { resetToken: "", resetExpires: "" } });
    res.json({ success: true, message: "Mot de passe mis à jour avec succès !" });
  } catch (err) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.post('/api/contact', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Vous devez être connecté." });
  const { type, message } = req.body;
  if (!message || message.trim() === '') return res.status(400).json({ error: "Message vide." });
  try {
    await resend.emails.send({
      from: 'TokOverlay <onboarding@resend.dev>', to: ['gueganoscar@gmail.com'],
      subject: `[TokOverlay] ${type} de @${req.session.user.pseudo}`,
      html: `<div style="font-family: Arial; padding: 20px;"><h2>Retour (${type})</h2><p>${message}</p></div>`
    });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Erreur d'envoi." }); }
});

app.get('/api/me', async (req, res) => {
  if (!req.session.user || !db) return res.status(401).json({ error: 'Non connecté' });
  const userDb = await db.collection('users').findOne({ email: req.session.user.email });
  if (!userDb) return res.status(401).json({ error: 'Utilisateur introuvable' });
  res.json({ id: userDb._id, pseudo: userDb.pseudo, email: userDb.email, role: userDb.role || 'streamer', overlayToken: signOverlayToken(userDb.pseudo) });
});

app.get('/api/gifts/:username', async (req, res) => {
  try {
    const pseudo = normalizePseudo(req.params.username);
    if (!req.session.user || !canManage(req.session.user, pseudo)) return res.status(401).json({ error: "Non autorisé" });
    const data = connexionsActives[pseudo];
    if (!data || !data.connection) return res.json([]);

    const gifts = await data.connection.getAvailableGifts();
    const cleanGifts = gifts.map(g => ({
        id: g.id, name: g.name, diamond_count: g.diamond_count, image: g.image?.url_list[0] || ''
    })).filter(g => g.image && g.diamond_count > 0);
    res.json(cleanGifts);
  } catch (err) { res.json([]); }
});

app.post('/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('__Host-tokoverlay'); res.json({ success: true }); }); });
app.get('/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('__Host-tokoverlay'); res.redirect('/'); }); });

app.get('/overlay/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'overlay.html')));
app.get('/overlay-vip/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vip-overlay.html')));
app.get('/elimination/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'elimination.html')));
app.get('/layout/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'layout.html')));

app.get('/api/test-vip/:username', (req, res) => {
  const pseudo = req.params.username;
  io.to(`streamer:${pseudo}`).emit('vip_alert', { username: "Testeur_VIP", giftName: "galaxy" });
  setTimeout(() => { io.to(`streamer:${pseudo}`).emit('roblox_pseudo', { username: "Testeur_VIP", message: "MonPseudoRoblox123" }); }, 1000);
  res.send(`Test de simulation VIP lancé pour @${pseudo} !`);
});

app.get('/encheres/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  try {
    const targetPseudo = normalizePseudo(req.params.username);
    if (req.session.user.pseudo !== targetPseudo) return res.redirect('/encheres/' + encodeURIComponent(req.session.user.pseudo));
  } catch { return res.redirect('/'); }
  res.sendFile(path.join(__dirname, 'public', 'controle-encheres.html'));
});

app.get('/statistiques/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  try {
    const targetPseudo = normalizePseudo(req.params.username);
    if (req.session.user.pseudo !== targetPseudo) return res.redirect('/statistiques/' + encodeURIComponent(req.session.user.pseudo));
  } catch { return res.redirect('/'); }
  res.sendFile(path.join(__dirname, 'public', 'statistiques.html'));
});

app.get('/admin-live/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  if (isAdmin(req.session.user)) return res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
  try {
    const targetPseudo = normalizePseudo(req.params.username);
    if (req.session.user.pseudo !== targetPseudo) return res.redirect('/admin-live/' + encodeURIComponent(req.session.user.pseudo));
  } catch { return res.redirect('/'); }
  res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
});

app.get('/api/admin/stats-globales', async (req, res) => {
  if (!req.session.user || !isAdmin(req.session.user)) return res.status(403).json({ error: "Accès refusé." });
  if (!db) return res.json({ streamers: [] });
  try {
    const streamers = await db.collection('users').find({}).project({ password: 0, apiKey: 0 }).toArray();
    const resultat = streamers.map(s => {
      const liveData = connexionsActives[s.pseudo];
      const isOnline = liveData && liveData.connection && liveData.connection.isConnected;
      const diamantsSessionActuelle = liveData ? Object.values(liveData.gifters).reduce((sum, g) => sum + g.coins, 0) : 0;
      return { pseudo: s.pseudo, email: s.email, totalDiamantsGlobal: s.totalDiamantsGlobal || 0, diamantsSessionActuelle, enLigne: !!isOnline };
    });
    res.json({ streamers: resultat });
  } catch (err) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.get('/vip-room', (req, res) => {
  if (!req.session.user || !isAdmin(req.session.user)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'vip.html'));
});

app.get('/api/live-status/:pseudo', async (req, res) => {
  try {
    const pseudo = normalizePseudo(req.params.pseudo);
    if (!req.session.user || !canManage(req.session.user, pseudo)) return res.status(403).json({ error: "Accès refusé." });
    const data = connexionsActives[pseudo];
    const isOnline = data && data.connection && data.connection.isConnected;
    res.json({ online: !!isOnline });
  } catch { res.status(400).json({ error: "Requête invalide." }); }
});

const connexionsActives = {};
const ELIGIBLE_GIFTS = ["whale diving", "corgi", "swan", "galaxy", "donut"];
const waitingUsers = new Map();

function arreterEcouteLive(pseudo, data, reason) {
  if (!data || data.closed) return;
  data.closed = true;
  if (data.refreshTimer) { clearInterval(data.refreshTimer); data.refreshTimer = null; }
  if (data.enchere?.minuteur) { clearTimeout(data.enchere.minuteur); data.enchere.minuteur = null; }
  if (data.elimination?.timer) { clearInterval(data.elimination.timer); data.elimination.timer = null; }
  try {
    if (data.connection) { data.connection.removeAllListeners(); if (typeof data.connection.disconnect === 'function') data.connection.disconnect(); }
  } catch {}
  if (connexionsActives[pseudo] === data) delete connexionsActives[pseudo];
  io.to(`streamer:${pseudo}`).emit('liveArrete', { reason });
}

function demarrerEcouteLive(pseudo, apiKey) {
  if (connexionsActives[pseudo]) return;
  const connection = new TikTokLiveConnection(pseudo, { signApiKey: apiKey });
  const data = {
    connection, closed: false, refreshTimer: null,
    likers: Object.create(null), gifters: Object.create(null), 
    enchere: null, bestGift: null, debutLive: new Date(), 
    derniereGagnantId: null, vouchFait: false, objectif: null,
    roue: { active: false, options: ["Gage 1"], montantMin: 10 },
    coffre: { actif: false, secret: '', devoiles: [], recompense: '', gagnant: null, dernierMessageGagnant: '' },
    elimination: { actif: false, cout: 1, intervalle: 5, giftImage: 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/5ea6ceee6885dfb90c910fae1ba1c1bb~tplv-obj.png', locked: false, eliminationEnCours: false, totalCoins: 0, places: [], timer: null, nextElimination: null, gagnant: null, messageGagnant: '' },
    pendingUpdates: { likers: false, gifters: false, stats: false, objectif: false }
  };
  connexionsActives[pseudo] = data;

  data.refreshTimer = setInterval(() => {
    if (connexionsActives[pseudo] !== data || data.closed) { clearInterval(data.refreshTimer); return; }
    const p = data.pendingUpdates;
    if (p.likers) { io.to(`streamer:${pseudo}`).emit('updateTopLikers', Object.values(data.likers).sort((a, b) => b.likes - a.likes).slice(0, 3)); p.likers = false; }
    if (p.gifters) { io.to(`streamer:${pseudo}`).emit('updateTopGifters', Object.values(data.gifters).sort((a, b) => b.coins - a.coins).slice(0, 3)); p.gifters = false; }
  }, 2000); 

  connection.connect().catch(() => {
    io.to(`streamer:${pseudo}`).emit('erreurConnexion', "Impossible de se connecter au live.");
    arreterEcouteLive(pseudo, data, 'connect_error');
  });

  connection.once('error', () => arreterEcouteLive(pseudo, data, 'error'));

  connection.on('like', (d = {}) => {
    if (data.closed) return;
    const user = d.user || {};
    const id = resolveUserId(d, user);
    if (!data.likers[id]) data.likers[id] = { nickname: safeText(user.nickname, 'Anonyme'), profilePictureUrl: avatarFor(user, safeText(user.nickname)), likes: 0 };
    data.likers[id].likes += positiveInteger(d.count, 1);
    data.pendingUpdates.likers = true;
  });

  connection.on('gift', (d = {}) => {
    if (data.closed) return;
    if (d.gift?.type === 1 && !d.repeatEnd) return;
    const user = d.user || {};
    const id = resolveUserId(d, user);
    const nickname = safeText(user.nickname || d.nickname, 'Anonyme');
    const totalPieces = positiveInteger(d.gift?.diamondCount, 0) * positiveInteger(d.repeatCount, 1);
    if (totalPieces === 0) return;
    
    const avatar = avatarFor(user, nickname);
    if (!data.gifters[id]) data.gifters[id] = { nickname, profilePictureUrl: avatar, coins: 0 };
    data.gifters[id].coins += totalPieces;
    
    if (db) db.collection('users').updateOne({ pseudo: pseudo }, { $inc: { totalDiamantsGlobal: totalPieces } }, { upsert: true }).catch(() => {});

    const elim = data.elimination;
    if (elim && elim.actif && !elim.locked && !elim.gagnant) {
      const nbPlaces = Math.floor(totalPieces / elim.cout);
      if (nbPlaces > 0) {
        for (let i = 0; i < nbPlaces; i++) elim.places.push({ id, nickname, avatar, eliminated: false });
        elim.totalCoins += totalPieces;
        io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
      }
    }
    data.pendingUpdates.gifters = true;
  });

  connection.on('chat', (d = {}) => {
    if (data.closed) return;
    const user = d.user || {};
    const id = resolveUserId(d, user);
    const message = safeText(d.comment || d.text || d.message || d.msg || d.content, '');
    const nickname = safeText(d.nickname || user.nickname, 'Anonyme');
    const avatar = avatarFor(user, nickname);

    io.to(`streamer:${pseudo}`).emit('chatEnDirect', { nickname, avatar, message });

    if (data.elimination && data.elimination.gagnant && id === data.elimination.gagnant.id) {
      data.elimination.messageGagnant = message;
      io.to(`streamer:${pseudo}`).emit('updateElimination', etatElimination(pseudo));
    }

    if (data.coffre && data.coffre.actif && !data.coffre.gagnant) {
      const msgNettoye = message.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      const secretNettoye = data.coffre.secret.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      if (msgNettoye !== "" && msgNettoye === secretNettoye) {
        data.coffre.gagnant = { id, nickname, avatar };
        data.coffre.actif = false;
      }
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
    gagnant: elim.gagnant, messageGagnant: elim.messageGagnant
  };
}

io.on('connection', socket => {
  socket.on('disconnect', () => {});

  socket.on('rejoindre', async (payload = {}, ack = () => {}) => {
    try {
      const { pseudo, token } = payload;
      let pseudoNettoye;
      try { pseudoNettoye = normalizePseudo(pseudo); } catch { return ack({ ok: false, error: 'Pseudo invalide.' }); }

      const utilisateurConnecte = socket.request.session?.user;
      const allowed = canManage(utilisateurConnecte, pseudoNettoye) || verifyOverlayToken(token, pseudoNettoye);
      if (!allowed) return ack({ ok: false, error: 'Authentification invalide.' });

      if (!db) return ack({ ok: false, error: 'Base de données indisponible.' });
      const utilisateur = await db.collection('users').findOne({ pseudo: pseudoNettoye });
      if (!utilisateur) return ack({ ok: false, error: 'Streamer inconnu.' });

      socket.join(`streamer:${pseudoNettoye}`);
      demarrerEcouteLive(pseudoNettoye, utilisateur.apiKey);
      ack({ ok: true });
      
      const data = connexionsActives[pseudoNettoye];
      if (data && data.elimination) socket.emit('updateElimination', etatElimination(pseudoNettoye));
    } catch { ack({ ok: false, error: 'Requête invalide.' }); }
  });

  socket.on('configurerElimination', (payload = {}) => {
    try {
      const { pseudo, cout, intervalle, giftImage } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;
      
      const data = connexionsActives[pseudoNettoye];
      if (data) {
        if (data.elimination && data.elimination.timer) clearInterval(data.elimination.timer);
        
        data.elimination = {
          actif: true, cout: positiveInteger(cout, 1), intervalle: positiveInteger(intervalle, 5),
          giftImage: safeText(giftImage, 'https://p16-webcast.tiktokcdn.com/img/maliva/webcast-va/5ea6ceee6885dfb90c910fae1ba1c1bb~tplv-obj.png'),
          locked: false, eliminationEnCours: false, totalCoins: 0, places: [], timer: null, nextElimination: null, gagnant: null, messageGagnant: ''
        };
        io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
      }
    } catch {}
  });

  socket.on('updateEliminationSettings', (payload = {}) => {
    try {
      const { pseudo, cout, intervalle, giftImage } = payload;
      const pseudoNettoye = normalizePseudo(pseudo);
      if (!canManage(socket.request.session?.user, pseudoNettoye)) return;

      const data = connexionsActives[pseudoNettoye];
      const elim = data?.elimination;
      if (elim && elim.actif && !elim.gagnant) {
        if (cout) elim.cout = positiveInteger(cout, 1);
        if (intervalle) elim.intervalle = positiveInteger(intervalle, 5);
        if (giftImage) elim.giftImage = giftImage;

        if (elim.eliminationEnCours && elim.timer) {
          clearInterval(elim.timer);
          elim.nextElimination = Date.now() + (elim.intervalle * 1000);
          elim.timer = setInterval(() => { processEliminationKill(pseudoNettoye, data); }, elim.intervalle * 1000);
        }
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
      } else if (action === 'start_kill') {
        if(elim.gagnant) return; // Ne pas relancer si déjà gagné
        elim.locked = true; elim.eliminationEnCours = true;
        if (elim.timer) clearInterval(elim.timer);
        
        elim.nextElimination = Date.now() + (elim.intervalle * 1000);
        elim.timer = setInterval(() => { processEliminationKill(pseudoNettoye, data); }, elim.intervalle * 1000);
      } else if (action === 'stop_kill') {
        elim.eliminationEnCours = false;
        if (elim.timer) { clearInterval(elim.timer); elim.timer = null; }
        elim.nextElimination = null;
      } else if (action === 'reset') {
        if (elim.timer) { clearInterval(elim.timer); elim.timer = null; }
        elim.actif = false; elim.places = []; elim.totalCoins = 0; elim.nextElimination = null; elim.gagnant = null; elim.messageGagnant = '';
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
      elim.nextElimination = Date.now() + (elim.intervalle * 1000);

      const vivantsApres = elim.places.filter(p => !p.eliminated);
      const uniqueApresIds = [...new Set(vivantsApres.map(p => p.id))];

      if (uniqueApresIds.length === 1 && elim.places.length > 1) {
        clearInterval(elim.timer); elim.timer = null; elim.eliminationEnCours = false; elim.nextElimination = null;
        elim.gagnant = vivantsApres[0];
        const userGlobal = data.gifters[elim.gagnant.id];
        elim.gagnant.coins = userGlobal ? userGlobal.coins : 0;
      }
    } else {
      clearInterval(elim.timer); elim.timer = null; elim.eliminationEnCours = false; elim.nextElimination = null;
      if(uniqueVivantsIds.length === 1 && elim.places.length > 1) {
        elim.gagnant = vivants[0];
        const userGlobal = data.gifters[elim.gagnant.id];
        elim.gagnant.coins = userGlobal ? userGlobal.coins : 0;
      }
    }
    io.to(`streamer:${pseudoNettoye}`).emit('updateElimination', etatElimination(pseudoNettoye));
  }
});

server.listen(PORT, () => console.log(`🚀 TokOverlay démarré sur le port ${PORT}`));