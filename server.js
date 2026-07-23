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

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

const TikTokLiveConnection = TikTokModule.TikTokLiveConnection || TikTokModule.WebcastPushConnection;

if (!process.env.SESSION_SECRET || !process.env.MONGO_URI) {
  throw new Error("FATAL ERROR: SESSION_SECRET et MONGO_URI sont obligatoires !");
}

app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/img', express.static(path.join(__dirname, 'img')));

const OVERLAY_TOKEN_SECRET = process.env.OVERLAY_TOKEN_SECRET || crypto.randomBytes(32).toString('hex');

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
    secure: process.env.NODE_ENV === 'production',
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
  if (typeof value !== 'string') return '';
  return value.replace('@', '').trim().toLowerCase();
}

function safeText(value, fallback = '') {
  return typeof value === 'string' ? value.trim() : fallback;
}

function positiveInteger(value, fallback = 0) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? n : fallback;
}

function avatarFor(user = {}, nickname = 'Anonyme') {
  const avatarList = user?.avatarThumb?.urlList;
  if (Array.isArray(avatarList) && avatarList.length > 0 && typeof avatarList[0] === 'string') {
    return avatarList[0];
  }
  return `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
}

function isAdmin(user) {
  return user && user.role === 'admin';
}

function canManage(user, pseudo) {
  return Boolean(user && (isAdmin(user) || user.pseudo === pseudo));
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

// ----------------------------------------------------
// ROUTES D'AUTHENTIFICATION & PROFIL
// ----------------------------------------------------

app.post('/register', async (req, res) => {
  let { pseudo, apiKey, email, password } = req.body;
  try {
    if (!db) return res.status(500).send("Base de données en cours de connexion.");
    email = safeText(email).toLowerCase();
    const pseudoNettoye = normalizePseudo(pseudo);
    const cleanApiKey = safeText(apiKey);

    if (!pseudoNettoye || !cleanApiKey || !email || !password) {
      return res.redirect('/?error=missing_fields');
    }

    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne({
      $or: [{ email }, { pseudo: pseudoNettoye }]
    });

    if (existingUser) {
      if (existingUser.email === email) return res.redirect('/?error=email_exists');
      if (existingUser.pseudo === pseudoNettoye) return res.redirect('/?error=pseudo_exists');
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
    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ pseudo: normalizePseudo(pseudo) });
    if (user && typeof password === 'string' && await bcrypt.compare(password, user.password)) {
      
      await new Promise((resolve, reject) =>
        req.session.regenerate((error) => error ? reject(error) : resolve())
      );

      req.session.user = { id: user._id, pseudo: user.pseudo, email: user.email, role: user.role || 'streamer' };
      await new Promise((resolve, reject) => req.session.save((err) => err ? reject(err) : resolve()));

      return res.redirect('/choix.html');
    }
    res.redirect('/?error=wrong_credentials');
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

app.post('/api/update-profile', async (req, res) => {
  let { pseudo, apiKey } = req.body;
  if (!req.session.user || !db) return res.status(401).json({ error: "Non autorisé" });
  try {
    const nvPseudo = normalizePseudo(pseudo);
    const nvApiKey = safeText(apiKey);

    if (!nvPseudo || !nvApiKey) {
      return res.status(400).json({ error: "Champs invalides." });
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
      { $set: { pseudo: nvPseudo, apiKey: nvApiKey } }
    );
    
    req.session.user.pseudo = nvPseudo;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('__Host-tokoverlay');
    res.json({ success: true });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('__Host-tokoverlay');
    res.redirect('/');
  });
});

// ----------------------------------------------------
// ROUTES FRONT-END ET API
// ----------------------------------------------------

app.get('/overlay/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'overlay.html')));
app.get('/layout/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'layout.html')));

app.get('/encheres/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  const targetPseudo = normalizePseudo(req.params.username);
  if (req.session.user.pseudo !== targetPseudo) return res.redirect('/encheres/' + encodeURIComponent(req.session.user.pseudo));
  res.sendFile(path.join(__dirname, 'public', 'controle-encheres.html'));
});

app.get('/statistiques/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  const targetPseudo = normalizePseudo(req.params.username);
  if (req.session.user.pseudo !== targetPseudo) return res.redirect('/statistiques/' + encodeURIComponent(req.session.user.pseudo));
  res.sendFile(path.join(__dirname, 'public', 'statistiques.html'));
});

app.get('/admin-live/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  
  if (isAdmin(req.session.user)) {
    return res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
  }

  const targetPseudo = normalizePseudo(req.params.username);
  if (req.session.user.pseudo !== targetPseudo) {
    return res.redirect('/admin-live/' + encodeURIComponent(req.session.user.pseudo));
  }
  
  res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
});

// ----------------------------------------------------
// ROUTES VIP / SUPER ADMIN
// ----------------------------------------------------
app.get('/api/admin/stats-globales', async (req, res) => {
  if (!req.session.user || !isAdmin(req.session.user)) {
    return res.status(403).json({ error: "Accès refusé. Réservé à l'administrateur." });
  }
  if (!db) return res.json({ streamers: [] });

  try {
    const streamers = await db.collection('users').find({}).project({ password: 0, apiKey: 0 }).toArray();
    
    const resultat = streamers.map(s => {
      const liveData = connexionsActives[s.pseudo];
      const isOnline = liveData && liveData.connection && liveData.connection.isConnected;
      const diamantsSessionActuelle = liveData ? Object.values(liveData.gifters).reduce((sum, g) => sum + g.coins, 0) : 0;
      
      return {
        pseudo: s.pseudo,
        email: s.email,
        totalDiamantsGlobal: s.totalDiamantsGlobal || 0,
        diamantsSessionActuelle,
        enLigne: !!isOnline
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
// ----------------------------------------------------

app.get('/api/historique/:pseudo', async (req, res) => {
  const pseudo = normalizePseudo(req.params.pseudo);
  if (!req.session.user || !canManage(req.session.user, pseudo)) return res.status(401).json({ error: "Non autorisé" });
  if (!db) return res.json({ lives: [], encheres: [] });

  try {
    const lives = await db.collection('historique_lives').find({ pseudo }).sort({ fin: -1 }).limit(5).toArray();
    const encheres = await db.collection('historique_encheres').find({ pseudo }).sort({ date: -1 }).limit(5).toArray();
    res.json({ lives, encheres });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get('/api/live-status/:pseudo', async (req, res) => {
  const pseudo = normalizePseudo(req.params.pseudo);
  
  if (!req.session.user || !canManage(req.session.user, pseudo)) {
    return res.status(403).json({ error: "Accès refusé." });
  }

  if (!connexionsActives[pseudo] && db) {
    const user = await db.collection('users').findOne({ pseudo });
    if (user) demarrerEcouteLive(pseudo, user.apiKey);
  }
  const data = connexionsActives[pseudo];
  const isOnline = data && data.connection && data.connection.isConnected;
  res.json({ online: !!isOnline });
});

app.get('/api/live-stats/:pseudo', (req, res) => {
  const pseudo = normalizePseudo(req.params.pseudo);
  if (!req.session.user || !canManage(req.session.user, pseudo)) return res.status(401).json({ error: "Non autorisé" });
  
  const data = connexionsActives[pseudo];
  if (!data) return res.json({ totalDiamonds: 0, totalLikes: 0 });
  res.json({
    totalDiamonds: Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0),
    totalLikes: Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0)
  });
});

// ----------------------------------------------------
// GESTION DU LIVE TIKTOK (SÉCURISÉE & ROBUSTE)
// ----------------------------------------------------

const connexionsActives = {};

function arreterEcouteLive(pseudo, data, reason) {
  if (connexionsActives[pseudo] !== data || data.closed) return;

  data.closed = true;
  clearInterval(data.refreshTimer);

  if (data.enchere?.minuteur) clearTimeout(data.enchere.minuteur);
  if (!data.historySaved) {
    data.historySaved = true;
    sauvegarderHistoriqueLive(pseudo, data);
  }

  try {
    data.connection.removeAllListeners();
    if (typeof data.connection.disconnect === 'function') {
      data.connection.disconnect();
    }
  } catch {}

  delete connexionsActives[pseudo];
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
    likers: {}, 
    gifters: {}, 
    enchere: null, 
    bestGift: null,
    debutLive: new Date(), 
    derniereGagnantId: null, 
    vouchFait: false, 
    objectif: null,
    roue: { active: false, options: ["Gage 1", "Gage 2", "100 Diamants", "Rien", "Boost x2"] },
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
  }, 2000); 

  connection.connect().catch(() => {
    io.to(`streamer:${pseudo}`).emit('erreurConnexion', "Impossible de se connecter au live.");
    arreterEcouteLive(pseudo, data, 'connect_error');
  });

  connection.once('error', () => {
    arreterEcouteLive(pseudo, data, 'error');
  });

  connection.on('like', (d = {}) => {
    if (data.closed) return;
    const user = d.user && typeof d.user === 'object' ? d.user : {};
    const id = safeText(user.displayId || user.uniqueId, `unknown:${Math.random()}`);
    const nickname = safeText(user.nickname, 'Anonyme');
    const likes = positiveInteger(d.count, 1);
    const avatar = avatarFor(user, nickname);
    
    if (!data.likers[id]) data.likers[id] = { nickname, profilePictureUrl: avatar, likes: 0 };
    data.likers[id].likes += likes;
    
    data.pendingUpdates.likers = true;
    data.pendingUpdates.stats = true;
    if (data.objectif && data.objectif.metrique === 'likes') data.pendingUpdates.objectif = true;
  });

  connection.on('gift', (d = {}) => {
    if (data.closed) return;
    if (d.gift?.type === 1 && !d.repeatEnd) return;
    const user = d.user && typeof d.user === 'object' ? d.user : {};
    const id = safeText(user.displayId || d.uniqueId || user.userId, 'inconnu');
    const nickname = safeText(user.nickname || d.nickname, 'Anonyme');
    
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

    if (totalPieces >= 10 && data.roue && Array.isArray(data.roue.options) && data.roue.options.length > 0) {
      const optionGagnee = data.roue.options[Math.floor(Math.random() * data.roue.options.length)];
      io.to(`streamer:${pseudo}`).emit('tournerRoue', { gagnant: nickname, resultat: optionGagnee });
    }
    
    if (!data.bestGift || totalPieces > data.bestGift.montant) {
      data.bestGift = { pseudo: nickname, montant: totalPieces, icon: giftIcon };
      io.to(`streamer:${pseudo}`).emit('updateBestGift', data.bestGift); 
    }

    data.pendingUpdates.gifters = true;
    data.pendingUpdates.stats = true;
    if (data.objectif && data.objectif.metrique === 'diamants') data.pendingUpdates.objectif = true;
  });

  connection.on('chat', (d = {}) => {
    if (data.closed) return;
    const user = d.user && typeof d.user === 'object' ? d.user : {};
    const id = safeText(d.uniqueId || d.userId || user.displayId || user.userId, 'inconnu');
    const nickname = safeText(d.nickname || user.nickname, 'Anonyme');
    const avatar = avatarFor(user, nickname);
    const message = safeText(d.comment || d.text || d.message || d.msg || d.content, '');

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
  if (data.enchere?.minuteur) clearTimeout(data.enchere.minuteur);

  const enchere = {
    actif: true, phase: 'timer',
    snipeMs: snipeSecondes * 1000, miseMinimale: miseMinimale || 0,
    finTimestamp: Date.now() + dureeSecondes * 1000, dons: {}, minuteur: null,
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
  
  if (enchere.minuteur) clearTimeout(enchere.minuteur);
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
// GESTION DES WEBSOCKETS AVEC VALIDATION STRICTE DES TYPES
// ----------------------------------------------------

io.on('connection', socket => {
  socket.on('rejoindre', async ({ pseudo, apiKey, token }) => {
    const pseudoNettoye = normalizePseudo(pseudo);
    if (!pseudoNettoye) return;

    const utilisateurConnecte = socket.request.session?.user;
    const estAdmin = isAdmin(utilisateurConnecte);
    const estProprietaireConnecte = canManage(utilisateurConnecte, pseudoNettoye);
    const tokenValide = verifyOverlayToken(token, pseudoNettoye);

    if (db) {
      const utilisateur = await db.collection('users').findOne({ pseudo: pseudoNettoye });
      if (!utilisateur) {
        socket.emit('erreurConnexion', 'Streamer inconnu.');
        return;
      }

      const cleFournie = safeText(apiKey);
      const cleValideEnBase = utilisateur.apiKey && utilisateur.apiKey === cleFournie;

      if (!estAdmin && !estProprietaireConnecte && !tokenValide && !cleValideEnBase) {
        socket.emit('erreurConnexion', 'Accès refusé : Authentification invalide.');
        return;
      }
      
      socket.join(`streamer:${pseudoNettoye}`);
      demarrerEcouteLive(pseudoNettoye, utilisateur.apiKey);
    } else {
      socket.join(`streamer:${pseudoNettoye}`);
      demarrerEcouteLive(pseudoNettoye, apiKey);
    }
    
    const data = connexionsActives[pseudoNettoye];
    if (data && data.enchere && data.enchere.actif) socket.emit('enchereDemarree', etatEnchere(pseudoNettoye));
    if (data && data.bestGift) socket.emit('updateBestGift', data.bestGift);
    if (data && data.objectif) socket.emit('updateObjectif', etatObjectif(pseudoNettoye));
    if (data && data.coffre) socket.emit('updateCoffre', etatCoffrePublic(pseudoNettoye));
    socket.emit('initVouch', { vouches: vouchesGlobalCount });
  });

  socket.on('configurerRoue', ({ pseudo, options }) => {
    const user = socket.request.session?.user;
    const pseudoNettoye = normalizePseudo(pseudo);
    if (!canManage(user, pseudoNettoye)) return;
    const data = connexionsActives[pseudoNettoye];
    if (data && Array.isArray(options)) {
      data.roue.options = options.map(opt => safeText(opt)).filter(Boolean);
    }
  });

  socket.on('forcerTournerRoue', ({ pseudo }) => {
    const user = socket.request.session?.user;
    const pseudoNettoye = normalizePseudo(pseudo);
    if (!canManage(user, pseudoNettoye)) return;
    const data = connexionsActives[pseudoNettoye];
    if (data && data.roue && Array.isArray(data.roue.options) && data.roue.options.length > 0) {
      const optionGagnee = data.roue.options[Math.floor(Math.random() * data.roue.options.length)];
      io.to(`streamer:${pseudoNettoye}`).emit('tournerRoue', { gagnant: "Test Admin", resultat: optionGagnee });
    }
  });

  socket.on('demarrerEnchere', ({ pseudo, dureeSecondes, snipeSecondes, miseMinimale }) => {
    const utilisateurConnecte = socket.request.session?.user;
    const pseudoNettoye = normalizePseudo(pseudo);
    if (!canManage(utilisateurConnecte, pseudoNettoye)) return;

    const duree = parseInt(dureeSecondes, 10);
    const snipe = parseInt(snipeSecondes, 10);
    const min = parseInt(miseMinimale, 10) || 0;

    if (!Number.isSafeInteger(duree) || duree <= 0 || !Number.isSafeInteger(snipe) || snipe < 0 || !Number.isSafeInteger(min) || min < 0) return;

    if (connexionsActives[pseudoNettoye]) demarrerEnchere(pseudoNettoye, duree, snipe, min);
  });

  socket.on('definirObjectif', ({ pseudo, cible, metrique, label }) => {
    const utilisateurConnecte = socket.request.session?.user;
    const pseudoNettoye = normalizePseudo(pseudo);
    if (!canManage(utilisateurConnecte, pseudoNettoye)) return;
    const data = connexionsActives[pseudoNettoye];
    if (!data) return;

    const cibleNombre = parseInt(cible, 10);
    if (!Number.isSafeInteger(cibleNombre) || cibleNombre <= 0) return;

    data.objectif = {
      cible: cibleNombre,
      metrique: metrique === 'likes' ? 'likes' : 'diamants',
      label: safeText(label, 'Objectif du live').slice(0, 60)
    };
    io.to(`streamer:${pseudoNettoye}`).emit('updateObjectif', etatObjectif(pseudoNettoye));
  });

  socket.on('configurerCoffre', ({ pseudo, secret, recompense }) => {
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
  });

  socket.on('devoilerCharHasard', ({ pseudo }) => {
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
  });

  socket.on('devoilerCharIndex', ({ pseudo, index }) => {
    const utilisateurConnecte = socket.request.session?.user;
    const pseudoNettoye = normalizePseudo(pseudo);
    if (!canManage(utilisateurConnecte, pseudoNettoye)) return;
    const coffre = connexionsActives[pseudoNettoye]?.coffre;
    if (!coffre || !coffre.actif) return;

    const idxArr = parseInt(index, 10) - 1;
    if (Number.isSafeInteger(idxArr) && idxArr >= 0 && idxArr < coffre.devoiles.length) {
      coffre.devoiles[idxArr] = true;
      io.to(`streamer:${pseudoNettoye}`).emit('updateCoffre', etatCoffrePublic(pseudoNettoye));
    }
  });
});

server.listen(PORT, () => console.log(`🚀 TokOverlay démarré sur le port ${PORT}`));