const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const TikTokModule = require('tiktok-live-connector');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

const TikTokLiveConnection = TikTokModule.TikTokLiveConnection || TikTokModule.WebcastPushConnection;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/img', express.static(path.join(__dirname, 'img')));

// Sécurité : Validation stricte du secret de session en production
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  throw new Error("FATAL ERROR: SESSION_SECRET est manquant dans l'environnement de production !");
}

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'tokoverlay_secret_key_change_it',
  resave: false,
  saveUninitialized: false,
  store: process.env.MONGO_URI ? MongoStore.create({ mongoUrl: process.env.MONGO_URI }) : new session.MemoryStore()
});
app.use(sessionMiddleware);

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

const mongoUri = process.env.MONGO_URI;
let db = null;

let vouchesGlobalCount = 0;

async function connectMongo() {
  if (!mongoUri) {
    console.error("❌ ERREUR : MONGO_URI absente des variables Render !");
    return;
  }
  try {
    const client = new MongoClient(mongoUri);
    await client.connect();
    db = client.db('tokoverlay_db');
    console.log("✅ Connecté à MongoDB Atlas avec succès !");

    const compteur = await db.collection('compteurs').findOne({ _id: 'vouches' });
    vouchesGlobalCount = compteur?.total || 0;
  } catch (err) {
    console.error("❌ Erreur de connexion MongoDB :", err);
  }
}
connectMongo();

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
    email = email.trim().toLowerCase();
    const pseudoNettoye = pseudo.replace('@', '').trim();
    const usersCollection = db.collection('users');

    const existingUser = await usersCollection.findOne({
      $or: [{ email }, { pseudo: pseudoNettoye }]
    });

    if (existingUser) {
      if (existingUser.email === email) return res.redirect('/?error=email_exists');
      if (existingUser.pseudo === pseudoNettoye) return res.redirect('/?error=pseudo_exists');
    }

    const passwordHache = await bcrypt.hash(password, 10);
    const newUser = { pseudo: pseudoNettoye, apiKey: apiKey.trim(), email, password: passwordHache };
    await usersCollection.insertOne(newUser);
    req.session.user = { pseudo: newUser.pseudo, apiKey: newUser.apiKey, email: newUser.email };
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
    const user = await usersCollection.findOne({ pseudo: pseudo.replace('@', '').trim() });
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = { pseudo: user.pseudo, apiKey: user.apiKey, email: user.email };
      return res.redirect('/choix.html');
    }
    res.redirect('/?error=wrong_credentials');
  } catch (err) {
    res.status(500).send("Erreur serveur.");
  }
});

app.get('/api/me', (req, res) => {
  if (req.session.user) res.json(req.session.user);
  else res.status(401).json({ error: 'Non connecté' });
});

app.post('/api/update-profile', async (req, res) => {
  let { pseudo, apiKey } = req.body;
  if (!req.session.user || !db) return res.status(401).json({ error: "Non autorisé" });
  try {
    const nvPseudo = pseudo.replace('@', '').trim();
    const nvApiKey = apiKey.trim();
    await db.collection('users').updateOne({ email: req.session.user.email }, { $set: { pseudo: nvPseudo, apiKey: nvApiKey } });
    req.session.user.pseudo = nvPseudo;
    req.session.user.apiKey = nvApiKey;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// ----------------------------------------------------
// ROUTES FRONT-END ET API
// ----------------------------------------------------

app.get('/overlay/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'overlay.html')));
app.get('/layout/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'layout.html')));

app.get('/encheres/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  if (req.session.user.pseudo !== req.params.username) return res.redirect('/encheres/' + encodeURIComponent(req.session.user.pseudo));
  res.sendFile(path.join(__dirname, 'public', 'controle-encheres.html'));
});

app.get('/admin-live/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  if (req.session.user.pseudo !== req.params.username) return res.redirect('/admin-live/' + encodeURIComponent(req.session.user.pseudo));
  res.sendFile(path.join(__dirname, 'public', 'admin-live.html'));
});

app.get('/chat/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  if (req.session.user.pseudo !== req.params.username) return res.redirect('/chat/' + encodeURIComponent(req.session.user.pseudo));
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

app.get('/api/historique/:pseudo', async (req, res) => {
  const pseudo = req.params.pseudo;
  if (!req.session.user || req.session.user.pseudo !== pseudo) return res.status(401).json({ error: "Non autorisé" });
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
  const pseudo = req.params.pseudo;
  if (!connexionsActives[pseudo] && db) {
    const user = await db.collection('users').findOne({ pseudo });
    if (user) demarrerEcouteLive(pseudo, user.apiKey);
  }
  const data = connexionsActives[pseudo];
  const isOnline = data && data.connection && data.connection.isConnected;
  res.json({ online: !!isOnline });
});

app.get('/api/live-stats/:pseudo', (req, res) => {
  const pseudo = req.params.pseudo;
  if (!req.session.user || req.session.user.pseudo !== pseudo) return res.status(401).json({ error: "Non autorisé" });
  
  const data = connexionsActives[pseudo];
  if (!data) return res.json({ totalDiamonds: 0, totalLikes: 0 });
  res.json({
    totalDiamonds: Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0),
    totalLikes: Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0)
  });
});

// ----------------------------------------------------
// GESTION DU LIVE TIKTOK (TIKTOK LIVE CONNECTOR)
// ----------------------------------------------------

const connexionsActives = {};

function demarrerEcouteLive(pseudo, apiKey) {
  if (connexionsActives[pseudo]) return;

  const connection = new TikTokLiveConnection(pseudo, { signApiKey: apiKey });
  const data = {
    connection, likers: {}, gifters: {}, enchere: null, bestGift: null,
    debutLive: new Date(), derniereGagnantId: null, vouchFait: false, objectif: null,
    coffre: { actif: false, secret: '', devoiles: [], recompense: '', gagnant: null, dernierMessageGagnant: '' },
    pendingUpdates: { likers: false, gifters: false, stats: false, objectif: false }
  };
  connexionsActives[pseudo] = data;

  const boucleActualisation = setInterval(() => {
    if (!connexionsActives[pseudo]) {
      clearInterval(boucleActualisation);
      return;
    }
    const p = data.pendingUpdates;

    if (p.likers) {
      io.to(pseudo).emit('updateTopLikers', Object.values(data.likers).sort((a, b) => b.likes - a.likes).slice(0, 3));
      p.likers = false;
    }
    if (p.gifters) {
      io.to(pseudo).emit('updateTopGifters', Object.values(data.gifters).sort((a, b) => b.coins - a.coins).slice(0, 3));
      p.gifters = false;
    }
    if (p.stats) {
      const totalDiamonds = Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0);
      const totalLikes = Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0);
      io.to(pseudo).emit('updateStatsLive', { totalDiamonds, totalLikes });
      p.stats = false;
    }
    if (p.objectif && data.objectif) {
      io.to(pseudo).emit('updateObjectif', etatObjectif(pseudo));
      p.objectif = false;
    }
  }, 2000); 

  connection.connect().catch(err => {
    io.to(pseudo).emit('erreurConnexion', "Impossible de se connecter au live.");
    clearInterval(boucleActualisation);
    delete connexionsActives[pseudo];
  });

  connection.on('error', err => {
    console.error(`[TikTok] Erreur fatale pour ${pseudo}:`, err.message || err);
    sauvegarderHistoriqueLive(pseudo);
    if (data.enchere?.minuteur) clearTimeout(data.enchere.minuteur);
    clearInterval(boucleActualisation); 
    delete connexionsActives[pseudo];
  });

  connection.on('like', d => {
    const id = d.user?.displayId || 'inconnu';
    const nickname = d.user?.nickname || 'Anonyme';
    const avatar = d.user?.avatarThumb?.urlList?.[0] || `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
    
    if (!data.likers[id]) data.likers[id] = { nickname, profilePictureUrl: avatar, likes: 0 };
    data.likers[id].likes += d.count || 1;
    
    data.pendingUpdates.likers = true;
    data.pendingUpdates.stats = true;
    if (data.objectif && data.objectif.metrique === 'likes') data.pendingUpdates.objectif = true;
  });

  connection.on('gift', d => {
    if (d.gift?.type === 1 && !d.repeatEnd) return;
    const id = d.user?.displayId || d.uniqueId || 'inconnu';
    const nickname = d.user?.nickname || d.nickname || 'Anonyme';
    const totalPieces = (d.gift?.diamondCount || 0) * (d.repeatCount || 1);
    if (totalPieces === 0) return;
    
    const avatar = d.user?.avatarThumb?.urlList?.[0] || `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
    const giftIcon = d.gift?.icon?.urlList?.[0] || 'https://via.placeholder.com/60';

    if (!data.gifters[id]) data.gifters[id] = { nickname, profilePictureUrl: avatar, coins: 0 };
    data.gifters[id].coins += totalPieces;
    
    traiterDonPourEnchere(pseudo, id, nickname, avatar, totalPieces);
    
    if (!data.bestGift || totalPieces > data.bestGift.montant) {
      data.bestGift = { pseudo: nickname, montant: totalPieces, icon: giftIcon };
      io.to(pseudo).emit('updateBestGift', data.bestGift); 
    }

    data.pendingUpdates.gifters = true;
    data.pendingUpdates.stats = true;
    if (data.objectif && data.objectif.metrique === 'diamants') data.pendingUpdates.objectif = true;
  });

  // ANALYSE DU CHAT UNIFIÉE POUR TOUS LES MODULES (Coffre, Enchères, Vouch, Radar)
  connection.on('chat', d => {
    const id = d.uniqueId || d.userId || d.user?.displayId || d.user?.userId || 'inconnu';
    const nickname = d.nickname || d.user?.nickname || 'Anonyme';
    const avatar = d.profilePictureUrl || d.user?.avatarThumb?.urlList?.[0] || `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
    
    // Extraction parfaite validée par le radar
    const message = d.comment || d.text || d.message || d.msg || '';

    // Envoi en direct vers le panneau de débogage / chat
    io.to(pseudo).emit('chatEnDirect', { nickname, avatar, message });

    // Mise à jour de l'enchère en cours
    if (data.enchere && data.enchere.dons[id]) {
      data.enchere.dons[id].dernierMessageChat = message;
    }

    // Gestion du Coffre-Fort (déblocage automatique par le chat)
    if (data.coffre && data.coffre.actif && !data.coffre.gagnant) {
      const msgNettoye = message.trim().toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      const secretNettoye = data.coffre.secret.trim().toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      
      if (msgNettoye !== "" && msgNettoye === secretNettoye) {
        console.log(`🎉 [COFFRE] VICTOIRE ! ${nickname} a ouvert le coffre !`);
        data.coffre.gagnant = { id, nickname, avatar };
        data.coffre.actif = false;
        
        io.to(pseudo).emit('updateCoffre', etatCoffrePublic(pseudo)); 
        io.to(pseudo).emit('coffreOuvert', etatCoffrePublic(pseudo)); 
      }
    } else if (data.coffre && data.coffre.gagnant && id === data.coffre.gagnant.id) {
      data.coffre.dernierMessageGagnant = message;
      io.to(pseudo).emit('updateMessageGagnantCoffre', { message }); 
    }

    // Gestion des enchères et du Vouch
    if (data.derniereGagnantId && id === data.derniereGagnantId) {
      io.to(pseudo).emit('updateMessageGagnant', { message });

      if (!data.vouchFait && message.trim().toLowerCase() === 'vouch') {
        data.vouchFait = true;
        incrementerVouchGlobal();
        io.to(pseudo).emit('vouchConfirme', {});
      }
    }
  });

  connection.on('disconnect', () => {
    sauvegarderHistoriqueLive(pseudo);
    if (data.enchere?.minuteur) clearTimeout(data.enchere.minuteur);
    clearInterval(boucleActualisation); 
    delete connexionsActives[pseudo];
  });
  
  connection.on('streamEnd', () => {
    sauvegarderHistoriqueLive(pseudo);
    if (data.enchere?.minuteur) clearTimeout(data.enchere.minuteur);
    clearInterval(boucleActualisation); 
    delete connexionsActives[pseudo];
  });
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

function sauvegarderHistoriqueLive(pseudo) {
  const data = connexionsActives[pseudo];
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
  }).catch(err => console.error("Erreur sauvegarde historique live :", err));
}

function demarrerEnchere(pseudo, dureeSecondes, snipeSecondes, miseMinimale) {
  const data = connexionsActives[pseudo];
  if (!data) return;
  data.enchere = {
    actif: true, phase: 'timer',
    snipeMs: snipeSecondes * 1000, miseMinimale: miseMinimale || 0,
    finTimestamp: Date.now() + dureeSecondes * 1000, dons: {}, minuteur: null,
    totalDiamantsEnchere: 0
  };
  programmerTransitionOuFin(pseudo);
  io.to(pseudo).emit('enchereDemarree', etatEnchere(pseudo));
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

function programmerTransitionOuFin(pseudo) {
  const data = connexionsActives[pseudo];
  if (!data || !data.enchere) return;
  const enchere = data.enchere;
  
  if (enchere.minuteur) clearTimeout(enchere.minuteur);
  const delai = Math.max(enchere.finTimestamp - Date.now(), 0);
  const delaiSecurise = (isNaN(delai) || delai < 0) ? 1000 : delai;

  enchere.minuteur = setTimeout(() => {
    const currentData = connexionsActives[pseudo];
    if (!currentData || !currentData.enchere || !currentData.enchere.actif) return;

    if (enchere.phase === 'timer') {
      enchere.phase = 'snipe';
      enchere.finTimestamp = Date.now() + enchere.snipeMs;
      io.to(pseudo).emit('updateEnchere', etatEnchere(pseudo));
      programmerTransitionOuFin(pseudo);
    } else {
      terminerEnchere(pseudo);
    }
  }, delaiSecurise);
}

function traiterDonPourEnchere(pseudo, id, nickname, avatar, totalPieces) {
  const enchere = connexionsActives[pseudo]?.enchere;
  if (!enchere || !enchere.actif) return;
  if (!enchere.dons[id]) enchere.dons[id] = { id, nickname, profilePictureUrl: avatar, coins: 0, dernierMessageChat: '' };
  enchere.dons[id].coins += totalPieces;
  enchere.totalDiamantsEnchere += totalPieces;
  io.to(pseudo).emit('updateEnchere', etatEnchere(pseudo));
}

function terminerEnchere(pseudo) {
  const enchere = connexionsActives[pseudo]?.enchere;
  if (!enchere) return;

  const donsValides = Object.values(enchere.dons).filter(don => don.coins >= enchere.miseMinimale).sort((a, b) => b.coins - a.coins);
  
  if (donsValides.length >= 2 && donsValides[0].coins === donsValides[1].coins) {
    enchere.phase = 'timer';
    enchere.finTimestamp = Date.now() + 30000;
    io.to(pseudo).emit('egaliteEnchere', { message: "Égalité ! +30s ajoutées !" });
    programmerTransitionOuFin(pseudo);
    io.to(pseudo).emit('updateEnchere', etatEnchere(pseudo));
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
    }).catch(err => console.error("Erreur sauvegarde historique enchère :", err));
  }

  io.to(pseudo).emit('enchereTerminee', { 
    gagnant, 
    classement: donsValides.slice(0, 3),
    totalDiamantsEnchere: enchere.totalDiamantsEnchere 
  });
}

// ----------------------------------------------------
// GESTION DES WEBSOCKETS (CLIENT-SERVEUR)
// ----------------------------------------------------

io.on('connection', socket => {
  socket.on('rejoindre', async ({ pseudo, apiKey }) => {
    if (!pseudo) return;

    if (db) {
      const utilisateur = await db.collection('users').findOne({ pseudo });
      if (!utilisateur || utilisateur.apiKey !== apiKey) {
        socket.emit('erreurConnexion', 'Accès refusé : Clé API ou pseudo invalide.');
        return;
      }
    }

    socket.join(pseudo);
    demarrerEcouteLive(pseudo, apiKey);
    
    const data = connexionsActives[pseudo];
    if (data && data.enchere && data.enchere.actif) socket.emit('enchereDemarree', etatEnchere(pseudo));
    if (data && data.bestGift) socket.emit('updateBestGift', data.bestGift);
    if (data && data.objectif) socket.emit('updateObjectif', etatObjectif(pseudo));
    if (data && data.coffre) socket.emit('updateCoffre', etatCoffrePublic(pseudo));
    socket.emit('initVouch', { vouches: vouchesGlobalCount });
  });

  socket.on('demarrerEnchere', ({ pseudo, dureeSecondes, snipeSecondes, miseMinimale }) => {
    const utilisateurConnecte = socket.request.session?.user;
    if (!utilisateurConnecte || utilisateurConnecte.pseudo !== pseudo) return;

    const duree = parseInt(dureeSecondes, 10);
    const snipe = parseInt(snipeSecondes, 10);
    const min = parseInt(miseMinimale, 10) || 0;

    if (isNaN(duree) || duree <= 0 || isNaN(snipe) || snipe < 0 || isNaN(min) || min < 0) return;

    if (connexionsActives[pseudo]) demarrerEnchere(pseudo, duree, snipe, min);
  });

  socket.on('definirObjectif', ({ pseudo, cible, metrique, label }) => {
    const utilisateurConnecte = socket.request.session?.user;
    if (!utilisateurConnecte || utilisateurConnecte.pseudo !== pseudo) return;
    const data = connexionsActives[pseudo];
    if (!data) return;

    const cibleNombre = parseInt(cible, 10);
    if (!cibleNombre || cibleNombre <= 0) return;

    data.objectif = {
      cible: cibleNombre,
      metrique: metrique === 'likes' ? 'likes' : 'diamants',
      label: (label || '').trim().slice(0, 60) || 'Objectif du live'
    };
    io.to(pseudo).emit('updateObjectif', etatObjectif(pseudo));
  });

  socket.on('configurerCoffre', ({ pseudo, secret, recompense }) => {
    const utilisateurConnecte = socket.request.session?.user;
    if (!utilisateurConnecte || utilisateurConnecte.pseudo !== pseudo) return;
    const data = connexionsActives[pseudo];
    if (!data) return;

    const cleanSecret = secret.trim();
    data.coffre = {
      actif: true,
      secret: cleanSecret,
      devoiles: new Array(cleanSecret.length).fill(false),
      recompense: recompense.trim(),
      gagnant: null,
      dernierMessageGagnant: ''
    };
    io.to(pseudo).emit('updateCoffre', etatCoffrePublic(pseudo));
  });

  socket.on('devoilerCharHasard', ({ pseudo }) => {
    const utilisateurConnecte = socket.request.session?.user;
    if (!utilisateurConnecte || utilisateurConnecte.pseudo !== pseudo) return;
    const coffre = connexionsActives[pseudo]?.coffre;
    if (!coffre || !coffre.actif) return;

    const indicesNonDevoiles = coffre.devoiles.map((dev, idx) => dev ? -1 : idx).filter(idx => idx !== -1);
    if (indicesNonDevoiles.length > 0) {
      const idxChoisi = indicesNonDevoiles[Math.floor(Math.random() * indicesNonDevoiles.length)];
      coffre.devoiles[idxChoisi] = true;
      io.to(pseudo).emit('updateCoffre', etatCoffrePublic(pseudo));
    }
  });

  socket.on('devoilerCharIndex', ({ pseudo, index }) => {
    const utilisateurConnecte = socket.request.session?.user;
    if (!utilisateurConnecte || utilisateurConnecte.pseudo !== pseudo) return;
    const coffre = connexionsActives[pseudo]?.coffre;
    if (!coffre || !coffre.actif) return;

    const idxArr = parseInt(index, 10) - 1;
    if (idxArr >= 0 && idxArr < coffre.devoiles.length) {
      coffre.devoiles[idxArr] = true;
      io.to(pseudo).emit('updateCoffre', etatCoffrePublic(pseudo));
    }
  });
});

server.listen(PORT, () => console.log(`🚀 TokOverlay démarré sur le port ${PORT}`));