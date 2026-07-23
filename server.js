const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const TikTokModule = require('tiktok-live-connector');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
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

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'tokoverlay_secret_key_change_it',
  resave: false,
  saveUninitialized: false
});
app.use(sessionMiddleware);

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

const mongoUri = process.env.MONGO_URI;
let db = null;

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
  } catch (err) {
    console.error("❌ Erreur de connexion MongoDB :", err);
  }
}
connectMongo();

app.post('/register', async (req, res) => {
  let { pseudo, apiKey, email, password } = req.body;
  try {
    if (!db) return res.status(500).send("Base de données en cours de connexion.");
    email = email.trim().toLowerCase();
    const usersCollection = db.collection('users');
    if (await usersCollection.findOne({ email })) return res.redirect('/?error=email_exists');

    const passwordHache = await bcrypt.hash(password, 10);
    const newUser = { pseudo: pseudo.replace('@', '').trim(), apiKey: apiKey.trim(), email, password: passwordHache };
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
app.get('/overlay/:username', (req, res) => res.sendFile(path.join(__dirname, 'public', 'overlay.html')));
app.get('/encheres/:username', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  if (req.session.user.pseudo !== req.params.username) return res.redirect('/encheres/' + encodeURIComponent(req.session.user.pseudo));
  res.sendFile(path.join(__dirname, 'public', 'controle-encheres.html'));
});

const connexionsActives = {};

function demarrerEcouteLive(pseudo, apiKey) {
  if (connexionsActives[pseudo]) return;

  const connection = new TikTokLiveConnection(pseudo, { signApiKey: apiKey });
  const data = { connection, likers: {}, gifters: {}, enchere: null, bestGift: null };
  connexionsActives[pseudo] = data;

  connection.connect().catch(err => {
    io.to(pseudo).emit('erreurConnexion', "Impossible de se connecter au live.");
    delete connexionsActives[pseudo];
  });

  connection.on('like', d => {
    const id = d.user?.displayId || 'inconnu';
    const nickname = d.user?.nickname || 'Anonyme';
    const avatar = d.user?.avatarThumb?.urlList?.[0] || `https://ui-avatars.com/api/?name=${encodeURIComponent(nickname)}&background=random`;
    if (!data.likers[id]) data.likers[id] = { nickname, profilePictureUrl: avatar, likes: 0 };
    data.likers[id].likes += d.count || 1;
    io.to(pseudo).emit('updateTopLikers', Object.values(data.likers).sort((a, b) => b.likes - a.likes).slice(0, 3));
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
    io.to(pseudo).emit('updateTopGifters', Object.values(data.gifters).sort((a, b) => b.coins - a.coins).slice(0, 3));
    traiterDonPourEnchere(pseudo, id, nickname, avatar, totalPieces);

    if (!data.bestGift || totalPieces > data.bestGift.montant) {
      data.bestGift = { pseudo: nickname, montant: totalPieces, icon: giftIcon };
      io.to(pseudo).emit('updateBestGift', data.bestGift);
    }
  });

  connection.on('chat', d => {
    const id = d.user?.displayId || 'inconnu';
    const message = d.comment;
    if (data.enchere && data.enchere.dons[id]) {
      data.enchere.dons[id].dernierMessageChat = message;
    }
  });

  connection.on('disconnect', () => {
    if (data.enchere?.minuteur) clearTimeout(data.enchere.minuteur);
    delete connexionsActives[pseudo];
  });
  connection.on('streamEnd', () => {
    if (data.enchere?.minuteur) clearTimeout(data.enchere.minuteur);
    delete connexionsActives[pseudo];
  });
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
  const enchere = connexionsActives[pseudo]?.enchere;
  if (!enchere) return;
  if (enchere.minuteur) clearTimeout(enchere.minuteur);
  const delai = Math.max(enchere.finTimestamp - Date.now(), 0);
  enchere.minuteur = setTimeout(() => {
    if (enchere.phase === 'timer') {
      enchere.phase = 'snipe';
      enchere.finTimestamp = Date.now() + enchere.snipeMs;
      io.to(pseudo).emit('updateEnchere', etatEnchere(pseudo));
      programmerTransitionOuFin(pseudo);
    } else {
      terminerEnchere(pseudo);
    }
  }, delai);
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
  
  io.to(pseudo).emit('enchereTerminee', { 
    gagnant, 
    classement: donsValides.slice(0, 3),
    totalDiamantsEnchere: enchere.totalDiamantsEnchere 
  });
}

io.on('connection', socket => {
  socket.on('rejoindre', async ({ pseudo, apiKey }) => {
    if (!pseudo) return;
    socket.join(pseudo);

    let cleAUtiliser = apiKey;
    if (db) {
      const utilisateur = await db.collection('users').findOne({ pseudo });
      if (!utilisateur) {
        socket.emit('erreurConnexion', "Ce pseudo n'est pas enregistré sur TokOverlay.");
        return;
      }
      cleAUtiliser = utilisateur.apiKey;
    }

    demarrerEcouteLive(pseudo, cleAUtiliser);
    const data = connexionsActives[pseudo];
    if (data && data.enchere && data.enchere.actif) socket.emit('enchereDemarree', etatEnchere(pseudo));
    if (data && data.bestGift) socket.emit('updateBestGift', data.bestGift);
  });

  socket.on('demarrerEnchere', ({ pseudo, dureeSecondes, snipeSecondes, miseMinimale }) => {
    const utilisateurConnecte = socket.request.session?.user;
    if (!utilisateurConnecte || utilisateurConnecte.pseudo !== pseudo) {
      socket.emit('erreurConnexion', "Non autorisé à démarrer une enchère pour ce compte.");
      return;
    }
    if (connexionsActives[pseudo]) demarrerEnchere(pseudo, dureeSecondes, snipeSecondes, miseMinimale);
  });
});

app.get('/api/live-stats/:pseudo', (req, res) => {
  const pseudo = req.params.pseudo;
  const data = connexionsActives[pseudo];
  if (!data) return res.json({ totalDiamonds: 0, totalLikes: 0 });
  res.json({
    totalDiamonds: Object.values(data.gifters).reduce((sum, g) => sum + g.coins, 0),
    totalLikes: Object.values(data.likers).reduce((sum, l) => sum + l.likes, 0)
  });
});

server.listen(PORT, () => console.log(`🚀 TokOverlay démarré sur le port ${PORT}`));
