const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
app.set('trust proxy', 1); // Railway est derrière un proxy : nécessaire pour avoir la vraie IP
app.use(cors());

// Lecture du corps des requêtes : JSON, formulaire, ou texte contenant du JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text({ type: ['text/plain'] }));
app.use((req, res, next) => {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (e) { req.body = {}; }
  }
  if (!req.body || typeof req.body !== 'object') req.body = {};
  next();
});

// Connexion à la base de données (chemin compatible Railway avec volume ou local)
const dbPath = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'game.db')
  : './game.db';

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("Erreur BDD:", err.message);
  else console.log(`Connecté à la base de données SQLite sur : ${dbPath}`);
});

// Helpers pour utiliser sqlite3 avec async/await
const run = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.run(sql, params, function (err) {
      err ? reject(err) : resolve(this);
    })
  );
const get = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)))
  );
const all = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)))
  );

// ---------------------------------------------------------------------------
// Base de données
// ---------------------------------------------------------------------------
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      coins INTEGER DEFAULT 1000
    )
  `);
  // Ajout des colonnes de compte sur une ancienne base (l'erreur "colonne existe déjà" est ignorée)
  db.run(`ALTER TABLE users ADD COLUMN nickname TEXT`, () => {});
  db.run(`ALTER TABLE users ADD COLUMN password_hash TEXT`, () => {});

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS cards (
      card_id INTEGER PRIMARY KEY,
      name TEXT,
      power INTEGER,
      global_population INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      card_id INTEGER,
      obtained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Combat : cartes posées (une ligne par exemplaire posé, verrouillé jusqu'à la résolution)
  db.run(`
    CREATE TABLE IF NOT EXISTS placements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      inventory_id INTEGER NOT NULL UNIQUE,
      card_id INTEGER NOT NULL,
      camp TEXT NOT NULL,
      day TEXT NOT NULL
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_placements_day ON placements(day)`);

  // Résultat de chaque journée de combat (jour = date à Paris, AAAA-MM-JJ)
  db.run(`
    CREATE TABLE IF NOT EXISTS battle_days (
      day TEXT PRIMARY KEY,
      winner TEXT,
      total_a INTEGER DEFAULT 0,
      total_b INTEGER DEFAULT 0
    )
  `);

  // Ce qui est arrivé à chaque joueur (affiché à sa prochaine connexion)
  db.run(`
    CREATE TABLE IF NOT EXISTS battle_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      day TEXT,
      user_id TEXT,
      camp TEXT,
      outcome TEXT,
      cards INTEGER
    )
  `);

  // Puissance de chaque carte, dans l'ordre des animations 0 à 9
  const powerList = [10, 10, 8, 8, 6, 6, 4, 4, 2, 2];

  // À chaque démarrage, la puissance est mise à jour sans toucher à la population
  const stmt = db.prepare(`
    INSERT INTO cards (card_id, name, power, global_population)
    VALUES (?, ?, ?, 0)
    ON CONFLICT(card_id) DO UPDATE SET power = excluded.power
  `);
  for (let i = 0; i <= 9; i++) {
    stmt.run(i, `Carte #${i + 1}`, powerList[i]);
  }
  stmt.finalize();
});

// ---------------------------------------------------------------------------
// Comptes et sessions
// ---------------------------------------------------------------------------
const NICK_RE = /^[A-Za-z0-9_-]{3,16}$/;
const SESSION_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours
const BAD_LOGIN = "Incorrect nickname or password";
// Hash factice : on compare toujours un mot de passe, même si le pseudo n'existe pas
const DUMMY_HASH = bcrypt.hashSync('mot-de-passe-factice', 10);

const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await run(
    `INSERT INTO sessions (token_hash, user_id, created_at) VALUES (?, ?, ?)`,
    [hashToken(token), userId, Date.now()]
  );
  return token;
}

// Limite le nombre de tentatives de connexion/inscription par adresse IP
function rateLimit(max, windowMs) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const recent = (hits.get(req.ip) || []).filter((t) => now - t < windowMs);
    if (recent.length >= max) {
      return res.status(429).json({ success: false, error: "Too many attempts, try again later" });
    }
    recent.push(now);
    hits.set(req.ip, recent);
    next();
  };
}
const authLimiter = rateLimit(15, 10 * 60 * 1000);

// Vérifie le jeton de session (dans le corps "token" ou l'en-tête Authorization: Bearer ...)
async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : req.body.token;
    if (!token || typeof token !== 'string') {
      return res.status(401).json({ success: false, error: "Not logged in" });
    }
    const session = await get(
      `SELECT user_id, created_at FROM sessions WHERE token_hash = ?`,
      [hashToken(token)]
    );
    if (!session || Date.now() - session.created_at > SESSION_MS) {
      return res.status(401).json({ success: false, error: "Session expired, please log in again" });
    }
    req.userId = session.user_id;
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Server error" });
  }
}

// Inscription
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const nickname = String(req.body.nickname || '').trim();
    const password = String(req.body.password || '');

    if (!NICK_RE.test(nickname)) {
      return res.status(400).json({
        success: false,
        error: "Invalid nickname (3 to 16 characters: letters, digits, _ or -)"
      });
    }
    if (password.length < 6 || password.length > 64) {
      return res.status(400).json({ success: false, error: "Password must be 6 to 64 characters" });
    }

    const id = nickname.toLowerCase(); // "Bob" et "bob" sont le même pseudo
    const hash = await bcrypt.hash(password, 10);

    try {
      await run(
        `INSERT INTO users (id, nickname, password_hash, coins) VALUES (?, ?, ?, 1000)`,
        [id, nickname, hash]
      );
    } catch (e) {
      if (e.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ success: false, error: "This nickname is already taken" });
      }
      throw e;
    }

    const token = await createSession(id);
    res.json({ success: true, token, nickname, coins: 1000 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Connexion
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const nickname = String(req.body.nickname || '').trim();
    const password = String(req.body.password || '');
    const user = await get(`SELECT * FROM users WHERE id = ?`, [nickname.toLowerCase()]);

    const ok = await bcrypt.compare(password, (user && user.password_hash) || DUMMY_HASH);
    if (!user || !user.password_hash || !ok) {
      return res.status(401).json({ success: false, error: BAD_LOGIN });
    }

    const token = await createSession(user.id);
    res.json({ success: true, token, nickname: user.nickname, coins: user.coins });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Profil du joueur connecté (pour afficher ses pièces au lancement d'une scène)
app.post('/api/me', auth, async (req, res) => {
  try {
    const user = await get(`SELECT nickname, coins FROM users WHERE id = ?`, [req.userId]);
    res.json({ success: true, nickname: user.nickname, coins: user.coins });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ---------------------------------------------------------------------------
// Achat d'un Booster (5 cartes)
// ---------------------------------------------------------------------------
app.post('/api/packs/buy', auth, async (req, res) => {
  const userId = req.userId;
  const PACK_COST = 100;
  let debited = false;

  try {
    // Débit atomique : ne passe que s'il reste assez de pièces
    const debit = await run(
      `UPDATE users SET coins = coins - ? WHERE id = ? AND coins >= ?`,
      [PACK_COST, userId, PACK_COST]
    );
    if (debit.changes === 0) {
      return res.status(400).json({ success: false, error: "Not enough coins!" });
    }
    debited = true;

    // Tirage séquentiel des 5 cartes
    const drawnCards = [];
    for (let i = 0; i < 5; i++) {
      const cardId = Math.floor(Math.random() * 10);
      await run(`UPDATE cards SET global_population = global_population + 1 WHERE card_id = ?`, [cardId]);
      await run(`INSERT INTO inventory (user_id, card_id) VALUES (?, ?)`, [userId, cardId]);
      const card = await get(`SELECT * FROM cards WHERE card_id = ?`, [cardId]);
      drawnCards.push({
        animationIndex: card.card_id,
        name: card.name,
        power: card.power,
        globalPopulation: card.global_population
      });
    }

    const user = await get(`SELECT coins FROM users WHERE id = ?`, [userId]);
    res.json({ success: true, remainingCoins: user.coins, drawnCards });
  } catch (e) {
    console.error(e);
    // Si quelque chose a planté après le débit, on rend les pièces
    if (debited) {
      try { await run(`UPDATE users SET coins = coins + ? WHERE id = ?`, [PACK_COST, userId]); }
      catch (e2) { console.error(e2); }
    }
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ---------------------------------------------------------------------------
// Inventaire : les 10 cartes du jeu, dans l'ordre des animations (0 à 9),
// avec le nombre d'exemplaires possédés (count = 0 si la carte n'est pas possédée)
// ---------------------------------------------------------------------------
app.post('/api/inventory', auth, async (req, res) => {
  try {
    const rows = await new Promise((resolve, reject) =>
      db.all(
        `SELECT c.card_id AS animationIndex, c.name, c.power,
                c.global_population AS globalPopulation,
                COUNT(i.id) AS count, COUNT(p.id) AS placed
         FROM cards c
         LEFT JOIN inventory i ON i.card_id = c.card_id AND i.user_id = ?
         LEFT JOIN placements p ON p.inventory_id = i.id
         GROUP BY c.card_id
         ORDER BY c.card_id`,
        [req.userId],
        (err, r) => (err ? reject(err) : resolve(r))
      )
    );
    res.json({ success: true, total: rows.reduce((s, r) => s + r.count, 0), cards: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ---------------------------------------------------------------------------
// Combat : 2 camps (A et B), 42 cartes posées maximum par jour et par joueur.
// Une carte posée est définitive : elle est verrouillée jusqu'à minuit (heure de Paris).
// À minuit, le camp qui a le plus de puissance gagne et récupère ses cartes ;
// le camp perdant voit ses cartes détruites (retirées de l'inventaire et de la population).
// Égalité : personne ne perd rien.
// ---------------------------------------------------------------------------
const CAMPS = ['A', 'B'];
const MAX_PLACED_PER_DAY = 42;

// Jour de combat = date à Paris, au format AAAA-MM-JJ
function parisDay(d = new Date()) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit', day: '2-digit'
  }).format(d);
}

function secondsToParisMidnight() {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Paris', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  }).formatToParts(new Date());
  const v = (t) => parseInt(parts.find((p) => p.type === t).value, 10);
  return 86400 - ((v('hour') % 24) * 3600 + v('minute') * 60 + v('second'));
}

// Résout une journée passée. Peut être relancée sans risque : le gagnant est figé
// dès le premier passage et chaque carte n'est détruite qu'une seule fois.
async function resolveDay(day) {
  let rec = await get(`SELECT * FROM battle_days WHERE day = ?`, [day]);
  if (!rec) {
    const sums = await all(
      `SELECT p.camp AS camp, SUM(c.power) AS total
       FROM placements p JOIN cards c ON c.card_id = p.card_id
       WHERE p.day = ? GROUP BY p.camp`,
      [day]
    );
    const total = { A: 0, B: 0 };
    sums.forEach((s) => { total[s.camp] = s.total; });
    const winner = total.A > total.B ? 'A' : total.B > total.A ? 'B' : 'TIE';
    await run(
      `INSERT OR IGNORE INTO battle_days (day, winner, total_a, total_b) VALUES (?, ?, ?, ?)`,
      [day, winner, total.A, total.B]
    );
    rec = await get(`SELECT * FROM battle_days WHERE day = ?`, [day]);
  }

  const rows = await all(`SELECT id, user_id, inventory_id, card_id, camp FROM placements WHERE day = ?`, [day]);
  const perUser = {};
  for (const r of rows) {
    const lost = rec.winner !== 'TIE' && r.camp !== rec.winner;
    if (lost) {
      const del = await run(`DELETE FROM inventory WHERE id = ?`, [r.inventory_id]);
      if (del.changes === 1) {
        await run(`UPDATE cards SET global_population = MAX(global_population - 1, 0) WHERE card_id = ?`, [r.card_id]);
      }
    }
    const done = await run(`DELETE FROM placements WHERE id = ?`, [r.id]);
    if (done.changes === 1) {
      const key = r.user_id + '|' + r.camp;
      perUser[key] = (perUser[key] || 0) + 1;
    }
  }
  for (const key of Object.keys(perUser)) {
    const [userId, camp] = key.split('|');
    const outcome = rec.winner === 'TIE' ? 'tie' : camp === rec.winner ? 'won' : 'lost';
    await run(
      `INSERT INTO battle_log (day, user_id, camp, outcome, cards) VALUES (?, ?, ?, ?, ?)`,
      [day, userId, camp, outcome, perUser[key]]
    );
  }
}

let resolving = false;
async function resolvePastDays() {
  if (resolving) return;
  resolving = true;
  try {
    const days = await all(`SELECT DISTINCT day FROM placements WHERE day < ? ORDER BY day`, [parisDay()]);
    for (const d of days) await resolveDay(d.day);
  } catch (e) {
    console.error('Résolution du combat :', e);
  } finally {
    resolving = false;
  }
}
setInterval(resolvePastDays, 60 * 1000);
setTimeout(resolvePastDays, 5000);

// Poser des cartes dans un camp
app.post('/api/battle/place', auth, async (req, res) => {
  try {
    const userId = req.userId;
    const camp = String(req.body.camp || '').toUpperCase();
    const cardId = parseInt(req.body.cardId, 10);
    const count = req.body.count === undefined ? 1 : parseInt(req.body.count, 10);

    if (!CAMPS.includes(camp)) return res.status(400).json({ success: false, error: "Invalid camp" });
    if (!Number.isInteger(cardId) || cardId < 0 || cardId > 9) return res.status(400).json({ success: false, error: "Invalid card" });
    if (!Number.isInteger(count) || count < 1 || count > MAX_PLACED_PER_DAY) return res.status(400).json({ success: false, error: "Invalid amount" });

    const day = parisDay();
    const mine = await all(
      `SELECT camp, COUNT(*) AS n FROM placements WHERE user_id = ? AND day = ? GROUP BY camp`,
      [userId, day]
    );
    const inOther = mine.filter((r) => r.camp !== camp).reduce((s, r) => s + r.n, 0);
    if (inOther > 0) {
      return res.status(400).json({ success: false, error: "You already joined the other camp today" });
    }
    const placedToday = mine.filter((r) => r.camp === camp).reduce((s, r) => s + r.n, 0);
    if (placedToday + count > MAX_PLACED_PER_DAY) {
      return res.status(400).json({ success: false, error: `Daily limit reached (${MAX_PLACED_PER_DAY} cards)` });
    }

    const free = await all(
      `SELECT i.id FROM inventory i
       LEFT JOIN placements p ON p.inventory_id = i.id
       WHERE i.user_id = ? AND i.card_id = ? AND p.id IS NULL
       LIMIT ?`,
      [userId, cardId, count]
    );
    if (free.length < count) {
      return res.status(400).json({ success: false, error: "Not enough free copies of this card" });
    }

    for (const row of free) {
      await run(
        `INSERT INTO placements (user_id, inventory_id, card_id, camp, day) VALUES (?, ?, ?, ?, ?)`,
        [userId, row.id, cardId, camp, day]
      );
    }
    res.json({
      success: true,
      camp,
      placedToday: placedToday + count,
      remainingToday: MAX_PLACED_PER_DAY - placedToday - count
    });
  } catch (e) {
    console.error(e);
    if (e && e.code === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ success: false, error: "Please try again" });
    }
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// État du combat : mon camp du jour, totaux des 2 camps, temps restant, dernier résultat
app.post('/api/battle/status', auth, async (req, res) => {
  try {
    await resolvePastDays();
    const userId = req.userId;
    const day = parisDay();

    const sums = await all(
      `SELECT p.camp AS camp, SUM(c.power) AS total
       FROM placements p JOIN cards c ON c.card_id = p.card_id
       WHERE p.day = ? GROUP BY p.camp`,
      [day]
    );
    const total = { A: 0, B: 0 };
    sums.forEach((s) => { total[s.camp] = s.total; });

    const mine = await all(
      `SELECT camp, COUNT(*) AS n FROM placements WHERE user_id = ? AND day = ? GROUP BY camp`,
      [userId, day]
    );
    const last = await get(
      `SELECT day, camp, outcome, cards FROM battle_log WHERE user_id = ? ORDER BY id DESC LIMIT 1`,
      [userId]
    );

    res.json({
      success: true,
      day,
      maxPerDay: MAX_PLACED_PER_DAY,
      myCamp: mine.length ? mine[0].camp : "",
      placedToday: mine.length ? mine[0].n : 0,
      totalA: total.A,
      totalB: total.B,
      secondsToResolution: secondsToParisMidnight(),
      lastResult: last || { day: "", camp: "", outcome: "", cards: 0 }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ---------------------------------------------------------------------------
// Route de test : désactivée par défaut.
// Pour l'activer, ajoutez la variable ENABLE_DEV_ROUTES=1 dans Railway (onglet Variables).
// ---------------------------------------------------------------------------
if (process.env.ENABLE_DEV_ROUTES === '1') {
  console.log("⚠️ Routes de développement activées");
  app.get('/api/dev/reset/:nickname', async (req, res) => {
    try {
      const result = await run(
        `UPDATE users SET coins = 1000 WHERE id = ?`,
        [String(req.params.nickname).toLowerCase()]
      );
      if (result.changes === 0) {
        return res.status(404).json({ success: false, error: "Player not found" });
      }
      res.json({ success: true, coins: 1000 });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
}

// Requête mal formée (JSON invalide, etc.)
app.use((err, req, res, next) => {
  res.status(400).json({ success: false, error: "Invalid request" });
});

// Lancement du serveur sur le port dynamique de Railway ou 3000 en local
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur Card Conquest lancé sur le port ${PORT}`);
});
