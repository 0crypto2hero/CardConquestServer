const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
 
const app = express();
app.use(cors());
app.use(express.json());
 
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
 
// Initialisation des tables et du joueur par défaut
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      coins INTEGER DEFAULT 1000
    )
  `, () => {
    db.run(`INSERT OR IGNORE INTO users (id, coins) VALUES ('player_123', 1000)`);
  });
 
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
 
// Route d'initialisation / récupération de profil
app.get('/api/user/:userId', async (req, res) => {
  try {
    await run(`INSERT OR IGNORE INTO users (id, coins) VALUES (?, 1000)`, [req.params.userId]);
    const user = await get(`SELECT coins FROM users WHERE id = ?`, [req.params.userId]);
    res.json({ success: true, coins: user.coins });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Erreur serveur" });
  }
});
 
// Route principale : Achat d'un Booster (5 Cartes) en GET
app.get('/api/packs/buy', async (req, res) => {
  const userId = req.query.userId || 'player_123';
  const PACK_COST = 100;
 
  try {
    // Crée le joueur s'il n'existe pas
    await run(`INSERT OR IGNORE INTO users (id, coins) VALUES (?, 1000)`, [userId]);
 
    // Débit atomique : ne passe que s'il reste assez de pièces
    const debit = await run(
      `UPDATE users SET coins = coins - ? WHERE id = ? AND coins >= ?`,
      [PACK_COST, userId, PACK_COST]
    );
    if (debit.changes === 0) {
      return res.status(400).json({ success: false, error: "Pièces insuffisantes !" });
    }
 
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
    res.status(500).json({ success: false, error: "Erreur serveur" });
  }
});
 
// ⚠️ Route de test uniquement : à supprimer avant la mise en ligne finale
app.get('/api/dev/reset/:userId', async (req, res) => {
  try {
    await run(`INSERT OR IGNORE INTO users (id, coins) VALUES (?, 1000)`, [req.params.userId]);
    await run(`UPDATE users SET coins = 1000 WHERE id = ?`, [req.params.userId]);
    res.json({ success: true, coins: 1000 });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});
 
// Lancement du serveur sur le port dynamique de Railway ou 3000 en local
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur Card Conquest lancé sur le port ${PORT}`);
});
