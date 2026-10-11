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

  const stmt = db.prepare(`INSERT OR IGNORE INTO cards (card_id, name, power, global_population) VALUES (?, ?, ?, 0)`);
  for (let i = 0; i <= 9; i++) {
    const powerList = [10, 15, 25, 40, 50, 65, 80, 100, 120, 150];
    stmt.run(i, `Carte #${i + 1}`, powerList[i]);
  }
  stmt.finalize();
});

// Route d'initialisation / récupération de profil
app.get('/api/user/:userId', (req, res) => {
  const { userId } = req.params;

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
    if (!user) {
      db.run(`INSERT INTO users (id, coins) VALUES (?, 1000)`, [userId], () => {
        return res.json({ success: true, coins: 1000 });
      });
    } else {
      return res.json({ success: true, coins: user.coins });
    }
  });
});

// Route principale : Achat d'un Booster (5 Cartes) en GET
app.get('/api/packs/buy', (req, res) => {
  const userId = req.query.userId || 'player_123';
  const PACK_COST = 100;

  db.get(`SELECT coins FROM users WHERE id = ?`, [userId], (err, user) => {
    if (!user) {
      db.run(`INSERT INTO users (id, coins) VALUES (?, 1000)`, [userId], () => {
        processPurchase(userId, 1000, res, PACK_COST);
      });
    } else {
      processPurchase(userId, user.coins, res, PACK_COST);
    }
  });
});

// Fonction utilitaire pour gérer la transaction d'achat
function processPurchase(userId, currentCoins, res, PACK_COST) {
  if (currentCoins < PACK_COST) {
    return res.status(400).json({ success: false, error: "Pièces insuffisantes !" });
  }

  const newCoins = currentCoins - PACK_COST;
  db.run(`UPDATE users SET coins = ? WHERE id = ?`, [newCoins, userId]);

  const drawnCards = [];
  let completed = 0;

  for (let i = 0; i < 5; i++) {
    const randomCardId = Math.floor(Math.random() * 10);

    db.run(`UPDATE cards SET global_population = global_population + 1 WHERE card_id = ?`, [randomCardId], function(err) {
      db.run(`INSERT INTO inventory (user_id, card_id) VALUES (?, ?)`, [userId, randomCardId]);

      db.get(`SELECT * FROM cards WHERE card_id = ?`, [randomCardId], (err, cardData) => {
        drawnCards.push({
          animationIndex: cardData.card_id,
          name: cardData.name,
          power: cardData.power,
          globalPopulation: cardData.global_population
        });

        completed++;
        if (completed === 5) {
          return res.json({
            success: true,
            remainingCoins: newCoins,
            drawnCards: drawnCards
          });
        }
      });
    });
  }
}

// Lancement du serveur sur le port dynamique de Railway ou 3000 en local
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur Card Conquest lancé sur le port ${PORT}`);
});