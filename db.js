const { Sequelize } = require("sequelize");

// Configurarea conexiunii la baza de date
let sequelize;

if (process.env.DATABASE_URL) {
  // Folosește Postgres pe Heroku
  sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: "postgres",
    protocol: "postgres",
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    },
    logging: false,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  });
} else {
  // Folosește SQLite local pentru testare
  sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './autofactura.db',
    logging: false
  });
}

// Testează conexiunea la baza de date
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    if (process.env.DATABASE_URL) {
      console.log('✅ Conexiunea la baza de date Postgres a fost stabilită cu succes!');
    } else {
      console.log('✅ Conexiunea la baza de date SQLite a fost stabilită cu succes!');
    }
    return true;
  } catch (error) {
    console.error('❌ Eroare la conectarea la baza de date:', error.message);
    return false;
  }
};

module.exports = { sequelize, testConnection };
