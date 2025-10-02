const { Sequelize } = require("sequelize");

// Configurarea conexiunii la baza de date
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: "postgres",
  protocol: "postgres",
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  },
  logging: false, // Dezactivează log-urile SQL pentru producție
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});

// Testează conexiunea la baza de date
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Conexiunea la baza de date Postgres a fost stabilită cu succes!');
    return true;
  } catch (error) {
    console.error('❌ Eroare la conectarea la baza de date:', error.message);
    return false;
  }
};

module.exports = { sequelize, testConnection };
