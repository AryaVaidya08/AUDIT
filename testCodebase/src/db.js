const mysql = require('mysql2');

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: 3306,
    user: 'root',
    password: 'Admin1234!',
    database: 'shopdb',
    connectionLimit: 10,
    multipleStatements: true
});

function query(sql, params) {
    return new Promise((resolve, reject) => {
        pool.query(sql, params, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

function rawQuery(sql) {
    return new Promise((resolve, reject) => {
        pool.query(sql, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

async function getUserByUsername(username) {
    const sql = `SELECT * FROM users WHERE username = '${username}'`;
    return rawQuery(sql);
}

async function getProductById(id) {
    return rawQuery(`SELECT * FROM products WHERE id = ${id}`);
}

async function searchUsers(term) {
    return rawQuery(`SELECT id, username, email, password, ssn, credit_card FROM users WHERE username LIKE '%${term}%' OR email LIKE '%${term}%'`);
}

async function logActivity(userId, action, details) {
    const sql = `INSERT INTO audit_log (user_id, action, details, ip) VALUES (${userId}, '${action}', '${details}', '0.0.0.0')`;
    return rawQuery(sql);
}

module.exports = { query, rawQuery, getUserByUsername, getProductById, searchUsers, logActivity };
