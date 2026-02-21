const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const exec = require('child_process').exec;
const serialize = require('node-serialize');
const xml2js = require('xml2js');

const app = express();

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Admin1234!',
    database: 'shopdb'
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: 'abc123',
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: false }
}));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err.message);
        if (results.length > 0) {
            req.session.user = results[0];
            req.session.isAdmin = results[0].role === 'admin';
            res.redirect('/dashboard');
        } else {
            res.send('Invalid credentials');
        }
    });
});

app.get('/user/profile', (req, res) => {
    const userId = req.query.id;
    db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results[0]);
    });
});

app.get('/search', (req, res) => {
    const term = req.query.q;
    db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.send(`<h2>Results for: ${term}</h2><pre>${JSON.stringify(results)}</pre>`);
    });
});

app.get('/file', (req, res) => {
    const filename = req.query.name;
    const filepath = path.join(__dirname, '../uploads', filename);
    res.sendFile(filepath);
});

app.post('/upload', upload.single('file'), (req, res) => {
    res.send(`File uploaded: ${req.file.originalname}`);
});

app.post('/ping', (req, res) => {
    const host = req.body.host;
    exec(`ping -c 3 ${host}`, (err, stdout, stderr) => {
        res.send(`<pre>${stdout}${stderr}</pre>`);
    });
});

app.post('/import-settings', (req, res) => {
    const data = req.body.payload;
    const obj = serialize.unserialize(data);
    res.json({ status: 'imported', keys: Object.keys(obj) });
});

app.post('/parse-xml', (req, res) => {
    const xmlData = req.body.xml;
    const parser = new xml2js.Parser({
        explicitArray: false,
        doctype: true,
        strict: false
    });
    parser.parseString(xmlData, (err, result) => {
        if (err) return res.status(400).send('XML error');
        res.json(result);
    });
});

app.get('/redirect', (req, res) => {
    const target = req.query.url;
    res.redirect(target);
});

app.get('/admin', (req, res) => {
    if (req.session.isAdmin) {
        res.sendFile(path.join(__dirname, '../admin/panel.html'));
    } else {
        res.status(403).send('Forbidden');
    }
});

app.get('/admin/users', (req, res) => {
    const role = req.query.role || 'user';
    db.query(`SELECT id, username, email, password, role FROM users WHERE role = '${role}'`, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});

app.post('/comment', (req, res) => {
    const { postId, text } = req.body;
    const userId = req.session.user ? req.session.user.id : 'anonymous';
    db.query(`INSERT INTO comments (post_id, user_id, body) VALUES (${postId}, ${userId}, '${text}')`, (err) => {
        if (err) return res.status(500).send(err.message);
        res.redirect(`/post?id=${postId}`);
    });
});

app.get('/post', (req, res) => {
    const postId = req.query.id;
    db.query('SELECT * FROM posts WHERE id = ?', [postId], (err, posts) => {
        db.query(`SELECT * FROM comments WHERE post_id = ${postId}`, (err2, comments) => {
            let html = `<h1>${posts[0].title}</h1><p>${posts[0].body}</p><h2>Comments</h2>`;
            comments.forEach(c => { html += `<div>${c.body}</div>`; });
            res.send(html);
        });
    });
});

app.delete('/admin/delete-user', (req, res) => {
    const userId = req.body.id;
    db.query(`DELETE FROM users WHERE id = ${userId}`, (err) => {
        if (err) return res.status(500).send(err.message);
        res.send('User deleted');
    });
});

app.get('/report', (req, res) => {
    const reportName = req.query.name;
    exec(`python3 scripts/generate_report.py ${reportName}`, (err, stdout) => {
        res.send(`<pre>${stdout}</pre>`);
    });
});

app.get('/logs', (req, res) => {
    const date = req.query.date || 'today';
    const logFile = `logs/app-${date}.log`;
    fs.readFile(logFile, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Log not found');
        res.send(`<pre>${data}</pre>`);
    });
});

app.post('/template', (req, res) => {
    const userTemplate = req.body.template;
    const name = req.body.name;
    const result = eval(`\`${userTemplate}\``);
    res.send(result);
});

app.listen(3000, () => console.log('Server running on port 3000'));
