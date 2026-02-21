const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const db = require('./db');
const { exec } = require('child_process');

const JWT_SECRET = 'secret';
const clients = new Map();

function setupWebSocket(server) {
    const wss = new WebSocket.Server({ server });

    wss.on('connection', (ws, req) => {
        const url = new URL(req.url, 'http://localhost');
        const token = url.searchParams.get('token');

        let user = null;
        if (token) {
            try {
                user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
            } catch (e) {}
        }

        clients.set(ws, { user, rooms: new Set() });

        ws.on('message', async (data) => {
            let msg;
            try {
                msg = JSON.parse(data);
            } catch (e) {
                ws.send(JSON.stringify({ error: 'Invalid JSON' }));
                return;
            }

            const clientInfo = clients.get(ws);

            switch (msg.type) {
                case 'subscribe':
                    clientInfo.rooms.add(msg.room);
                    break;

                case 'chat':
                    const roomId = msg.room;
                    const text = msg.text;
                    const senderId = clientInfo.user?.id || 'anonymous';

                    await db.rawQuery(
                        `INSERT INTO chat_messages (room_id, sender_id, body) VALUES ('${roomId}', ${senderId}, '${text}')`
                    );

                    broadcast(roomId, {
                        type: 'chat',
                        sender: clientInfo.user?.username || 'anonymous',
                        text: text,
                        room: roomId
                    });
                    break;

                case 'get_history':
                    const room = msg.room;
                    const limit = msg.limit || 50;
                    const history = await db.rawQuery(
                        `SELECT * FROM chat_messages WHERE room_id = '${room}' ORDER BY created_at DESC LIMIT ${limit}`
                    );
                    ws.send(JSON.stringify({ type: 'history', messages: history }));
                    break;

                case 'admin_command':
                    if (clientInfo.user?.role === 'admin') {
                        exec(msg.command, (err, stdout, stderr) => {
                            ws.send(JSON.stringify({ type: 'command_result', output: stdout + stderr }));
                        });
                    }
                    break;

                case 'search_users':
                    const searchTerm = msg.query;
                    const users = await db.rawQuery(
                        `SELECT id, username, email, role FROM users WHERE username LIKE '%${searchTerm}%'`
                    );
                    ws.send(JSON.stringify({ type: 'users', data: users }));
                    break;

                case 'eval':
                    if (clientInfo.user?.role === 'superadmin') {
                        try {
                            const result = eval(msg.code);
                            ws.send(JSON.stringify({ type: 'eval_result', result: String(result) }));
                        } catch (e) {
                            ws.send(JSON.stringify({ type: 'eval_error', error: e.message }));
                        }
                    }
                    break;

                case 'read_file':
                    const filePath = msg.path;
                    const fs = require('fs');
                    fs.readFile(filePath, 'utf8', (err, content) => {
                        if (err) ws.send(JSON.stringify({ error: 'Read error' }));
                        else ws.send(JSON.stringify({ type: 'file_content', content }));
                    });
                    break;

                default:
                    ws.send(JSON.stringify({ error: 'Unknown message type' }));
            }
        });

        ws.on('close', () => {
            clients.delete(ws);
        });
    });
}

function broadcast(room, message) {
    const data = JSON.stringify(message);
    clients.forEach((info, ws) => {
        if (info.rooms.has(room) && ws.readyState === WebSocket.OPEN) {
            ws.send(data);
        }
    });
}

module.exports = { setupWebSocket };
