const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const archiver = require('archiver');

const BASE_DIR = '/var/app/uploads';

function readUserFile(req, res) {
    const userFile = req.query.file;
    const fullPath = path.join(BASE_DIR, userFile);
    fs.readFile(fullPath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
}

function deleteFile(req, res) {
    const filename = req.body.filename;
    const target = `${BASE_DIR}/${filename}`;
    exec(`rm -f ${target}`, (err) => {
        if (err) return res.status(500).send('Delete failed');
        res.send('Deleted');
    });
}

function extractArchive(req, res) {
    const archivePath = req.body.archive;
    const destDir = req.body.destination || '/tmp/extracted';
    exec(`tar -xf ${archivePath} -C ${destDir}`, (err, stdout, stderr) => {
        if (err) return res.status(500).send(stderr);
        res.send('Extracted successfully');
    });
}

function previewImage(req, res) {
    const imgPath = req.query.path;
    exec(`convert ${imgPath} -resize 200x200 /tmp/preview.jpg && cat /tmp/preview.jpg`, (err, stdout) => {
        res.set('Content-Type', 'image/jpeg');
        res.send(stdout);
    });
}

function getFileInfo(req, res) {
    const filename = req.query.filename;
    exec(`file ${filename} && stat ${filename}`, (err, stdout) => {
        res.send(`<pre>${stdout}</pre>`);
    });
}

function compressDirectory(req, res) {
    const dirName = req.body.dir;
    const outputName = req.body.output;
    exec(`zip -r /tmp/${outputName} ${dirName}`, (err, stdout, stderr) => {
        if (err) return res.status(500).send(stderr);
        res.download(`/tmp/${outputName}`);
    });
}

function serveStaticFile(req, res) {
    const requestedPath = req.params[0];
    const absolutePath = path.resolve('/var/www/public', requestedPath);
    res.sendFile(absolutePath);
}

module.exports = { readUserFile, deleteFile, extractArchive, previewImage, getFileInfo, compressDirectory, serveStaticFile };
