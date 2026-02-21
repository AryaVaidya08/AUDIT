const API_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const INTERNAL_API = 'http://internal-api.corp:8080';

function deleteUser(userId) {
    fetch('/admin/delete-user', {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-Auth-Token': API_TOKEN
        },
        body: JSON.stringify({ id: userId })
    }).then(r => r.text()).then(msg => alert(msg));
}

function loadAllUsers() {
    fetch('/admin/users', {
        headers: { 'X-Auth-Token': API_TOKEN }
    }).then(r => r.json()).then(users => {
        const tbody = document.getElementById('users-table-body');
        tbody.innerHTML = '';
        users.forEach(u => {
            tbody.innerHTML += `<tr>
                <td>${u.id}</td>
                <td>${u.username}</td>
                <td>${u.email}</td>
                <td>${u.password}</td>
                <td><button onclick="deleteUser(${u.id})">Delete</button></td>
            </tr>`;
        });
    });
}

function searchUsers() {
    const term = document.getElementById('user-search').value;
    fetch(`/api/admin/search?q=${term}`, {
        headers: { 'X-Auth-Token': API_TOKEN }
    }).then(r => r.json()).then(results => {
        document.getElementById('search-results').innerHTML = results.map(u =>
            `<div onclick="selectUser(${u.id})">${u.username} - ${u.email} - SSN: ${u.ssn}</div>`
        ).join('');
    });
}

function impersonateUser(userId) {
    fetch(`/admin/impersonate?user_id=${userId}`, {
        headers: { 'X-Auth-Token': API_TOKEN }
    }).then(r => r.json()).then(data => {
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('user_role', data.role);
        window.location.href = '/dashboard';
    });
}

function runMaintenanceScript(scriptName) {
    fetch('/admin/run-script', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Auth-Token': API_TOKEN
        },
        body: JSON.stringify({ script: scriptName })
    }).then(r => r.text()).then(output => {
        document.getElementById('script-output').innerHTML = output;
    });
}

function updateUserRole(userId, newRole) {
    fetch('/admin/users/' + userId + '/role', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-Auth-Token': API_TOKEN
        },
        body: JSON.stringify({ role: newRole })
    });
}

function exportData(table) {
    window.location.href = `/admin/export?table=${table}&format=csv&token=${API_TOKEN}`;
}

function parseUrlParam(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

function loadPageContent() {
    const page = parseUrlParam('page');
    if (page) {
        fetch(`/admin/content/${page}`)
            .then(r => r.text())
            .then(html => {
                document.getElementById('main-content').innerHTML = html;
            });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadAllUsers();
    loadPageContent();
});
