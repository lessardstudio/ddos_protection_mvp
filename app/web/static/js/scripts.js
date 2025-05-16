let trafficChart = null;
let map = null;

// Инициализация карты
function initMap() {
    map = L.map('map').setView([0, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors'
    }).addTo(map);
}

// Инициализация графика
function initTrafficChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Normal Traffic',
                    borderColor: 'rgb(75, 192, 192)',
                    data: []
                },
                {
                    label: 'Attack Traffic',
                    borderColor: 'rgb(255, 99, 132)',
                    data: []
                },
                {
                    label: 'Blocked Traffic',
                    borderColor: 'rgb(153, 102, 255)',
                    data: []
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Обновление статистики
function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            if (trafficChart) {
                // Добавляем новые данные
                const timestamp = new Date().toLocaleTimeString();
                trafficChart.data.labels.push(timestamp);
                trafficChart.data.datasets[0].data.push(data.generator.normal);
                trafficChart.data.datasets[1].data.push(data.generator.attack);
                trafficChart.data.datasets[2].data.push(data.generator.blocked);
                
                // Ограничиваем количество точек на графике
                if (trafficChart.data.labels.length > 20) {
                    trafficChart.data.labels.shift();
                    trafficChart.data.datasets[0].data.shift();
                    trafficChart.data.datasets[1].data.shift();
                    trafficChart.data.datasets[2].data.shift();
                }
                
                trafficChart.update();
                console.log('Updating chart with normal:', data.generator.normal, 
                          'attack:', data.generator.attack, 
                          'blocked:', data.generator.blocked);
            }
        })
        .catch(error => {
            console.error('Error fetching stats:', error);
            showAlert('Error updating statistics', 'error');
        });
}

// Управление трафиком
function controlTraffic(action, type) {
    const url = action === 'stop' ? '/api/traffic/stop' : `/api/traffic/start?mode=${type}`;
    fetch(url, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Traffic control response:', data);
        if (data.status === 'started' || data.status === 'success') {
            showAlert(`${type} traffic ${action}ed successfully`, 'success');
        } else {
            showAlert('Failed to control traffic', 'error');
        }
    })
    .catch(error => {
        console.error('Error controlling traffic:', error);
        showAlert('Error controlling traffic', 'error');
    });
}

// Блокировка IP
function blockIp() {
    const ipInput = document.getElementById('ipInput');
    const ip = ipInput.value.trim();
    
    if (ip) {
        fetch('/api/block', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip })
        })
        .then(response => response.json())
        .then(data => {
            console.log('IP block response:', data);
            if (data.status === 'success') {
                showAlert(`IP ${ip} blocked successfully`, 'success');
                ipInput.value = '';
                updateIpLists();
            } else {
                showAlert('Failed to block IP', 'error');
            }
        })
        .catch(error => {
            console.error('Error blocking IP:', error);
            showAlert('Error blocking IP', 'error');
        });
    }
}

// Обновление списков IP
function updateIpLists() {
    fetch('/api/ip_lists')
        .then(response => response.json())
        .then(data => {
            const ipListsDiv = document.getElementById('ipLists');
            ipListsDiv.innerHTML = `
                <h3>Blocked IPs</h3>
                <ul>${data.permanent_ban.map(ip => `<li>${ip}</li>`).join('')}</ul>
                <h3>Temporary Blocked IPs</h3>
                <ul>${data.temp_ban.map(ip => `<li>${ip}</li>`).join('')}</ul>
                <h3>Suspicious IPs</h3>
                <ul>${data.suspicious.map(ip => `<li>${ip}</li>`).join('')}</ul>
            `;
        })
        .catch(error => {
            console.error('Error fetching IP lists:', error);
            showAlert('Error fetching IP lists', 'error');
        });
}

// Показ уведомлений
function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : 'success'}`;
    alertDiv.textContent = message;
    document.body.appendChild(alertDiv);
    setTimeout(() => alertDiv.remove(), 3000);
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    initMap();
    initTrafficChart();
    updateStats();
    updateIpLists();
    
    // Обновление данных каждые 5 секунд
    setInterval(() => {
        updateStats();
        updateIpLists();
    }, 5000);
}); 