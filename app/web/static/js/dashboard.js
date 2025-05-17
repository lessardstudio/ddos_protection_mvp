document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const startNormalBtn = document.getElementById('start-normal');
    const startAttackBtn = document.getElementById('start-attack');
    const startCombinedBtn = document.getElementById('start-combined');
    const stopBtn = document.getElementById('stop-traffic');
    const stopNormalBtn = document.getElementById('stop-normal');
    const stopAttackBtn = document.getElementById('stop-attack');
    const blockIpBtn = document.getElementById('block-ip');
    const alertBox = document.getElementById('alert-box');
    const detectionStatus = document.getElementById('detection-status');
    const blockedIpsCount = document.getElementById('blocked-ips');
    const normalCount = document.getElementById('normal-count');
    const attackCount = document.getElementById('attack-count');
    const blockedCount = document.getElementById('blocked-count');
    const normalBar = document.getElementById('normal-bar');
    const attackBar = document.getElementById('attack-bar');
    const blockedBar = document.getElementById('blocked-bar');
    const permanentBanList = document.getElementById('permanent-ban-list');
    const tempBanList = document.getElementById('temp-ban-list');
    const suspiciousList = document.getElementById('suspicious-list');
    const ipInput = document.getElementById('ip-input');
    const blockPermanentBtn = document.getElementById('block-permanent-btn');
    const blockTempBtn = document.getElementById('block-temp-btn');
    const markSuspiciousBtn = document.getElementById('mark-suspicious-btn');

    // Chart initialization
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    const trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [
                {
                    label: 'Normal Traffic',
                    data: Array(20).fill(0),
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    tension: 0.1
                },
                {
                    label: 'Attack Traffic (Unblocked)',
                    data: Array(20).fill(0),
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.1
                },
                {
                    label: 'Blocked Attack Traffic',
                    data: Array(20).fill(0),
                    borderColor: '#060606',
                    backgroundColor: 'rgba(150, 36, 48, 0.1)',
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Packets/sec'
                    }
                }
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return context[0].label;
                        },
                        label: function(context) {
                            const label = context.dataset.label || '';
                            const value = context.parsed.y;
                            return `${label}: ${value}`;
                        },
                        footer: function(context) {
                            if (context.length > 1) {
                                const attackValue = context[1].parsed.y || 0;
                                const blockedValue = context[2].parsed.y || 0;
                                const totalAttack = attackValue + blockedValue;
                                return `Total Attack Traffic: ${totalAttack}`;
                            }
                            return null;
                        }
                    }
                },
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        color: '#333',
                        font: {
                            weight: 'bold'
                        },
                        generateLabels: function(chart) {
                            const datasets = chart.data.datasets;
                            return datasets.map(function(dataset, i) {
                                return {
                                    text: dataset.label,
                                    fillStyle: dataset.borderColor,
                                    strokeStyle: dataset.borderColor,
                                    lineWidth: 1,
                                    hidden: !chart.isDatasetVisible(i),
                                    index: i
                                };
                            });
                        }
                    }
                }
            }
        }
    });

    // Update data every second
    setInterval(updateDashboard, 1000);
    setInterval(updateIpLists, 5000);

    // Event listeners
    startNormalBtn.addEventListener('click', () => sendTrafficCommand('start', 'normal'));
    startAttackBtn.addEventListener('click', () => sendTrafficCommand('start', 'attack'));
    startCombinedBtn.addEventListener('click', () => sendTrafficCommand('start', 'combined'));
    stopBtn.addEventListener('click', () => sendTrafficCommand('stop'));
    stopNormalBtn.addEventListener('click', () => sendTrafficCommand('stop_normal'));
    stopAttackBtn.addEventListener('click', () => sendTrafficCommand('stop_attack'));
    blockIpBtn.addEventListener('click', blockIp);
    blockPermanentBtn.addEventListener('click', () => manageIp('block_permanent'));
    blockTempBtn.addEventListener('click', () => manageIp('block_temp'));
    markSuspiciousBtn.addEventListener('click', () => manageIp('mark_suspicious'));

    async function updateDashboard() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();
            
            // Update status
            const isAttack = data.detection.is_attack;
            let statusText = 'НОРМАЛЬНЫЙ';
            let statusClass = 'alert alert-success';
            
            if (isAttack) {
                statusText = 'АТАКА ОБНАРУЖЕНА';
                statusClass = 'alert alert-danger';
            }
            
            // Если мы в комбинированном режиме, покажем это
            if (data.detection.mode === 'combined') {
                statusText += ' (КОМБИНИРОВАННЫЙ РЕЖИМ)';
            }
            
            detectionStatus.textContent = statusText;
            detectionStatus.className = statusClass;
            blockedIpsCount.textContent = data.detection.blocked_ips_count;
            
            // Update traffic bars
            normalCount.textContent = `${data.generator.normal} pps`;
            attackCount.textContent = `${data.generator.attack} pps`;
            blockedCount.textContent = `${data.generator.blocked} pps`;
            
            // Шкалы для полос прогресса (адаптивные)
            const normalMax = Math.max(100, data.generator.normal * 1.2);
            const attackMax = Math.max(100, data.generator.attack * 1.2);
            const blockedMax = Math.max(100, data.generator.blocked * 1.2);
            
            normalBar.style.width = `${(data.generator.normal / normalMax) * 100}%`;
            attackBar.style.width = `${(data.generator.attack / attackMax) * 100}%`;
            blockedBar.style.width = `${(data.generator.blocked / blockedMax) * 100}%`;
            
            // Update chart
            updateChart(data);
            
            // Анализируем трафик для автоматической блокировки IP
            await analyzeTraffic(data);
        } catch (error) {
            console.error('Dashboard update error:', error);
        }
    }

    function updateChart(data) {
        // Добавляем метку времени
        const now = new Date();
        const timeString = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
        
        // Выводим информацию о текущих значениях для отладки
        console.log('Updating chart with normal:', data.generator.normal, 
                  'unblocked attack:', data.generator.attack, 
                  'blocked:', data.generator.blocked);
        
        // Ограничиваем количество точек данных на графике (показываем только последние 20)
        if (trafficChart.data.labels.length > 20) {
            trafficChart.data.labels.shift();
            trafficChart.data.datasets.forEach(dataset => {
                dataset.data.shift();
            });
        }
        
        // Добавляем новые данные в график
        trafficChart.data.labels.push(timeString);
        trafficChart.data.datasets[0].data.push(data.generator.normal);
        trafficChart.data.datasets[1].data.push(data.generator.attack);
        trafficChart.data.datasets[2].data.push(data.generator.blocked);
        
        // Рассчитываем максимальное значение для оси Y
        let maxValue = 0;
        trafficChart.data.datasets.forEach(dataset => {
            const datasetMax = Math.max(...dataset.data.filter(value => !isNaN(value)));
            if (datasetMax > maxValue) maxValue = datasetMax;
        });
        
        // Добавляем запас в 20% сверху для лучшей визуализации
        const yAxisMax = Math.max(100, Math.ceil(maxValue * 1.2));
        
        // Обновляем максимум оси Y только если он изменился более чем на 10%
        const currentMax = trafficChart.options.scales.y.max || 100;
        if (Math.abs(currentMax - yAxisMax) / currentMax > 0.1) {
            trafficChart.options.scales.y.max = yAxisMax;
        }
        
        // Обновляем график
        trafficChart.update('none'); // Используем 'none' для более плавной анимации
    }

    async function sendTrafficCommand(action, mode = null) {
        let url = `/api/traffic/${action}`;
        if (mode && action === 'start') {
            url += `?mode=${mode}`;
        }
        
        try {
            const response = await fetch(url, { method: 'POST' });
            const result = await response.json();
            
            let message = '';
            if (action === 'start') {
                if (mode === 'normal') {
                    message = 'Нормальный трафик запущен';
                } else if (mode === 'attack') {
                    message = 'Атакующий трафик запущен';
                } else if (mode === 'combined') {
                    message = 'Комбинированный трафик запущен (норм + атака)';
                }
            } else if (action === 'stop') {
                message = 'Генерация всех типов трафика остановлена';
            } else if (action === 'stop_normal') {
                message = 'Генерация нормального трафика остановлена';
            } else if (action === 'stop_attack') {
                message = 'Генерация атакующего трафика остановлена';
            }
            
            showAlert(message, 'success');
        } catch (error) {
            showAlert('Ошибка при отправке команды', 'danger');
            console.error('Traffic control error:', error);
        }
    }

    async function blockIp() {
        const ip = prompt('Enter IP to block:');
        if (ip) {
            try {
                await fetch('/api/block', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip })
                });
                showAlert(`IP ${ip} blocked`, 'success');
            } catch (error) {
                showAlert('Block failed', 'danger');
                console.error('Block error:', error);
            }
        }
    }

    function showAlert(message, type) {
        alertBox.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
        setTimeout(() => alertBox.innerHTML = '', 3000);
    }

    async function updateIpLists() {
        try {
            const response = await fetch('/api/ip_lists');
            const data = await response.json();
            
            // Update permanent ban list
            permanentBanList.innerHTML = data.permanent_ban.length > 0 
                ? data.permanent_ban.map(ip => `<li class="list-group-item">${ip}</li>`).join('')
                : '<li class="list-group-item">Пока нет заблокированных IP</li>';
            
            // Update temporary ban list
            tempBanList.innerHTML = data.temp_ban.length > 0 
                ? data.temp_ban.map(ip => `<li class="list-group-item">${ip}</li>`).join('')
                : '<li class="list-group-item">Пока нет временно заблокированных IP</li>';
            
            // Update suspicious list
            suspiciousList.innerHTML = data.suspicious.length > 0 
                ? data.suspicious.map(ip => `<li class="list-group-item">${ip}</li>`).join('')
                : '<li class="list-group-item">Пока нет подозрительных IP</li>';
        } catch (error) {
            console.error('IP lists update error:', error);
        }
    }

    async function manageIp(action) {
        console.log('manageIp called with action:', action);
        const ip = ipInput.value.trim();
        if (!ip) {
            showAlert('Введите IP-адрес', 'danger');
            console.log('No IP entered');
            return;
        }
        // Простая проверка формата IP-адреса
        const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            showAlert('Некорректный формат IP-адреса', 'danger');
            console.log('Invalid IP format:', ip);
            return;
        }
        try {
            const endpoint = action === 'block_permanent' ? '/api/block_permanent' : 
                            action === 'block_temp' ? '/api/block_temp' : '/api/mark_suspicious';
            console.log('Sending request to:', endpoint, 'with IP:', ip);
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            console.log('Response received:', response.status, response.statusText);
            const result = await response.json();
            if (result.status === 'success') {
                showAlert(`IP ${ip} обработан как ${result.type}`, 'success');
                ipInput.value = '';
                updateIpLists();
            } else {
                showAlert('Действие не выполнено', 'danger');
                console.log('Action failed with result:', result);
            }
        } catch (error) {
            showAlert('Ошибка при выполнении действия', 'danger');
            console.error('IP management error:', error);
        }
    }

    async function analyzeTraffic(data) {
        try {
            // Пример данных для анализа (можно настроить на основе реальных данных)
            const features = [data.generator.normal, data.generator.attack, 0];
            const response = await fetch('/api/analyze_traffic', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ features })
            });
            const result = await response.json();
            if (result.is_attack) {
                //showAlert('Атака обнаружена! IP-адреса заблокированы.', 'danger');
                updateIpLists(); // Обновляем таблицы сразу после обнаружения атаки
            } else if (result.error) {
                console.error('Traffic analysis server error:', result.error);
            }
        } catch (error) {
            console.error('Traffic analysis error:', error);
        }
    }
});