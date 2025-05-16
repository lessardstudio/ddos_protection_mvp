function updateDashboard() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            console.log('Starting dashboard update...');
            // Update traffic chart
            const normalTraffic = data.generator.normal;
            const attackTraffic = data.generator.attack;
            const blockedTraffic = data.generator.blocked;
            if (trafficChart) {
                trafficChart.data.datasets[0].data = [normalTraffic, attackTraffic, blockedTraffic];
                trafficChart.update();
            } else {
                console.warn('trafficChart is not defined yet. Skipping chart update.');
            }
            
            document.getElementById('normalTraffic').textContent = normalTraffic + ' pps';
            document.getElementById('attackTraffic').textContent = attackTraffic + ' pps';
            document.getElementById('blocked-count').textContent = blockedTraffic + ' pps';
            
            // Update progress bars
            if (typeof updateProgressBar === 'function') {
                updateProgressBar('normal-bar', normalTraffic);
                updateProgressBar('attack-bar', attackTraffic);
                updateProgressBar('blocked-bar', blockedTraffic);
            } else {
                console.warn('updateProgressBar is not defined yet. Skipping progress bar update.');
            }
            
            // Update attack status
            const isAttack = data.detection.is_attack;
            document.getElementById('attackStatus').textContent = isAttack ? 'Attack Detected' : 'No Attack';
            document.getElementById('attackStatus').className = isAttack ? 'attack-detected' : 'no-attack';
            
            // Update blocked IPs count
            document.getElementById('blockedIps').textContent = data.detection.blocked_ips_count;
            
            // Временно отключаем analyzeTraffic для тестов
            // analyzeTraffic();
            console.log('analyzeTraffic temporarily disabled for testing.');
            console.log('Dashboard update completed.');
        })
        .catch(error => {
            console.error('Dashboard update error:', error);
        });
}

async function sendTrafficCommand(command) {
    try {
        const response = await fetch(`/api/traffic/${command}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log(`${command} response:`, data);
    } catch (error) {
        console.error('Traffic control error:', error);
    }
} 