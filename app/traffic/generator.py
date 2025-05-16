import time
import random
from threading import Thread
from scapy.all import IP, TCP, send
from app.utils.alerts import send_alert
import threading

class TrafficGenerator:
    def __init__(self, config, ip_manager=None):
        self.config = config.get('traffic', {})
        self.target_ip = self.config.get('target_ip', '127.0.0.1')  # Используем localhost, чтобы TrafficReceiver мог перехватывать пакеты
        self.normal_rate = self.config.get('normal_rate', 10)
        self.attack_rate = self.config.get('attack_rate', 500)
        self.is_running = False
        self.mode = 'normal'
        self.attack_mode = 'normal'
        self.normal_count = 0
        self.attack_count = 0
        self.ip_manager = ip_manager
        self.attack_thread = None
        self.normal_thread = None
        self.attack_modes = {
            'aggressive': {'rate': 2000, 'ip_count': 20},
            'smart': {'rate': 800, 'ip_count': 5},
            'normal': {'rate': 1200, 'ip_count': 10}
        }

    def generate_normal(self):
        while self.is_running:
            packet = IP(dst=self.target_ip)/TCP(dport=80)
            send(packet, verbose=0)
            self.normal_count += 1
            time.sleep(1.0 / self.normal_rate)

    def generate_attack(self):
        """Generate attack traffic"""
        try:
            if self.attack_mode == 'normal':
                return
            
            attack_config = self.attack_modes.get(self.attack_mode, self.attack_modes['normal'])
            rate = attack_config['rate']
            ip_count = attack_config['ip_count']
            
            # Debug logs
            send_alert(f"Generating attack traffic - Mode: {self.attack_mode}, Rate: {rate}, IP count: {ip_count}")
            
            while self.is_running:
                try:
                    # Generate attack packets
                    packets_sent = 0
                    for _ in range(rate):
                        if not self.is_running:
                            break
                        
                        # Get random IP that is not blocked
                        ip = None
                        for _ in range(10):  # Try up to 10 times to get unblocked IP
                            ip = self.ip_manager.get_random_ip()
                            if not self.ip_manager.is_ip_blocked(ip):
                                break
                        
                        if ip is None:
                            send_alert("No available unblocked IPs for attack")
                            continue
                        
                        # Create attack packet
                        packet = IP(dst=self.target_ip)/TCP(dport=80, flags="S")
                        packet.src = ip
                        
                        # Send packet
                        send(packet, verbose=0)
                        self.attack_count += 1
                        packets_sent += 1
                        
                    # Логируем отправленные пакеты
                    if packets_sent > 0:
                        send_alert(f"Sent {packets_sent} attack packets, total attack count: {self.attack_count}")
                    
                    time.sleep(1)  # Wait for 1 second
                    
                except Exception as e:
                    send_alert(f"Error in attack generation: {str(e)}")
                    time.sleep(1)
                
        except Exception as e:
            send_alert(f"Fatal error in attack generation: {str(e)}")
        finally:
            self.is_running = False

    def start(self, mode):
        """Запускает генерацию трафика в указанном режиме"""
        if self.is_running:
            return
        
        self.is_running = True
        self.mode = mode
        self.attack_mode = random.choice(['aggressive', 'smart', 'normal']) if mode == 'attack' else 'normal'
        send_alert(f"Starting traffic generation in {mode} mode with attack mode: {self.attack_mode}")
        
        if mode == 'attack':
            self.attack_thread = threading.Thread(target=self.generate_attack)
            self.attack_thread.daemon = True
            self.attack_thread.start()
        else:
            self.normal_thread = threading.Thread(target=self.generate_normal)
            self.normal_thread.daemon = True
            self.normal_thread.start()
        send_alert(f"Traffic generation started in {mode} mode")

    def stop(self):
        if self.is_running:
            self.is_running = False
            if self.attack_thread:
                self.attack_thread.join(timeout=2)
            if self.normal_thread:
                self.normal_thread.join(timeout=2)
            send_alert("Traffic generator stopped")

    def get_stats(self):
        """Возвращает текущую статистику по трафику"""
        # Вычисляем текущие значения pps для каждого типа трафика
        # Используем разницу между текущим и предыдущим значением счетчиков
        if not hasattr(self, '_last_stats_time'):
            self._last_stats_time = time.time()
            self._last_normal_count = self.normal_count
            self._last_attack_count = self.attack_count
            normal_pps = 0
            attack_pps = 0
        else:
            current_time = time.time()
            time_diff = current_time - self._last_stats_time
            
            if time_diff > 0:
                normal_pps = int((self.normal_count - self._last_normal_count) / time_diff)
                attack_pps = int((self.attack_count - self._last_attack_count) / time_diff)
                
                # Обновляем предыдущие значения
                self._last_stats_time = current_time
                self._last_normal_count = self.normal_count
                self._last_attack_count = self.attack_count
            else:
                normal_pps = 0
                attack_pps = 0
        
        # Оценка заблокированного трафика (приблизительно)
        blocked_pps = 0
        if self.ip_manager and self.mode == 'attack':
            blocked_ips = self.ip_manager.get_all_blocked_ips()
            if blocked_ips:
                # Считаем, что заблокировано до 80% атакующего трафика, 
                # в зависимости от количества заблокированных IP
                block_ratio = min(0.8, (len(blocked_ips) * 0.2) + 0.1)
                blocked_pps = int(attack_pps * block_ratio)
        
        # Возвращаем только незаблокированный атакующий трафик в 'attack'
        attack_pps = max(0, attack_pps - blocked_pps)
        
        return {
            'normal': normal_pps,
            'attack': attack_pps,
            'blocked': blocked_pps,
            'total_attack': attack_pps + blocked_pps,
            'attack_mode': self.attack_mode if self.mode == 'attack' else 'normal',
            'is_running': self.is_running
        }