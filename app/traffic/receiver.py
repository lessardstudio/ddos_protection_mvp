from scapy.all import sniff
from threading import Thread, Event
from collections import deque
from app.utils.alerts import send_alert
import threading
import time

class TrafficReceiver:
    def __init__(self, config):
        self.config = config.get('traffic', {})
        self.interface = self.config.get('interface', 'eth0')
        self.is_running = False
        self.stop_event = Event()
        self.packet_history = deque(maxlen=1000)
        self.unique_ips = set()
        self.normal_count = 0
        self.attack_count = 0
        self.blocked_count = 0
        
        # Инициализация потоков
        self.sniffer_thread = None
        self.test_data_thread = None
        
        # Объект для перехвата пакетов
        self.sniffer = None

    def _packet_handler(self, packet):
        if not self.is_running:
            return

        if hasattr(packet, 'src'):
            self.unique_ips.add(packet.src)
            
        self.packet_history.append(packet)
        
        # Определяем тип трафика (упрощенно)
        if len(self.packet_history) > 100:  # Если много пакетов за короткое время
            self.attack_count += 1
        else:
            self.normal_count += 1

    def start(self):
        """Запускает перехват трафика"""
        if self.is_running:
            return
        self.is_running = True
        send_alert(f"Starting traffic capture on interface: {self.interface}")
        
        # Запуск снифера в отдельном потоке
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()
        
        # Запуск генератора тестовых данных в отдельном потоке
        self.test_data_thread = threading.Thread(target=self.generate_test_data, daemon=True)
        self.test_data_thread.start()
        
        send_alert("Traffic receiver started")

    def stop(self):
        """Останавливает перехват трафика"""
        if not self.is_running:
            return
        send_alert("Stopping traffic receiver...")
        
        # Устанавливаем флаг остановки
        self.is_running = False
        self.stop_event.set()
        
        # Останавливаем снифер, если он запущен
        if hasattr(self, 'sniffer') and self.sniffer:
            try:
                # Для некоторых версий scapy может потребоваться специальная остановка
                if hasattr(self.sniffer, 'stop'):
                    self.sniffer.stop()
            except Exception as e:
                send_alert(f"Error stopping sniffer: {e}")
        
        # Ждем завершения потоков
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
            send_alert("Sniffer thread stopped")
        
        if self.test_data_thread and self.test_data_thread.is_alive():
            self.test_data_thread.join(timeout=2)
            send_alert("Test data thread stopped")
        
        send_alert("Traffic receiver stopped")

    def get_normal_count(self):
        """Возвращает количество нормального трафика"""
        return self.normal_count

    def get_attack_count(self):
        """Возвращает количество атакующего трафика"""
        return self.attack_count

    def get_blocked_count(self):
        """Возвращает количество заблокированного трафика"""
        return self.blocked_count

    def get_stats(self):
        """Возвращает текущую статистику по трафику"""
        # Вычисляем текущие значения pps для каждого типа трафика
        # Используем разницу между текущим и предыдущим значением счетчиков
        if not hasattr(self, '_last_stats_time'):
            self._last_stats_time = time.time()
            self._last_normal_count = self.normal_count
            self._last_attack_count = self.attack_count
            self._last_blocked_count = self.blocked_count
            normal_pps = 0
            attack_pps = 0
            blocked_pps = 0
        else:
            current_time = time.time()
            time_diff = current_time - self._last_stats_time
            
            if time_diff > 0:
                normal_pps = int((self.normal_count - self._last_normal_count) / time_diff)
                attack_pps = int((self.attack_count - self._last_attack_count) / time_diff)
                blocked_pps = int((self.blocked_count - self._last_blocked_count) / time_diff)
                
                # Обновляем предыдущие значения
                self._last_stats_time = current_time
                self._last_normal_count = self.normal_count
                self._last_attack_count = self.attack_count
                self._last_blocked_count = self.blocked_count
            else:
                normal_pps = 0
                attack_pps = 0
                blocked_pps = 0
        
        stats = {
            'pps': len(self.packet_history),
            'unique_ips': len(self.unique_ips),
            'protocols': 1,  # Предполагаем, что используется только один протокол для упрощения
            'normal_count': normal_pps,  # Отправляем pps вместо накопительного счетчика
            'attack_count': attack_pps,  # Отправляем pps вместо накопительного счетчика
            'blocked_count': blocked_pps   # Отправляем pps вместо накопительного счетчика
        }
        send_alert(f"Traffic stats: PPS={len(self.packet_history)}, Unique IPs={len(self.unique_ips)}, " +
                   f"Normal={normal_pps} pps, Attack={attack_pps} pps, Blocked={blocked_pps} pps")
        return stats

    def get_recent_ips(self, limit=10):
        """Возвращает список последних IP-адресов"""
        send_alert(f"Returning {len(self.unique_ips)} recent IPs")
        return list(self.unique_ips)[:limit]

    def sniff_packets(self):
        """Основная функция перехвата пакетов"""
        try:
            send_alert(f"Starting packet sniffing on interface {self.interface}")
            try:
                # Определите поведение при перехвате пакетов
                self.sniffer = sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda x: self.stop_event.is_set()
                )
            except Exception as e:
                send_alert(f"Error starting sniffing: {e}")
                # Вместо остановки продолжаем работу с тестовыми данными
                send_alert("Switching to test data generation only")
        except Exception as e:
            send_alert(f"Error in packet sniffing: {e}")
        finally:
            # Даже если перехват не работает, продолжаем генерировать тестовые данные
            if not hasattr(self, 'test_data_thread') or not self.test_data_thread.is_alive():
                self.test_data_thread = threading.Thread(target=self.generate_test_data, daemon=True)
                self.test_data_thread.start()
                send_alert("Started test data generation as fallback")

    def generate_test_data(self):
        """Генерирует тестовые данные для демонстрации"""
        import time
        import random
        
        send_alert("Starting test data generation")
        attack_mode = False
        attack_cycle = 0
        
        # Переменные для хранения предыдущих значений счетчиков
        last_normal_count = 0
        last_attack_count = 0
        last_blocked_count = 0
        
        while self.is_running:
            current_time = int(time.time())
            
            # Сохраняем предыдущие значения счетчиков
            prev_normal = self.normal_count
            prev_attack = self.attack_count
            prev_blocked = self.blocked_count
            
            # Базовый нормальный трафик (растет постепенно)
            normal_increment = random.randint(5, 10)
            self.normal_count += normal_increment
            
            # Период атаки каждые 20 секунд (10 секунд атаки, 10 секунд покоя)
            if current_time % 20 < 10:  # 10 секунд атаки, 10 секунд покоя
                if not attack_mode:  # Только что началась атака
                    attack_mode = True
                    attack_cycle += 1
                    send_alert(f"DEMO: Attack cycle {attack_cycle} started")
                
                # Во время атаки генерируем атакующий трафик
                attack_increment = random.randint(30, 50)
                
                # Получаем или создаем заблокированные IP
                from app.app import app
                with app.app_context():
                    from flask import current_app
                    ip_manager = current_app.config.get('ip_manager')
                    if ip_manager:
                        blocked_ips = ip_manager.get_all_blocked_ips()
                        blocked_ips_count = len(blocked_ips)
                        
                        # Добавим несколько блокировок IP, если их нет
                        if blocked_ips_count < 3:
                            # Добавим несколько случайных IP для блокировки
                            for _ in range(3 - blocked_ips_count):
                                test_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                                ip_manager.add_permanent_ban(test_ip)
                                send_alert(f"DEMO: Blocked attack IP {test_ip}")
                            
                            # Обновляем список заблокированных IP
                            blocked_ips = ip_manager.get_all_blocked_ips()
                            blocked_ips_count = len(blocked_ips)
                        
                        # Рассчитываем заблокированный трафик на основе количества заблокированных IP
                        # Чем больше заблокированных IP, тем выше процент блокировки
                        block_ratio = min(0.8, (blocked_ips_count * 0.2) + 0.1)  # Максимум 80% блокировка
                        blocked_increment = int(attack_increment * block_ratio)
                        
                        # Обновляем счетчики:
                        # 1. Сначала увеличиваем общий счетчик атакующего трафика
                        self.attack_count += attack_increment
                        # 2. Затем увеличиваем счетчик заблокированного трафика
                        self.blocked_count += blocked_increment
                        
                        # Вычисляем инкременты для логов
                        normal_incr = self.normal_count - prev_normal
                        attack_incr = self.attack_count - prev_attack
                        blocked_incr = self.blocked_count - prev_blocked
                        unblocked = attack_incr - blocked_incr
                        
                        # Логируем с разбивкой на необработанный и заблокированный трафик
                        send_alert(f"DEMO: Generated test traffic - Normal: +{normal_incr}, " +
                                  f"Attack Total: +{attack_incr} (Unblocked: +{unblocked}, Blocked: +{blocked_incr})")
            else:
                if attack_mode:  # Атака только что закончилась
                    attack_mode = False
                    send_alert(f"DEMO: Attack cycle {attack_cycle} ended")
                
                # В нормальном состоянии генерируем только нормальный трафик
                normal_incr = self.normal_count - prev_normal
                send_alert(f"DEMO: Generated test traffic - Normal: +{normal_incr}, Attack Total: +0")
            
            # Небольшая задержка
            time.sleep(0.9)