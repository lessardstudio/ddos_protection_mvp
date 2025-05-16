import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import random

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IPManager:
    def __init__(self):
        # Таблица для IP, заблокированных навсегда (DDOS трафик)
        self.permanent_ban: List[str] = []
        # Таблица для IP с временной блокировкой (30 минут)
        self.temp_ban: Dict[str, float] = {}
        # Таблица для подозрительных IP без бана
        self.suspicious: List[str] = []
        # Время блокировки в секундах (30 минут)
        self.ban_duration = 30 * 60

    def add_permanent_ban(self, ip: str) -> None:
        """Добавляет IP в список навсегда заблокированных и логирует с красной пометкой."""
        if ip not in self.permanent_ban:
            self.permanent_ban.append(ip)
            logger.warning(f"WARNING! IP {ip} заблокирован навсегда из-за DDOS трафика.")

    def add_temp_ban(self, ip: str) -> None:
        """Добавляет IP в список временно заблокированных и логирует с красной пометкой."""
        if ip not in self.temp_ban and ip not in self.permanent_ban:
            self.temp_ban[ip] = time.time()
            logger.warning(f"WARNING! IP {ip} временно заблокирован на 30 минут из-за подозрительной активности.")

    def add_suspicious(self, ip: str) -> None:
        """Добавляет IP в список подозрительных и логирует с оранжевой пометкой."""
        if ip not in self.suspicious and ip not in self.temp_ban and ip not in self.permanent_ban:
            self.suspicious.append(ip)
            logger.info(f"warning! IP {ip} помечен как подозрительный.")

    def get_all_blocked_ips(self) -> List[str]:
        """Возвращает список всех заблокированных IP-адресов (постоянно и временно)"""
        # Фильтруем временно заблокированные IP, чтобы учитывать только активные блокировки
        current_time = time.time()
        active_temp_bans = [ip for ip, ban_time in self.temp_ban.items() 
                           if current_time - ban_time < self.ban_duration]
        
        # Объединяем постоянные и временные блокировки
        return self.permanent_ban + active_temp_bans

    def is_blocked(self, ip: str) -> bool:
        """Проверяет, заблокирован ли IP (навсегда или временно)."""
        if ip in self.permanent_ban:
            return True
        if ip in self.temp_ban:
            if time.time() - self.temp_ban[ip] < self.ban_duration:
                return True
            else:
                del self.temp_ban[ip]
                logger.info(f"IP {ip} разблокирован после 30 минут.")
        return False

    def check_activity(self) -> None:
        """Проверяет активность IP и обновляет статус временных блокировок."""
        current_time = time.time()
        for ip in list(self.temp_ban.keys()):
            if current_time - self.temp_ban[ip] >= self.ban_duration:
                del self.temp_ban[ip]
                logger.info(f"IP {ip} разблокирован после 30 минут.")

    def get_all_blocked(self) -> Dict[str, List[str]]:
        """Возвращает все списки заблокированных и подозрительных IP для администратора."""
        return {
            "permanent_ban": self.permanent_ban,
            "temp_ban": list(self.temp_ban.keys()),
            "suspicious": self.suspicious
        }

    def get_random_ip(self) -> str:
        """Возвращает случайный IP-адрес для симуляции трафика"""
        return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def is_ip_blocked(self, ip: str) -> bool:
        """Проверяет, заблокирован ли IP (альтернативное название для is_blocked)"""
        return self.is_blocked(ip) 