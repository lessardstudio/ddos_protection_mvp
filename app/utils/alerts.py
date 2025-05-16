def send_alert(message, level="info"):
    """Простая система оповещений для MVP"""
    print(f"[{level.upper()}] {message}")  # Вывод в консоль
    
    # В реальной системе здесь можно добавить:
    # - Отправку email
    # - Webhook-уведомления
    # - Запись в лог-файл