import yaml
from pathlib import Path

CONFIG_PATH = Path('config/settings.yaml')

def load_config():
    """Загрузка конфигурации из YAML файла"""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"Конфигурационный файл не найден: {CONFIG_PATH}")
    
    with open(CONFIG_PATH, 'r') as f:
        config = yaml.safe_load(f)
    
    return config

def save_config(new_config):
    """Сохранение конфигурации в YAML файл"""
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(new_config, f, default_flow_style=False)