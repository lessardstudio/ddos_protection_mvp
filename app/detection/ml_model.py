import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from pathlib import Path

class DDOSModel:
    def __init__(self, config):
        self.config = config
        self.model = None
        self.model_path = Path(config['detection']['model_path'])
        self.load_model()
        
    def load_model(self):
        """Загрузка предварительно обученной модели"""
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)
        else:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.01,
                random_state=42
            )
            
    def save_model(self):
        """Сохранение модели"""
        self.model_path.parent.mkdir(exist_ok=True)
        joblib.dump(self.model, self.model_path)
        
    def train(self, X):
        """Обучение модели"""
        self.model.fit(X)
        self.save_model()
        
    def predict(self, X):
        """Предсказание аномалий"""
        if self.model is None:
            raise ValueError("Модель не загружена")
        return self.model.decision_function(X)
    
    def generate_features(self, packet_data):
        """Генерация признаков из данных пакета"""
        # Пример признаков: количество пакетов, размер пакета, временные интервалы
        features = [
            packet_data.get('packet_count', 0),
            packet_data.get('packet_size', 0),
            packet_data.get('time_delta', 0),
            packet_data.get('unique_ips', 0)
        ]
        return np.array(features).reshape(1, -1)