import os
from flask import Flask, send_from_directory
from app.web.routes import init_routes
from app.detection.detector import DDOSDetector
from app.traffic.generator import TrafficGenerator
from app.traffic.receiver import TrafficReceiver
from app.utils.config import load_config
from app.utils.ip_manager import IPManager
from flasgger import Swagger

def create_app():
    # Получаем абсолютный путь до директории app
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(base_dir, 'app', 'web', 'templates')
    static_dir = os.path.join(base_dir, 'app', 'web', 'static')
    
    # Проверка путей (для отладки)
    print(f"Base directory: {base_dir}")
    print(f"Templates directory exists: {os.path.exists(templates_dir)}")
    print(f"Static directory exists: {os.path.exists(static_dir)}")
    
    app = Flask(__name__,
               static_folder=static_dir,
               template_folder=templates_dir)
    
    config = load_config()
    
    # Настройка Swagger
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": "apispec",
                "route": "/apispec.json",
                "rule_filter": lambda rule: True,  # all in
                "model_filter": lambda tag: True,  # all in
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs"
    }
    
    swagger_template = {
        "info": {
            "title": "DDoS Protection API",
            "description": "API для системы защиты от DDoS-атак",
            "contact": {
                "email": "admin@example.com"
            },
            "version": "1.0.0"
        },
        "host": "localhost:5000",
        "basePath": "/",
        "schemes": [
            "http"
        ],
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme."
            }
        },
    }
    
    swagger = Swagger(app, config=swagger_config, template=swagger_template)
    
    # Инициализация компонентов
    ip_manager = IPManager()
    detector = DDOSDetector(config, ip_manager)
    traffic_gen = TrafficGenerator(config, ip_manager)
    traffic_rec = TrafficReceiver(config)
    
    # Инициализация маршрутов
    init_routes(app, detector, traffic_gen, traffic_rec, ip_manager)
    
    # Маршрут для главной страницы
    @app.route('/')
    def serve_index():
        try:
            return send_from_directory(templates_dir, 'index.html')
        except Exception as e:
            return f"Error loading index.html: {str(e)}", 500
    
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)