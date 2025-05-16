import pytest
import numpy as np
from app.detection.detector import DDOSDetector
from app.detection.ml_model import DDOSModel
from app.utils.config import load_config

@pytest.fixture
def config():
    return load_config()

@pytest.fixture
def detector(config):
    return DDOSDetector(config)

@pytest.fixture
def model(config):
    return DDOSModel(config)

def test_detector_initialization(detector):
    assert detector is not None
    assert detector.threshold == -0.5
    assert not detector.is_trained

def test_model_training(model):
    X_train = np.random.rand(100, 4)  # 100 samples, 4 features
    model.train(X_train)
    assert model.model is not None

def test_detector_training(detector):
    X_train = np.random.rand(100, 4)
    detector.train(X_train)
    assert detector.is_trained

def test_attack_detection(detector, model):
    X_train = np.random.rand(100, 4)
    detector.train(X_train)
    
    normal_traffic = np.random.rand(1, 4)
    is_attack, score = detector.detect(normal_traffic)
    assert not is_attack
    
    attack_traffic = np.array([[100, 100, 100, 100]])  # Явные аномалии
    is_attack, score = detector.detect(attack_traffic)
    assert is_attack