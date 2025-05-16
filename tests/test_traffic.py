import pytest
import time
from app.traffic.generator import TrafficGenerator
from app.traffic.receiver import TrafficReceiver
from app.utils.config import load_config

@pytest.fixture
def config():
    return load_config()

@pytest.fixture
def generator(config):
    return TrafficGenerator(config)

@pytest.fixture
def receiver(config):
    return TrafficReceiver(config)

def test_generator_start_stop(generator):
    generator.start('normal')
    assert generator.is_running
    generator.stop()
    assert not generator.is_running

def test_receiver_start_stop(receiver):
    receiver.start()
    assert receiver.is_running
    receiver.stop()
    assert not receiver.is_running

def test_receiver_stats(receiver):
    receiver.start()
    time.sleep(1)  # Даем время для захвата пакетов
    stats = receiver.get_stats()
    assert isinstance(stats, dict)
    assert 'packet_count' in stats
    receiver.stop()