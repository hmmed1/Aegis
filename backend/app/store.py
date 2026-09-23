"""
Thread-safe in-memory store for sensor status, flow snapshots, and discovered
devices. Swap this for a real database later without touching the routes much
 -- everything goes through this one module.
"""
import threading
import time
from dataclasses import dataclass, field

from .config import settings


@dataclass
class SensorRecord:
    sensor_id: str
    last_seen: float = 0.0
    flows: list[dict] = field(default_factory=list)
    devices: list[dict] = field(default_factory=list)
    flows_updated_at: float = 0.0
    devices_updated_at: float = 0.0

    @property
    def online(self) -> bool:
        return (time.time() - self.last_seen) <= settings.SENSOR_OFFLINE_TIMEOUT_SECONDS


class Store:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sensors: dict[str, SensorRecord] = {}

    def _get_or_create(self, sensor_id: str) -> SensorRecord:
        rec = self._sensors.get(sensor_id)
        if rec is None:
            rec = SensorRecord(sensor_id=sensor_id)
            self._sensors[sensor_id] = rec
        return rec

    def touch(self, sensor_id: str) -> None:
        with self._lock:
            self._get_or_create(sensor_id).last_seen = time.time()

    def ingest_flows(self, sensor_id: str, flows: list[dict]) -> None:
        with self._lock:
            rec = self._get_or_create(sensor_id)
            rec.flows = flows
            rec.flows_updated_at = time.time()
            rec.last_seen = time.time()

    def ingest_devices(self, sensor_id: str, devices: list[dict]) -> None:
        with self._lock:
            rec = self._get_or_create(sensor_id)
            rec.devices = devices
            rec.devices_updated_at = time.time()
            rec.last_seen = time.time()

    def list_sensors(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "sensor_id": rec.sensor_id,
                    "online": rec.online,
                    "last_seen": rec.last_seen,
                    "flow_count": len(rec.flows),
                    "device_count": len(rec.devices),
                }
                for rec in sorted(self._sensors.values(), key=lambda r: r.sensor_id)
            ]

    def get_flows(self, sensor_id: str) -> list[dict] | None:
        with self._lock:
            rec = self._sensors.get(sensor_id)
            return list(rec.flows) if rec else None

    def get_devices(self, sensor_id: str) -> list[dict] | None:
        with self._lock:
            rec = self._sensors.get(sensor_id)
            return list(rec.devices) if rec else None

    def sensor_exists(self, sensor_id: str) -> bool:
        with self._lock:
            return sensor_id in self._sensors


store = Store()
