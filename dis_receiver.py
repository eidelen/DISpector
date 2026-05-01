import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from opendis.PduFactory import createPdu


ENTITY_APPEARANCE_PAINT_SCHEME = {
    0: "Uniform Color",
    1: "Camouflage",
}

ENTITY_APPEARANCE_BOOLEAN = {
    0: "No",
    1: "Yes",
}

ENTITY_APPEARANCE_DAMAGE = {
    0: "No Damage",
    1: "Slight Damage",
    2: "Moderate Damage",
    3: "Destroyed",
}

ENTITY_APPEARANCE_SMOKE = {
    0: "Not Smoking",
    1: "Smoke plume is rising from the entity",
    2: "Entity is emitting engine smoke",
    3: "Entity is emitting engine smoke and smoke plume is rising from the entity",
}

ENTITY_APPEARANCE_TRAILING = {
    0: "None",
    1: "Small",
    2: "Medium",
    3: "Large",
}

ENTITY_APPEARANCE_HATCH = {
    0: "Not applicable",
    1: "Primary hatch is closed",
    2: "Primary hatch is popped",
    3: "Primary hatch is popped and a person is visible under hatch",
    4: "Primary hatch is open",
    5: "Primary hatch is open and person is visible",
    6: "Unused",
    7: "Unused",
}

ENTITY_APPEARANCE_LIGHTS = {
    0: "None",
    1: "Running lights are on",
    2: "Navigation lights are on",
    3: "Formation lights are on",
    4: "Unused",
    5: "Unused",
    6: "Unused",
    7: "Unused",
}


@dataclass
class PacketRecord:
    sequence: int
    received_at: float
    source_host: str
    source_port: int
    size_bytes: int
    pdu_type: str
    exercise_id: Optional[int]
    application_id: Optional[int]
    site_id: Optional[int]
    entity_id: Optional[int]
    entity_name: str
    summary: str
    raw_hex: str
    raw_ascii: str
    details: Dict[str, Any]


def format_ascii_bytes(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)


def decode_marking(marking: Any) -> str:
    if marking is None:
        return ""

    getter = getattr(marking, "getString", None)
    if callable(getter):
        try:
            value = getter()
            if isinstance(value, str):
                cleaned = value.rstrip("\x00 ").strip()
                if cleaned:
                    return cleaned
        except Exception:
            pass

    characters = getattr(marking, "characters", None)
    if characters is not None:
        try:
            chars: List[str] = []
            for code in characters:
                if not isinstance(code, int):
                    continue
                if code == 0:
                    break
                chars.append(chr(code))
            cleaned = "".join(chars).rstrip()
            if cleaned:
                return cleaned
        except Exception:
            pass

    return ""


def decode_ascii_values(values: Any) -> str:
    if not isinstance(values, list):
        return ""

    chars: List[str] = []
    for code in values:
        if not isinstance(code, int):
            continue
        if code == 0:
            break
        if 32 <= code <= 126:
            chars.append(chr(code))
        else:
            chars.append(f"\\x{code:02x}")
    return "".join(chars)


def _enum_entry(bits: str, value: int, meaning: str) -> Dict[str, Any]:
    return {
        "bits": bits,
        "value": value,
        "meaning": meaning,
    }


def decode_entity_appearance(value: int) -> Dict[str, Any]:
    general = value & 0xFFFF
    specific = (value >> 16) & 0xFFFF

    paint_scheme = (general >> 0) & 0b1
    mobility_kill = (general >> 1) & 0b1
    fire_power_kill = (general >> 2) & 0b1
    damage = (general >> 3) & 0b11
    smoke = (general >> 5) & 0b11
    trailing = (general >> 7) & 0b11
    hatch = (general >> 9) & 0b111
    lights = (general >> 12) & 0b111
    flaming = (general >> 15) & 0b1

    return {
        "raw": value,
        "hex": f"0x{value:08X}",
        "binary32": f"{value:032b}",
        "binary32Grouped": " ".join(
            f"{(value >> shift) & 0xFF:08b}" for shift in (24, 16, 8, 0)
        ),
        "generalAppearanceLow16Hex": f"0x{general:04X}",
        "generalAppearanceLow16Binary": f"{general:016b}",
        "specificAppearanceHigh16Hex": f"0x{specific:04X}",
        "specificAppearanceHigh16Binary": f"{specific:016b}",
        "generalAppearanceInterpretation": {
            "paintScheme": _enum_entry("0", paint_scheme, ENTITY_APPEARANCE_PAINT_SCHEME.get(paint_scheme, "Unknown")),
            "mobilityKill": _enum_entry("1", mobility_kill, "Mobility Kill" if mobility_kill else "No Mobility Kill"),
            "firePowerKill": _enum_entry("2", fire_power_kill, "Fire-power kill" if fire_power_kill else "No Fire-power kill"),
            "damage": _enum_entry("3-4", damage, ENTITY_APPEARANCE_DAMAGE.get(damage, "Unknown")),
            "smoke": _enum_entry("5-6", smoke, ENTITY_APPEARANCE_SMOKE.get(smoke, "Unknown")),
            "trailingEffect": _enum_entry("7-8", trailing, ENTITY_APPEARANCE_TRAILING.get(trailing, "Unknown")),
            "hatchState": _enum_entry("9-11", hatch, ENTITY_APPEARANCE_HATCH.get(hatch, "Unknown")),
            "lights": _enum_entry("12-14", lights, ENTITY_APPEARANCE_LIGHTS.get(lights, "Unknown")),
            "flamingEffect": _enum_entry("15", flaming, "Flames present" if flaming else "None"),
        },
    }


def object_to_dict(value: Any, visited: Optional[set] = None) -> Any:
    if visited is None:
        visited = set()

    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, bytes):
        return value.hex(" ")

    if isinstance(value, (list, tuple)):
        return [object_to_dict(item, visited) for item in value]

    if isinstance(value, dict):
        return {str(key): object_to_dict(item, visited) for key, item in value.items()}

    value_id = id(value)
    if value_id in visited:
        return "<recursive>"

    visited.add(value_id)
    try:
        if hasattr(value, "__dict__"):
            data: Dict[str, Any] = {}
            for key, item in vars(value).items():
                if key.startswith("_"):
                    continue
                if key == "entityAppearance" and isinstance(item, int):
                    data[key] = decode_entity_appearance(item)
                    continue
                data[key] = object_to_dict(item, visited)
            if "characters" in data:
                decoded = decode_ascii_values(data["characters"])
                if decoded:
                    data["charactersText"] = decoded
            if data:
                return data
        return str(value)
    finally:
        visited.remove(value_id)


def build_packet_record(sequence: int, data: bytes, source: Tuple[str, int], pdu: Any) -> PacketRecord:
    pdu_type = pdu.__class__.__name__
    exercise_id = getattr(pdu, "exerciseID", None)

    entity_identifier = getattr(pdu, "entityID", None)
    simulation_address = getattr(entity_identifier, "simulationAddress", None)

    application_id = getattr(simulation_address, "application", None)
    site_id = getattr(simulation_address, "site", None)
    entity_id = getattr(entity_identifier, "entityNumber", None)

    entity_name = decode_marking(getattr(pdu, "marking", None))
    if not entity_name:
        entity_name = "<unnamed>"

    details = object_to_dict(pdu)
    summary_parts = [
        f"type={pdu_type}",
        f"exercise={exercise_id}" if exercise_id is not None else "exercise=n/a",
        f"app={application_id}" if application_id is not None else "app=n/a",
        f"entity={site_id}:{application_id}:{entity_id}" if entity_id is not None else "entity=n/a",
        f"name={entity_name}",
    ]

    return PacketRecord(
        sequence=sequence,
        received_at=time.time(),
        source_host=source[0],
        source_port=source[1],
        size_bytes=len(data),
        pdu_type=pdu_type,
        exercise_id=exercise_id,
        application_id=application_id,
        site_id=site_id,
        entity_id=entity_id,
        entity_name=entity_name,
        summary=", ".join(summary_parts),
        raw_hex=data.hex(" "),
        raw_ascii=format_ascii_bytes(data),
        details=details,
    )


class DisReceiver:
    def __init__(self, on_packet, on_error):
        self._on_packet = on_packet
        self._on_error = on_error
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._sequence = 0

    def start(
        self,
        bind_host: str,
        bind_port: int,
        buffer_size: int = 8192,
    ) -> None:
        if self._running:
            raise RuntimeError("Receiver is already running")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, bind_port))

        self._socket = sock
        self._running = True
        self._thread = threading.Thread(
            target=self._receive_loop,
            args=(buffer_size,),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._running

    def _receive_loop(self, buffer_size: int) -> None:
        while self._running and self._socket is not None:
            try:
                data, source = self._socket.recvfrom(buffer_size)
            except OSError:
                break

            try:
                pdu = createPdu(data)
                if pdu is None:
                    continue
                self._sequence += 1
                record = build_packet_record(self._sequence, data, source, pdu)
                self._on_packet(record)
            except Exception as exc:
                self._on_error(f"Failed to decode packet from {source[0]}:{source[1]}: {exc}")
