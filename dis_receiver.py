import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
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

IFACTS_TIME_24_DATUM_ID = 52001
IFACTS_DATE_EUROPEAN_DATUM_ID = 52601


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


def _select_entity_identifier(pdu: Any) -> Any:
    entity_identifier = getattr(pdu, "entityID", None)
    if entity_identifier is not None:
        return entity_identifier

    for attribute_name in ("originatingEntityID", "receivingEntityID"):
        candidate = getattr(pdu, attribute_name, None)
        if candidate is None:
            continue
        simulation_address = getattr(candidate, "simulationAddress", None)
        if simulation_address is None:
            continue
        if any(
            getattr(simulation_address, field_name, 0) != 0
            for field_name in ("site", "application")
        ) or getattr(candidate, "entityNumber", 0) != 0:
            return candidate

    return None


def _extract_variable_datum_bytes(variable_datum: Any) -> bytes:
    bit_length = getattr(variable_datum, "variableDatumLength", 0) or 0
    byte_length = max(0, (bit_length + 7) // 8)
    values = getattr(variable_datum, "variableData", None)
    if not isinstance(values, list):
        return b""

    byte_values = bytearray()
    for value in values[:byte_length]:
        if isinstance(value, int):
            byte_values.append(value & 0xFF)
    return bytes(byte_values)


def _interpret_variable_datum(variable_datum: Any) -> Dict[str, Any]:
    datum_id = getattr(variable_datum, "variableDatumID", None)
    payload = _extract_variable_datum_bytes(variable_datum)
    ascii_text = payload.decode("ascii", errors="replace").rstrip("\x00 ")

    interpretation: Dict[str, Any] = {
        "datumId": datum_id,
        "lengthBits": getattr(variable_datum, "variableDatumLength", None),
        "lengthBytes": len(payload),
        "payloadHex": payload.hex(" "),
        "payloadAscii": ascii_text,
    }

    if datum_id == IFACTS_TIME_24_DATUM_ID:
        interpretation["meaning"] = "IFACTS UTC time (HHMMSS)"
        if len(ascii_text) == 6 and ascii_text.isdigit():
            interpretation["formattedTimeUtc"] = (
                f"{ascii_text[0:2]}:{ascii_text[2:4]}:{ascii_text[4:6]}"
            )
    elif datum_id == IFACTS_DATE_EUROPEAN_DATUM_ID:
        interpretation["meaning"] = "IFACTS date (DDMMYYYY)"
        if len(ascii_text) == 8 and ascii_text.isdigit():
            interpretation["formattedDate"] = (
                f"{ascii_text[0:2]}.{ascii_text[2:4]}.{ascii_text[4:8]}"
            )
            interpretation["isoDate"] = (
                f"{ascii_text[4:8]}-{ascii_text[2:4]}-{ascii_text[0:2]}"
            )
    else:
        interpretation["meaning"] = "Unrecognized variable datum"

    return interpretation


def _interpret_set_data_pdu(pdu: Any, details: Dict[str, Any]) -> None:
    variable_datums = getattr(pdu, "variableDatumRecords", None)
    if not isinstance(variable_datums, list):
        return

    interpreted_variable_datums = [
        _interpret_variable_datum(variable_datum) for variable_datum in variable_datums
    ]
    details["interpretedVariableDatumRecords"] = interpreted_variable_datums

    time_text = ""
    date_text = ""
    for item in interpreted_variable_datums:
        datum_id = item.get("datumId")
        ascii_text = item.get("payloadAscii", "")
        if datum_id == IFACTS_TIME_24_DATUM_ID:
            time_text = ascii_text
        elif datum_id == IFACTS_DATE_EUROPEAN_DATUM_ID:
            date_text = ascii_text

    if len(time_text) == 6 and time_text.isdigit() and len(date_text) == 8 and date_text.isdigit():
        combined = f"{date_text}{time_text}"
        try:
            parsed = datetime.strptime(combined, "%d%m%Y%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return
        details["ifactsSimulationTimeUtc"] = {
            "iso8601": parsed.isoformat().replace("+00:00", "Z"),
            "display": parsed.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }


def _enum_entry(bits: str, value: int, meaning: str) -> Dict[str, Any]:
    return {
        "bits": bits,
        "value": value,
        "meaning": meaning,
    }


def decode_object_appearance(value: Any) -> str:
    if isinstance(value, bytes):
        number = int.from_bytes(value[:2].ljust(2, b"\x00"), byteorder="big", signed=False)
        return f"{number:016b}"

    if isinstance(value, bool):
        return f"{int(value):016b}"

    if isinstance(value, int):
        return f"{value & 0xFFFF:016b}"

    if isinstance(value, float) and isfinite(value):
        return f"{int(value) & 0xFFFF:016b}"

    return str(value)


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
                if key == "objectAppearance":
                    data[key] = decode_object_appearance(item)
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

    entity_identifier = _select_entity_identifier(pdu)
    simulation_address = getattr(entity_identifier, "simulationAddress", None)

    application_id = getattr(simulation_address, "application", None)
    site_id = getattr(simulation_address, "site", None)
    entity_id = getattr(entity_identifier, "entityNumber", None)

    entity_name = decode_marking(getattr(pdu, "marking", None))
    details = object_to_dict(pdu)
    if pdu_type == "SetDataPdu":
        _interpret_set_data_pdu(pdu, details)

    if not entity_name:
        if pdu_type == "SetDataPdu" and "ifactsSimulationTimeUtc" in details:
            entity_name = details["ifactsSimulationTimeUtc"]["display"]
        else:
            entity_name = "<unnamed>"

    summary_parts = [
        f"type={pdu_type}",
        f"exercise={exercise_id}" if exercise_id is not None else "exercise=n/a",
        f"app={application_id}" if application_id is not None else "app=n/a",
        f"entity={site_id}:{application_id}:{entity_id}" if entity_id is not None else "entity=n/a",
        f"name={entity_name}",
    ]

    if pdu_type == "SetDataPdu":
        request_id = getattr(pdu, "requestID", None)
        if request_id is not None:
            summary_parts.append(f"request={request_id}")

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
