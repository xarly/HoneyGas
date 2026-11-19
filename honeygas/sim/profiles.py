"""Parse a profile YAML dict into typed dataclasses."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TagSpec:
    name: str
    unit: str = ""
    kind: str = "sine"          # sine | counter | setpoint
    base: float = 0.0
    amp: float = 0.0
    period: float = 600.0
    noise: float = 0.0
    rate: float = 0.0           # counter increment per second
    min: float = -1e12
    max: float = 1e12


@dataclass
class RegEntry:
    tag: Optional[str] = None
    scale: float = 1.0
    static: Optional[int] = None
    label: str = ""


@dataclass
class ModbusMap:
    unit: int = 1
    input_registers: Dict[int, RegEntry] = field(default_factory=dict)
    holding_registers: Dict[int, RegEntry] = field(default_factory=dict)
    coils: Dict[int, RegEntry] = field(default_factory=dict)
    discrete_inputs: Dict[int, RegEntry] = field(default_factory=dict)


@dataclass
class HmiValue:
    label: str
    tag: str
    unit: str = ""


@dataclass
class HmiSpec:
    title: str = "SCADA"
    values: List[HmiValue] = field(default_factory=list)


@dataclass
class Credential:
    username: str
    password: str


@dataclass
class AtgTank:
    num: int
    product: str
    volume: float
    tc_volume: float
    ullage: float
    height: float
    water: float
    temp: float


@dataclass
class AtgSpec:
    station: str
    tanks: List[AtgTank] = field(default_factory=list)


@dataclass
class Vendor:
    manufacturer: str = "Generic"
    product: str = "Controller"
    firmware: str = "1.0.0"
    serial: str = "SN-000000"


@dataclass
class S7Spec:
    """Siemens S7 PLC identity exposed via S7comm Read SZL (0x0011 / 0x001C)."""
    order_number: str = "6ES7 315-2EH14-0AB0"   # MLFB of the module
    basic_hardware: str = "6ES7 315-2EH14-0AB0"  # MLFB of the basic hardware
    firmware: str = "V3.2.6"                      # 'Vx.y.z'
    module_type: str = "CPU 315-2 PN/DP"
    system_name: str = "SIMATIC 300(1)"
    serial: str = "S C-C2UR28922017"
    copyright: str = "Original Siemens Equipment"
    plant_id: str = ""
    pdu_size: int = 480                           # negotiated max PDU length

    def fw_tuple(self) -> tuple:
        nums = [int(x) for x in self.firmware.lstrip("Vv").split(".") if x.isdigit()]
        while len(nums) < 3:
            nums.append(0)
        return tuple(min(max(n, 0), 255) for n in nums[:3])


@dataclass
class Iec104Point:
    """A monitored point exposed over IEC 60870-5-104.

    type_id selects the ASDU used in the interrogation response:
      13 = M_ME_NC_1 (measured value, short float)   -> `tag`/`static` as float
       1 = M_SP_NA_1 (single point, on/off)          -> state from `tag`/`static`
    """
    ioa: int
    tag: Optional[str] = None
    static: Optional[float] = None
    type_id: int = 13
    scale: float = 1.0
    label: str = ""


@dataclass
class Iec104Command:
    """A control point an attacker can try to operate over IEC 60870-5-104.

    type_id: 45 = C_SC_NA_1 (single command), 46 = C_DC_NA_1 (double command),
             50 = C_SE_NC_1 (set-point, short float).
    """
    ioa: int
    type_id: int = 45
    label: str = ""


@dataclass
class Iec104Spec:
    common_address: int = 1
    spontaneous_seconds: float = 0.0        # 0 disables periodic spontaneous data
    points: List[Iec104Point] = field(default_factory=list)
    commands: List[Iec104Command] = field(default_factory=list)


@dataclass
class Profile:
    name: str
    mode: str
    vendor: Vendor
    credentials: List[Credential]
    tags: List[TagSpec]
    modbus: ModbusMap
    hmi: HmiSpec
    atg: Optional[AtgSpec] = None
    s7: Optional[S7Spec] = None
    iec104: Optional[Iec104Spec] = None


def _reg_map(raw: dict) -> Dict[int, RegEntry]:
    out: Dict[int, RegEntry] = {}
    for addr, entry in (raw or {}).items():
        entry = entry or {}
        out[int(addr)] = RegEntry(
            tag=entry.get("tag"),
            scale=float(entry.get("scale", 1.0)),
            static=(int(entry["static"]) if entry.get("static") is not None else None),
            label=entry.get("label", ""),
        )
    return out


def load_profile(d: dict) -> Profile:
    v = d.get("vendor", {}) or {}
    vendor = Vendor(
        manufacturer=v.get("manufacturer", "Generic"),
        product=v.get("product", "Controller"),
        firmware=v.get("firmware", "1.0.0"),
        serial=v.get("serial", "SN-000000"),
    )

    credentials = [
        Credential(username=str(c["username"]), password=str(c["password"]))
        for c in (d.get("credentials", []) or [])
    ]

    tags = []
    for t in d.get("tags", []) or []:
        tags.append(
            TagSpec(
                name=t["name"],
                unit=t.get("unit", ""),
                kind=t.get("kind", "sine"),
                base=float(t.get("base", 0.0)),
                amp=float(t.get("amp", 0.0)),
                period=float(t.get("period", 600.0)),
                noise=float(t.get("noise", 0.0)),
                rate=float(t.get("rate", 0.0)),
                min=float(t.get("min", -1e12)),
                max=float(t.get("max", 1e12)),
            )
        )

    m = d.get("modbus", {}) or {}
    modbus = ModbusMap(
        unit=int(m.get("unit", 1)),
        input_registers=_reg_map(m.get("input_registers", {})),
        holding_registers=_reg_map(m.get("holding_registers", {})),
        coils=_reg_map(m.get("coils", {})),
        discrete_inputs=_reg_map(m.get("discrete_inputs", {})),
    )

    h = d.get("hmi", {}) or {}
    hmi = HmiSpec(
        title=h.get("title", "SCADA"),
        values=[
            HmiValue(label=x["label"], tag=x["tag"], unit=x.get("unit", ""))
            for x in (h.get("values", []) or [])
        ],
    )

    atg = None
    a = d.get("atg")
    if a:
        atg = AtgSpec(
            station=a.get("station", "STATION"),
            tanks=[
                AtgTank(
                    num=int(t["num"]),
                    product=t.get("product", "PRODUCT"),
                    volume=float(t.get("volume", 0.0)),
                    tc_volume=float(t.get("tc_volume", 0.0)),
                    ullage=float(t.get("ullage", 0.0)),
                    height=float(t.get("height", 0.0)),
                    water=float(t.get("water", 0.0)),
                    temp=float(t.get("temp", 0.0)),
                )
                for t in (a.get("tanks", []) or [])
            ],
        )

    s7 = None
    s = d.get("s7")
    if s:
        order = s.get("order_number", S7Spec.order_number)
        s7 = S7Spec(
            order_number=order,
            basic_hardware=s.get("basic_hardware", order),
            firmware=s.get("firmware", S7Spec.firmware),
            module_type=s.get("module_type", S7Spec.module_type),
            system_name=s.get("system_name", S7Spec.system_name),
            serial=s.get("serial", S7Spec.serial),
            copyright=s.get("copyright", S7Spec.copyright),
            plant_id=s.get("plant_id", ""),
            pdu_size=int(s.get("pdu_size", 480)),
        )

    iec104 = None
    ie = d.get("iec104")
    if ie:
        points = [
            Iec104Point(
                ioa=int(p["ioa"]),
                tag=p.get("tag"),
                static=(float(p["static"]) if p.get("static") is not None else None),
                type_id=int(p.get("type_id", 13)),
                scale=float(p.get("scale", 1.0)),
                label=p.get("label", ""),
            )
            for p in (ie.get("points", []) or [])
        ]
        commands = [
            Iec104Command(
                ioa=int(c["ioa"]),
                type_id=int(c.get("type_id", 45)),
                label=c.get("label", ""),
            )
            for c in (ie.get("commands", []) or [])
        ]
        iec104 = Iec104Spec(
            common_address=int(ie.get("common_address", 1)),
            spontaneous_seconds=float(ie.get("spontaneous_seconds", 0.0)),
            points=points,
            commands=commands,
        )

    return Profile(
        name=d.get("name", "Unnamed"),
        mode=d.get("mode", "transport"),
        vendor=vendor,
        credentials=credentials,
        tags=tags,
        modbus=modbus,
        hmi=hmi,
        atg=atg,
        s7=s7,
        iec104=iec104,
    )
