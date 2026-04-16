#!/usr/bin/env python3
"""
Battery query BLE encryption test.

This script keeps the existing BT_Enc encryption flow:
1) BLE connect
2) project handshake (ECDH + AES-GCM) via BluetoothSecureClient
3) send msgbus command equivalent to mammotion: device.get_battery_info(46)
4) decrypt and parse response
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass

from bluetooth_secure_client import BluetoothSecureClient
from msgbus import Message, crc16
from msgbus.pb import Luba_msg_pb2, mctrl_sys_pb2

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class MsgbusFrame:
    sender: int
    receiver: int
    cmd: int
    cmd_sub: int
    seq: int
    data: bytes


def parse_msgbus_frame(raw: bytes) -> MsgbusFrame:
    if len(raw) < 12:
        raise ValueError(f"msgbus frame too short: {len(raw)}")
    if raw[0] != 0xA5 or raw[1] != 0x5A:
        raise ValueError(f"invalid msgbus head: {raw[:2].hex()}")

    sender = raw[2]
    receiver = raw[3]
    cmd = raw[4]
    cmd_sub = raw[5]
    data_len = raw[6] | (raw[7] << 8)
    seq = raw[8] | (raw[9] << 8)

    total_len = 10 + data_len + 2
    if len(raw) < total_len:
        raise ValueError(f"incomplete frame: expect {total_len}, got {len(raw)}")

    frame = raw[:total_len]
    payload = frame[10:-2]

    crc_expect = (frame[-2] << 8) | frame[-1]
    crc_calc = crc16(frame[:-2])
    if crc_expect != crc_calc:
        raise ValueError(f"crc mismatch: expect=0x{crc_expect:04x}, calc=0x{crc_calc:04x}")

    return MsgbusFrame(
        sender=sender,
        receiver=receiver,
        cmd=cmd,
        cmd_sub=cmd_sub,
        seq=seq,
        data=payload,
    )


def decode_run_opt_str_payload(data_bytes: bytes) -> str:
    """Align with mammotion.subdev.AbstractSubDevice.run_opt_str."""
    if data_bytes is None:
        return ""
    if len(data_bytes) == 0:
        return ""
    data_len = data_bytes[0]
    internal_data = data_bytes[1:-1]
    if len(internal_data) + 1 == data_len:
        return internal_data.decode("utf-8", "replace")
    return data_bytes.decode("utf-8", "replace")


def build_battery_query_protobuf(cmd_sub: int, recv_dev_id: int = 1, outer_rcver: int = 13) -> bytes:
    """
    Align with mammotion.prod light_ctrl_cmd_parm() protobuf bridge:
    LubaMsg.sys.to_dev_msgbus { type=130, typeCommand=cmd_sub }.
    """
    ping_msg = Luba_msg_pb2.LubaMsg()
    ping_msg.msgtype = Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS
    ping_msg.sender = Luba_msg_pb2.DEV_MOBILEAPP
    ping_msg.rcver = outer_rcver
    ping_msg.msgattr = 1
    ping_msg.seqs = 1
    ping_msg.version = 1
    ping_msg.subtype = 3691
    ping_msg.timestamp = 1

    ctrl_sys = mctrl_sys_pb2.MctlSys()
    msgbus_pkt = mctrl_sys_pb2.msgbus_pkt()
    msgbus_pkt.sendDeviceId = Luba_msg_pb2.DEV_MOBILEAPP
    msgbus_pkt.recvDeviceId = recv_dev_id
    msgbus_pkt.type = 130
    msgbus_pkt.typeCommand = cmd_sub
    ctrl_sys.to_dev_msgbus.CopyFrom(msgbus_pkt)
    ping_msg.sys.CopyFrom(ctrl_sys)
    return ping_msg.SerializeToString()


def build_battery_level_mow_info_request() -> bytes:
    """
    Align with mammotion.subdev.SubDeviceMainCtrl.get_battery_level():
    MctlSys.todev_mow_info_up = 1
    """
    luba_msg = Luba_msg_pb2.LubaMsg()
    luba_msg.msgtype = Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS
    luba_msg.sender = Luba_msg_pb2.DEV_MOBILEAPP
    luba_msg.rcver = Luba_msg_pb2.DEV_MAINCTL
    luba_msg.msgattr = Luba_msg_pb2.MSG_ATTR_NONE
    luba_msg.seqs = 1
    luba_msg.version = 1
    luba_msg.timestamp = 1

    ctrl_sys = mctrl_sys_pb2.MctlSys()
    ctrl_sys.todev_mow_info_up = 1
    luba_msg.sys.CopyFrom(ctrl_sys)
    return luba_msg.SerializeToString()


def parse_protobuf_battery_response(raw: bytes, cmd_sub: int):
    msg = Luba_msg_pb2.LubaMsg()
    msg.ParseFromString(raw)
    if not msg.HasField("sys"):
        return None
    if not msg.sys.HasField("to_app_msgbus"):
        return None
    rsp = msg.sys.to_app_msgbus
    if rsp.type != 130 or rsp.typeCommand != cmd_sub:
        return None
    if not rsp.data:
        return {"note": "to_app_msgbus exists but data empty"}
    byte_data = rsp.data.encode("utf-8", "ignore") if isinstance(rsp.data, str) else bytes(rsp.data)
    base64_data = base64.b64decode(byte_data)
    txt = decode_run_opt_str_payload(base64_data)
    try:
        return json.loads(txt)
    except Exception:
        return txt


async def wait_protobuf_response(
    client: BluetoothSecureClient,
    cmd_sub: int,
    timeout: float,
    request_type: str,
):
    """
    Keep receiving BLE notifications until matching business response arrives or timeout.
    """
    deadline = time.monotonic() + timeout
    packet_idx = 0

    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            return None, None

        try:
            encrypted = await client._wait_for_response(timeout=min(remain, 5.0))
        except Exception as exc:
            logger.warning("wait packet timeout/failed: %s", exc)
            continue

        packet_idx += 1
        logger.info("recv encrypted packet #%s, len=%s", packet_idx, len(encrypted))

        try:
            decrypted = await client.crypto_client.decrypt_receive_data(encrypted)
        except Exception as exc:
            # Some firmwares may return plain protobuf payload (not AES payload) after BluFi deframe.
            logger.info("packet #%s decrypt failed, try plain-protobuf parse: %s", packet_idx, exc)
            if request_type == "mow_info":
                plain_parsed = parse_mow_info_response(encrypted)
            else:
                plain_parsed = parse_protobuf_battery_response(encrypted, cmd_sub=cmd_sub)
            if plain_parsed is not None:
                logger.info("packet #%s matched as plain protobuf response", packet_idx)
                return encrypted, plain_parsed
            continue

        logger.info("packet #%s decrypted len=%s", packet_idx, len(decrypted))

        if request_type == "mow_info":
            parsed = parse_mow_info_response(decrypted)
        else:
            parsed = parse_protobuf_battery_response(decrypted, cmd_sub=cmd_sub)

        if parsed is not None:
            return decrypted, parsed

        logger.info("packet #%s not target response, keep listening", packet_idx)


def parse_mow_info_response(raw: bytes):
    msg = Luba_msg_pb2.LubaMsg()
    msg.ParseFromString(raw)
    if not msg.HasField("sys"):
        return None
    if not msg.sys.HasField("toapp_mow_info"):
        return None
    return {
        "batVal": msg.sys.toapp_mow_info.batVal,
        "raw_toapp_mow_info": str(msg.sys.toapp_mow_info),
    }

def get_RecordInfo():
    from mammotion import DeviceManager
    current_session = DeviceManager.get_instance().get_current_session()
    device_pro = current_session.device()
    maintenace = device_pro.get_maintenance(5)
    print(f"maintenace   ={maintenace}")
    return maintenace


async def run(
    device_name: str,
    cmd_sub: int,
    timeout: float,
    payload_mode: str,
    request_type: str,
    outer_rcver: int,
) -> int:
    client = BluetoothSecureClient(device_name=device_name)

    if not await client.search_device(timeout=10):
        logger.error("device not found")
        return 1

    if not await client.connect(debug_services=False):
        logger.error("BLE connect failed")
        return 2

    try:
        if not await client.perform_handshake():
            logger.error("crypto handshake failed")
            return 3

        if payload_mode == "protobuf":
            if request_type == "mow_info":
                request = build_battery_level_mow_info_request()
                logger.info("send battery query protobuf(todev_mow_info_up=1), len=%s", len(request))
            elif request_type == "record":
                maintenace = get_RecordInfo()
                logger.info("get_RecordInfo, len=%s", len(maintenace))
            else:
                request = build_battery_query_protobuf(cmd_sub=cmd_sub, recv_dev_id=1, outer_rcver=outer_rcver)
                logger.info(
                    "send battery query protobuf(to_dev_msgbus) cmd=130 cmd_sub=%s, outer_rcver=%s, len=%s",
                    cmd_sub,
                    outer_rcver,
                    len(request),
                )
        else:
            request = Message(7, 13).set_cmd(130).set_cmd_sub(cmd_sub).create()
            logger.info("send battery query raw-msgbus cmd=130 cmd_sub=%s, len=%s", cmd_sub, len(request))

        if not await client.send_encrypted_data(request, require_ack=False):
            logger.error("send encrypted battery query failed")
            return 4

        if payload_mode == "protobuf":
            decrypted, parsed = await wait_protobuf_response(
                client=client,
                cmd_sub=cmd_sub,
                timeout=timeout,
                request_type=request_type,
            )
            if not decrypted:
                logger.error("no matched protobuf response within timeout")
                return 5
            logger.info("matched protobuf response len=%s", len(decrypted))
            logger.info("battery parsed(protobuf bridge): %s", parsed)
        else:
            decrypted = await client.receive_encrypted_data(timeout=timeout)
            if not decrypted:
                logger.error("no decrypted response")
                return 5

            logger.info("decrypted response len=%s", len(decrypted))
            frame = parse_msgbus_frame(decrypted)
            logger.info(
                "response header sender=%s receiver=%s cmd=%s cmd_sub=%s seq=%s",
                frame.sender,
                frame.receiver,
                frame.cmd,
                frame.cmd_sub,
                frame.seq,
            )
            text = decode_run_opt_str_payload(frame.data)
            logger.info("battery raw text: %s", text)
            try:
                obj = json.loads(text)
                logger.info("battery parsed json: %s", json.dumps(obj, ensure_ascii=False, indent=2))
            except Exception:
                logger.info("battery parsed string: %s", text)

        return 0
    finally:
        await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="BT_Enc battery encrypted query test")
    parser.add_argument("--device", required=True, help="BLE device name, e.g. Luba-XXXX")
    parser.add_argument("--cmd-sub", type=int, default=46, help="battery info sub command")
    parser.add_argument("--timeout", type=float, default=20.0, help="response timeout seconds")
    parser.add_argument("--outer-rcver", type=int, default=13, help="LubaMsg.rcver for protobuf bridge, e.g. 31 or 13")
    parser.add_argument("--payload-mode", choices=["protobuf", "raw"], default="protobuf",
                        help="business payload format after encryption")
    parser.add_argument(
        "--request-type",
        choices=["msgbus_bridge", "mow_info","record"],
        default="msgbus_bridge",
        help="protobuf request shape",
    )
    args = parser.parse_args()

    code = asyncio.run(
        run(
            device_name=args.device,
            cmd_sub=args.cmd_sub,
            timeout=args.timeout,
            payload_mode=args.payload_mode,
            request_type=args.request_type,
            outer_rcver=args.outer_rcver,
        )
    )
    raise SystemExit(code)


if __name__ == "__main__":
    main()
