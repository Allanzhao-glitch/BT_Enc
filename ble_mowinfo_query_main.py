#!/usr/bin/env python3
"""BLE encrypted query helpers with per-function data handlers."""

from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import time
from typing import Any, Callable

from bluetooth_secure_client import BluetoothSecureClient
from google.protobuf.json_format import MessageToDict
from msgbus.pb import Luba_msg_pb2, dev_net_pb2, mctrl_sys_pb2,mctrl_driver_pb2


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

def _build_base_msg(msgtype: int, rcver: int) -> Luba_msg_pb2.LubaMsg:
    msg = Luba_msg_pb2.LubaMsg()
    msg.msgtype = msgtype
    msg.sender = Luba_msg_pb2.DEV_MOBILEAPP
    msg.rcver = rcver
    msg.msgattr = 1
    msg.seqs = 1
    msg.version = 1
    msg.subtype = 3691
    msg.timestamp = 1
    return msg


def build_ble_sync_request(sync_value: int = 2) -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, Luba_msg_pb2.DEV_MAINCTL)
    net = dev_net_pb2.DevNet()
    net.todev_ble_sync = sync_value
    msg.net.CopyFrom(net)
    return msg.SerializeToString()


def build_mow_info_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS, Luba_msg_pb2.DEV_MAINCTL)
    ctrl_sys = mctrl_sys_pb2.MctlSys()
    ctrl_sys.todev_mow_info_up = 1
    msg.sys.CopyFrom(ctrl_sys)
    return msg.SerializeToString()


def build_maintenance_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS, 15)
    cmd = mctrl_sys_pb2.MctlSys()
    report_cfg = mctrl_sys_pb2.report_info_cfg()
    report_cfg.act = 0
    report_cfg.timeout = 3
    report_cfg.period = 1000
    report_cfg.no_change_period = 1000
    report_cfg.count = 1
    report_cfg.sub.append(mctrl_sys_pb2.RIT_MAINTAIN)
    cmd.todev_report_cfg.CopyFrom(report_cfg)
    msg.sys.CopyFrom(cmd)
    return msg.SerializeToString()

def build_new_wifi_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, 0)
    cmd = dev_net_pb2.DevNet()
    msg_ctrl = dev_net_pb2.DrvWifiscanReq()
    msg_ctrl.bizid = int(time.time())
    cmd.todev_wifiscan.CopyFrom(msg_ctrl)
    msg.net.CopyFrom(cmd)
    return msg.SerializeToString()

def build_battery_info_request(sub_cmd: int) -> bytes:
    ping_msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS, 15)
    ctrl_sys = mctrl_sys_pb2.MctlSys()
    msgbus_pkt = mctrl_sys_pb2.msgbus_pkt()
    msgbus_pkt.sendDeviceId = Luba_msg_pb2.DEV_MOBILEAPP
    msgbus_pkt.recvDeviceId = 1
    msgbus_pkt.type = 130
    msgbus_pkt.typeCommand = sub_cmd

    ctrl_sys.to_dev_msgbus.CopyFrom(msgbus_pkt)
    ping_msg.sys.CopyFrom(ctrl_sys)
    return ping_msg.SerializeToString()


def build_light_request(sub_cmd: int,hex_data= None) -> bytes:
    ping_msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS, 15)
    ctrl_sys = mctrl_sys_pb2.MctlSys()
    msgbus_pkt = mctrl_sys_pb2.msgbus_pkt()
    msgbus_pkt.sendDeviceId = Luba_msg_pb2.DEV_MOBILEAPP
    msgbus_pkt.recvDeviceId = 1
    msgbus_pkt.type = 130
    msgbus_pkt.typeCommand = sub_cmd
    if hex_data is not None:
        if isinstance(hex_data, str):
            payload = bytearray(hex_data.encode("utf-8"))
        elif isinstance(hex_data, (bytes, bytearray)):
            payload = bytearray(hex_data)
        else:
            raise TypeError(f"hex_data must be str|bytes|bytearray, got {type(hex_data).__name__}")
        payload.append(0)
        msgbus_pkt.dataLength = len(payload)
        base64_data = base64.b64encode(bytes(payload))
        msgbus_pkt.data = base64_data.decode('utf-8')
    ctrl_sys.to_dev_msgbus.CopyFrom(msgbus_pkt)
    ping_msg.sys.CopyFrom(ctrl_sys)
    return ping_msg.SerializeToString()


def build_light_request(sub_cmd: int,hex_data= None) -> bytes:
    ping_msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS, 15)
    ctrl_sys = mctrl_sys_pb2.MctlSys()
    msgbus_pkt = mctrl_sys_pb2.msgbus_pkt()
    msgbus_pkt.sendDeviceId = Luba_msg_pb2.DEV_MOBILEAPP
    msgbus_pkt.recvDeviceId = 1
    msgbus_pkt.type = 130
    msgbus_pkt.typeCommand = sub_cmd
    if hex_data is not None:
        hex_data.append(0)
        msgbus_pkt.dataLength = len(hex_data)
        base64_data = base64.b64encode(bytes(hex_data))
        msgbus_pkt.data = base64_data.decode('utf-8')
    ctrl_sys.to_dev_msgbus.CopyFrom(msgbus_pkt)
    ping_msg.sys.CopyFrom(ctrl_sys)
    return ping_msg.SerializeToString()


def knife_ctrl_request():
    """刀盘控制"""
        
    ping_msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_EMBED_DRIVER, 1)
    cmd = mctrl_driver_pb2.MctlDriver()
    cmd_ctrl = mctrl_driver_pb2.DrvMowCtrlByHand()
    cmd_ctrl.main_ctrl = 1
    cmd_ctrl.cut_knife_ctrl = 1
    cmd_ctrl.cut_knife_height = 60
    cmd_ctrl.max_run_Speed = 3000
    cmd.mow_ctrl_by_hand.CopyFrom(cmd_ctrl)
    ping_msg.driver.CopyFrom(cmd)
    return ping_msg.SerializeToString()        

def build_disconnect_added_wifi_request(ssid: str) -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, Luba_msg_pb2.DEV_MAINCTL)
    net = dev_net_pb2.DevNet()

    wifi_cfg = dev_net_pb2.DrvWifiSet()
    wifi_cfg.configParam = 1
    wifi_cfg.Confssid = ssid
    net.todev_Wifi_Configuration.CopyFrom(wifi_cfg)

    msg.net.CopyFrom(net)
    return msg.SerializeToString()


async def _send_encrypted_or_fail(client: BluetoothSecureClient, payload: bytes, what: str) -> bool:
    logger.info("send %s, len=%s", what, len(payload))
    if not await client.send_encrypted_data(payload, require_ack=False):
        logger.error("send %s failed", what)
        return False
    return True


async def _wait_with_data_handler(
    client: BluetoothSecureClient,
    timeout: float,
    data_handle: Callable[[Luba_msg_pb2.LubaMsg], Any | None],
    debug_name: str,
):
    deadline = time.monotonic() + timeout
    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            return None

        try:
            encrypted = await client._wait_for_response(timeout=min(remain, 5.0))
        except Exception as exc:
            logger.warning("[%s] wait packet timeout/failed: %s", debug_name, exc)
            continue

        try:
            decrypted = await client.crypto_client.decrypt_receive_data(encrypted)
        except Exception:
            decrypted = encrypted

        try:
            msg = Luba_msg_pb2.LubaMsg()
            msg.ParseFromString(decrypted)
        except Exception:
            continue

        parsed = data_handle(msg)
        if parsed is not None:
            return parsed
        try:
            net_oneof = msg.net.WhichOneof("NetSubType") if msg.HasField("net") else None
            sys_oneof = msg.sys.WhichOneof("MctlSubType") if msg.HasField("sys") else None
            logger.debug(
                "[%s] unmatched packet: msgtype=%s sender=%s rcver=%s net_oneof=%s sys_oneof=%s",
                debug_name,
                msg.msgtype,
                msg.sender,
                msg.rcver,
                net_oneof,
                sys_oneof,
            )
        except Exception:
            pass


async def query_mow_info(client: BluetoothSecureClient, timeout: float):
    request = build_mow_info_request()
    if not await _send_encrypted_or_fail(client, request, "mow_info query protobuf(todev_mow_info_up=1)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("sys"):
            return None
        if not msg.sys.HasField("toapp_mow_info"):
            return None
        return {
            "batVal": msg.sys.toapp_mow_info.batVal,
            "raw_toapp_mow_info": str(msg.sys.toapp_mow_info),
        }

    return await _wait_with_data_handler(client, timeout, data_handle, "mow_info")


async def get_maintenance(client: BluetoothSecureClient, timeout: float):
    request = build_maintenance_request()
    if not await _send_encrypted_or_fail(client, request, "maintenance query protobuf(todev_report_cfg.RIT_MAINTAIN)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("sys"):
            return None
        if not msg.sys.HasField("toapp_report_data"):
            return None
        if not msg.sys.toapp_report_data.HasField("maintain"):
            return None
        maintain = msg.sys.toapp_report_data.maintain
        return {
            "maintain": MessageToDict(maintain, preserving_proto_field_name=True),
            "raw_maintain": str(maintain),
        }

    return await _wait_with_data_handler(client, timeout, data_handle, "maintenance")


async def disconnect_added_wifi(client: BluetoothSecureClient, ssid: str, timeout: float):
    request = build_disconnect_added_wifi_request(ssid)
    if not await _send_encrypted_or_fail(client, request, "disconnect_added_wifi protobuf(ForgetWifi)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_WifiConf"):
            return None
        resp = msg.net.toapp_WifiConf
        return {
            "success": bool(resp.succFlag),
            "code": resp.code,
            "ssid": resp.Confssid,
            "raw_wifi_conf": str(resp),
        }

    return await _wait_with_data_handler(client, timeout, data_handle, "disconnect_added_wifi")

async def query_wifi_list(client: BluetoothSecureClient, timeout: float):
    request = build_new_wifi_request()
    if not await _send_encrypted_or_fail(client, request, "query_wifi_list protobuf(ScanWifi)"):
        return None
    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        # if not msg.HasField("net"):
        #     return None
        # if not msg.net.HasField("toapp_wifiscan"):
            return msg
    return await _wait_with_data_handler(client, timeout, data_handle, "query_wifi_list")


async def build_light(client: BluetoothSecureClient,cmd:int,hex_data:bytes, timeout: float):
    request = build_light_request(cmd, hex_data=hex_data)
    if not await _send_encrypted_or_fail(client, request, "build_light(cmd)"):
        return None
    def data_handle(msg):
        if isinstance(msg, Luba_msg_pb2.LubaMsg):
            if msg.sys.HasField("to_app_msgbus") and msg.sys.to_app_msgbus.type == 130 and msg.sys.to_app_msgbus.typeCommand == cmd:
                if msg.sys.to_app_msgbus.data:
                    base64_data = base64.b64decode(msg.sys.to_app_msgbus.data)
                    print("base64_data", base64_data)
                    print("base64_data_hex", base64_data.hex())
                    raw_text = base64_data.decode("utf-8", errors="ignore")
                    clean_data = raw_text.rstrip("\x00").strip()
                    print("clean_data_repr", repr(clean_data))
                    return clean_data
    return await _wait_with_data_handler(client, timeout, data_handle, "build_light")

async def set_knife_control(client: BluetoothSecureClient,timeout):
        request = knife_ctrl_request()    
        if not await _send_encrypted_or_fail(client, request, "set_knife_control(cmd)"):
            return None
        def data_handle(msg):
            # if isinstance(msg, Luba_msg_pb2.LubaMsg):
            #     if msg.sys.HasField("to_app_msgbus") and msg.sys.to_app_msgbus.type == 130 and msg.sys.to_app_msgbus.typeCommand == cmd:
            #         if msg.sys.to_app_msgbus.data:
            #             base64_data = base64.b64decode(msg.sys.to_app_msgbus.data)
            #             print("base64_data",base64_data)
            #             return (int.from_bytes(base64_data, byteorder='little', signed=True) == 0)
            print("msg", msg)
            return msg
        return await _wait_with_data_handler(client, timeout, data_handle, "knife_ctrl")

async def get_battery_info(client: BluetoothSecureClient, timeout: float):
    request = build_battery_info_request(46)
    if not await _send_encrypted_or_fail(client, request, "get_battery_info protobuf(46)"):
        return None
    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("sys"):
            return None
        if not msg.sys.HasField("to_app_msgbus"):
            return None
        rsp = msg.sys.to_app_msgbus
        clean_data = ""
        if rsp.data:
            try:
                decoded_text = base64.b64decode(rsp.data)
                clean_data = _decode_msgbus_text_payload(decoded_text)
            except Exception:
                clean_data = ""
        return {
            "data_decoded": clean_data
        }

    return await _wait_with_data_handler(client, timeout, data_handle, "get_battery_info")

async def run(device_name: str, action: str, timeout: float, ssid: str | None = None) -> int:
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

        warmup = build_ble_sync_request(sync_value=2)
        if not await _send_encrypted_or_fail(client, warmup, "warmup protobuf(todev_ble_sync=2)"):
            return 4
        await asyncio.sleep(0.2)

        if action == "mow_info":
            parsed = await query_mow_info(client, timeout=timeout)
        elif action == "maintenance":
            parsed = await get_maintenance(client, timeout=timeout)
        elif action == "disconnect_added_wifi":
            if not ssid:
                logger.error("--ssid is required for action=disconnect_added_wifi")
                return 7
            parsed = await disconnect_added_wifi(client, ssid=ssid, timeout=timeout)
        elif action == "query_wifi_list":
            parsed = await query_wifi_list(client, timeout=timeout)
        elif action == "get_battery_info":
            parsed = await get_battery_info(client, timeout=timeout)
        elif action == "build_light":
            parsed = await build_light(client, 43,hex_data= bytearray("liftMotorSet 60".encode(encoding='utf-8')), timeout=timeout)
            parsed = await build_light(client, 43,hex_data= bytearray("liftMotorShowEnable".encode(encoding='utf-8')), timeout=timeout)

        elif action == "set_knife_control":
            while True:
                parsed = await set_knife_control(client, timeout=timeout)
                parsed = await build_light(client, 43,hex_data= bytearray("liftMotorShowEnable".encode(encoding='utf-8')), timeout=timeout)
        else:
            logger.error("unsupported action: %s", action)
            return 8

        if parsed is None:
            logger.error("no matched protobuf response within timeout")
            return 6

        logger.info("%s parsed(protobuf): %r", action, parsed)
        return 0
    finally:
        await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="Luba BLE encrypted query tool (per-function data_handle)")
    parser.add_argument("--device", required=True, help="BLE device name, e.g. Luba-XXXX")
    parser.add_argument(
        "--action",
        default="mow_info",
        choices=["mow_info", "maintenance", "disconnect_added_wifi","query_wifi_list","get_battery_info","build_light","set_knife_control"],
        help="query action",
    )
    parser.add_argument("--ssid", default=None, help="target ssid for action=disconnect_added_wifi")
    parser.add_argument("--timeout", type=float, default=30.0, help="response timeout seconds")
    args = parser.parse_args()
    raise SystemExit(
        asyncio.run(run(device_name=args.device, action=args.action, timeout=args.timeout, ssid=args.ssid))
    )


if __name__ == "__main__":
    main()
