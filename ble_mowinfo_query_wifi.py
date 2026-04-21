#!/usr/bin/env python3
"""BLE encrypted Wi-Fi scan query using per-function data handlers."""

from __future__ import annotations
import re
import argparse
import asyncio
import logging
import time
from typing import Any, Callable

from bluetooth_secure_client import BluetoothSecureClient
from google.protobuf.json_format import MessageToDict
from msgbus.pb import Luba_msg_pb2, dev_net_pb2


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


def query_new_wifi_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP,0)
    net = dev_net_pb2.DevNet()
    req = dev_net_pb2.DrvWifiscanReq()
    req.bizid = int(time.time())
    net.todev_wifiscan.CopyFrom(req)
    msg.net.CopyFrom(net)
    return msg.SerializeToString()

def query_added_wifi_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, 0)
    net = dev_net_pb2.DevNet()
    msg_ctrl = dev_net_pb2.DrvWifiList()
    msg_ctrl.NVS_Wifi_Upload = 1
    msg_ctrl.version = dev_net_pb2.VERSION_1
    net.todev_WifiListUpload.CopyFrom(msg_ctrl)
    msg.net.CopyFrom(net)
    return msg.SerializeToString()

def connect_added_wifi_request(ssid: str):
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, Luba_msg_pb2.DEV_MAINCTL)
    net = dev_net_pb2.DevNet()
    msg_ctrl = dev_net_pb2.DrvWifiSet()
    msg_ctrl.configParam = dev_net_pb2.DirectConnectWifi
    msg_ctrl.Confssid = ssid
    net.todev_Wifi_Configuration.CopyFrom(msg_ctrl)
    msg.net.CopyFrom(net)
    return msg.SerializeToString()

def connect_new_wifi_request(ssid,password):
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, 15)
    cmd = dev_net_pb2.DevNet()
    msg_ctrl = dev_net_pb2.DrvWificonnectReq()
    msg_ctrl.version = dev_net_pb2.CONNECT_VERSION_Default
    msg_ctrl.bizid = int(time.time())
    msg_ctrl.wifimode = dev_net_pb2.WIFI_MODE_STA
    msg_ctrl.wifi_ssid = ssid
    msg_ctrl.has_password = 1 if password else 0
    msg_ctrl.wifi_password = password or ""
    cmd.todev_wificonnect.CopyFrom(msg_ctrl)
    msg.net.CopyFrom(cmd)
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
            logger.debug(
                "[%s] unmatched packet: msgtype=%s sender=%s rcver=%s net_oneof=%s",
                debug_name,
                msg.msgtype,
                msg.sender,
                msg.rcver,
                net_oneof,
            )
        except Exception:
            pass


async def query_wifi_list(client: BluetoothSecureClient, timeout: float):
    """鑾峰彇鏂癢iFi"""
    request = query_new_wifi_request()
    if not await _send_encrypted_or_fail(client, request, "query_wifi_list protobuf(ScanWifi)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_wifiscan"):
            return None
        rsp = msg.net.toapp_wifiscan.wifilist
        return rsp
    return await _wait_with_data_handler(client, timeout, data_handle, "query_wifi_list")

async def query_added_wifi(client: BluetoothSecureClient, timeout: float):
    '''鑾峰彇宸叉坊鍔犵殑wifi'''
    request = query_added_wifi_request()
    if not await _send_encrypted_or_fail(client, request, "query_added_wifi protobuf(WifiListUpload)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_allListUpload"):
            return None
        rsp = msg.net.toapp_allListUpload
        return rsp.wifilist
    return await _wait_with_data_handler(client, timeout, data_handle, "query_added_wifi")

async def connect_added_wifi(client: BluetoothSecureClient, ssid: str, timeout: float):
    """杩炴帴宸叉坊鍔犵殑wifi"""
    request = connect_added_wifi_request(ssid)
    if not await _send_encrypted_or_fail(client, request, "connect_added_wifi protobuf(WifiSet)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_WifiConf"):
            return None
        rsp = msg.net.toapp_WifiConf
        return rsp
    return await _wait_with_data_handler(client, timeout, data_handle, "connect_added_wifi")

async def connect_new_wifi(client: BluetoothSecureClient, ssid: str, password: str, timeout: float):
    """杩炴帴鏂皐ifi"""
    request = connect_new_wifi_request(ssid, password)
    if not await _send_encrypted_or_fail(client, request, "connect_new_wifi protobuf(WifiSet)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        # if not msg.net.HasField("toapp_wificonnect"):
        #     return None
        # rsp = msg.net.toapp_wificonnect
        print(msg)
        return msg
    return await _wait_with_data_handler(client, timeout, data_handle, "connect_new_wifi")


async def run(device_name: str, timeout: float) -> int:
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

        while True:
            await asyncio.sleep(10.0)
            raw_new_wifi = await query_wifi_list(client, timeout=timeout)
            if raw_new_wifi is None:
                logger.error("no matched protobuf response within timeout")
                return 6

            logger.info("wifi parsed(protobuf): %r", raw_new_wifi)
            new_wifi = [wifi.ssid for wifi in raw_new_wifi] if raw_new_wifi else []
            logger.info("wifi ssids: %r", new_wifi)

        # raw_added_wifi = await query_added_wifi(client, timeout=timeout)
        # if raw_added_wifi is None:
        #     logger.error("no matched protobuf response within timeout")
        #     return 6

        # logger.info("wifi parsed(protobuf): %r", raw_added_wifi)
        # added_wifi = [wifi.Memssid for wifi in raw_added_wifi] if raw_added_wifi else []
    
        # logger.info("wifi ssids: %r", added_wifi)
        # raw_connect_new_wifi = await connect_new_wifi(client, ssid="mammotion2.4G", password="mammotion888.",  timeout=timeout)
        # if raw_connect_new_wifi is None:
        #     logger.error("no matched protobuf response within timeout")
        #     return 7
        # logger.info("connect_new_wifi parsed(protobuf): %r", raw_connect_new_wifi)

        return 0

    
    finally:
        await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="Luba BLE encrypted Wi-Fi scan query")
    parser.add_argument("--device", required=True, help="BLE device name, e.g. Luba-XXXX")
    parser.add_argument("--timeout", type=float, default=30.0, help="response timeout seconds")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(device_name=args.device, timeout=args.timeout)))


if __name__ == "__main__":
    main()
