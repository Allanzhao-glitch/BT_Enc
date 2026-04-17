#!/usr/bin/env python3
"""BLE encrypted query for saved Wi-Fi list (DevNet.todev_WifiListUpload)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import time

from bluetooth_secure_client import BluetoothSecureClient
from google.protobuf.json_format import MessageToDict
from msgbus.pb import Luba_msg_pb2, dev_net_pb2


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def build_ble_sync_request(sync_value: int = 2) -> bytes:
    """Warm up BLE channel: DevNet.todev_ble_sync = 2."""
    luba_msg = Luba_msg_pb2.LubaMsg()
    luba_msg.msgtype = Luba_msg_pb2.MSG_CMD_TYPE_ESP
    luba_msg.sender = Luba_msg_pb2.DEV_MOBILEAPP
    luba_msg.rcver = Luba_msg_pb2.DEV_MAINCTL
    luba_msg.msgattr = 1
    luba_msg.seqs = 1
    luba_msg.version = 1
    luba_msg.subtype = 3691
    luba_msg.timestamp = 1

    net = dev_net_pb2.DevNet()
    net.todev_ble_sync = sync_value
    luba_msg.net.CopyFrom(net)
    return luba_msg.SerializeToString()


def build_wifi_list_request() -> bytes:
    """Same route as mammotionkit get_added_wifi()."""
    luba_msg = Luba_msg_pb2.LubaMsg()
    luba_msg.msgtype = Luba_msg_pb2.MSG_CMD_TYPE_ESP
    luba_msg.sender = Luba_msg_pb2.DEV_MOBILEAPP
    luba_msg.rcver = Luba_msg_pb2.DEV_MAINCTL
    luba_msg.msgattr = 1
    luba_msg.seqs = 1
    luba_msg.version = 1
    luba_msg.subtype = 3691
    luba_msg.timestamp = 1

    net = dev_net_pb2.DevNet()
    req = dev_net_pb2.DrvWifiList()
    req.NVS_Wifi_Upload = 1
    req.version = 1
    net.todev_WifiListUpload.CopyFrom(req)
    luba_msg.net.CopyFrom(net)
    return luba_msg.SerializeToString()


def parse_wifi_list_response(raw: bytes):
    msg = Luba_msg_pb2.LubaMsg()
    msg.ParseFromString(raw)
    if not msg.HasField("net"):
        return None
    if not msg.net.HasField("toapp_allListUpload"):
        return None
    return {

        "wifilist": msg.net.toapp_allListUpload
    }


async def wait_wifi_list_response(client: BluetoothSecureClient, timeout: float):
    deadline = time.monotonic() + timeout
    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            return None
        try:
            encrypted = await client._wait_for_response(timeout=min(remain, 5.0))
        except Exception as exc:
            logger.warning("wait packet timeout/failed: %s", exc)
            continue

        try:
            decrypted = await client.crypto_client.decrypt_receive_data(encrypted)
        except Exception:
            decrypted = encrypted

        parsed = parse_wifi_list_response(decrypted)
        if parsed is not None:
            return parsed

        try:
            dbg = Luba_msg_pb2.LubaMsg()
            dbg.ParseFromString(decrypted)
            oneof_name = dbg.net.WhichOneof("NetSubType") if dbg.HasField("net") else None
            logger.info(
                "recv unmatched packet: msgtype=%s sender=%s rcver=%s net_oneof=%s",
                dbg.msgtype,
                dbg.sender,
                dbg.rcver,
                oneof_name,
            )
        except Exception:
            pass


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
        logger.info("send warmup protobuf(todev_ble_sync=2), len=%s", len(warmup))
        if not await client.send_encrypted_data(warmup, require_ack=False):
            logger.error("send warmup failed")
            return 4
        await asyncio.sleep(0.2)

        request = build_wifi_list_request()
        logger.info("send wifi list query protobuf(todev_WifiListUpload), len=%s", len(request))
        if not await client.send_encrypted_data(request, require_ack=False):
            logger.error("send query failed")
            return 5

        parsed = await wait_wifi_list_response(client, timeout=timeout)
        if parsed is None:
            logger.error("no matched protobuf response within timeout")
            return 6

        logger.info("wifi parsed(protobuf): %s", parsed)
        return 0
    finally:
        await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="Luba BLE encrypted saved Wi-Fi list query")
    parser.add_argument("--device", required=True, help="BLE device name, e.g. Luba-XXXX")
    parser.add_argument("--timeout", type=float, default=30.0, help="response timeout seconds")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(device_name=args.device, timeout=args.timeout)))


if __name__ == "__main__":
    main()
