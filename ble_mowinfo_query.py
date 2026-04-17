#!/usr/bin/env python3
"""
Minimal "known-good" BLE encrypted query path for Luba battery info.

Required runtime packages (pip):
- bleak
- protobuf
- cryptography
- msgbus

Local modules used:
- bluetooth_secure_client.py
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import time

from bluetooth_secure_client import BluetoothSecureClient
from msgbus.pb import Luba_msg_pb2, dev_net_pb2, mctrl_sys_pb2


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


def build_mow_info_request() -> bytes:
    """Battery query path used by mammotion get_battery_level()."""
    luba_msg = Luba_msg_pb2.LubaMsg()
    luba_msg.msgtype = Luba_msg_pb2.MSG_CMD_TYPE_EMBED_SYS
    luba_msg.sender = Luba_msg_pb2.DEV_MOBILEAPP
    luba_msg.rcver = Luba_msg_pb2.DEV_MAINCTL
    luba_msg.msgattr = 1
    luba_msg.seqs = 1
    luba_msg.version = 1
    luba_msg.subtype = 3691
    luba_msg.timestamp = 1

    ctrl_sys = mctrl_sys_pb2.MctlSys()
    ctrl_sys.todev_mow_info_up = 1
    luba_msg.sys.CopyFrom(ctrl_sys)
    return luba_msg.SerializeToString()


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


async def wait_mow_info_response(client: BluetoothSecureClient, timeout: float):
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

        # Usually encrypted payload after handshake.
        try:
            decrypted = await client.crypto_client.decrypt_receive_data(encrypted)
        except Exception:
            decrypted = encrypted

        parsed = parse_mow_info_response(decrypted)
        if parsed is not None:
            return parsed


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

        request = build_mow_info_request()
        logger.info("send battery query protobuf(todev_mow_info_up=1), len=%s", len(request))
        if not await client.send_encrypted_data(request, require_ack=False):
            logger.error("send query failed")
            return 5

        parsed = await wait_mow_info_response(client, timeout=timeout)
        if parsed is None:
            logger.error("no matched protobuf response within timeout")
            return 6

        logger.info("battery parsed(protobuf): %s", parsed)
        return 0
    finally:
        await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="Luba BLE encrypted battery query (minimal known-good path)")
    parser.add_argument("--device", required=True, help="BLE device name, e.g. Luba-XXXX")
    parser.add_argument("--timeout", type=float, default=30.0, help="response timeout seconds")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(device_name=args.device, timeout=args.timeout)))


if __name__ == "__main__":
    main()

