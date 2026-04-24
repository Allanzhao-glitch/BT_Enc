#!/usr/bin/env python3
"""BLE Wi-Fi scan loop.

Behavior:
- Wait up to 10s for each scan response.
- If timeout: send heartbeat to keep link alive, then start next scan cycle.
- If response received: wait 10s, then scan again.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import time
from typing import Any, Callable

from bluetooth_secure_client import BluetoothSecureClient
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


def build_wifi_scan_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, Luba_msg_pb2.DEV_MAINCTL)
    net = dev_net_pb2.DevNet()
    req = dev_net_pb2.DrvWifiscanReq()
    req.version = dev_net_pb2.SCAN_VERSION_Default
    req.bizid = int(time.time())
    net.todev_wifiscan.CopyFrom(req)
    msg.net.CopyFrom(net)
    return msg.SerializeToString()


def build_local_connect_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, Luba_msg_pb2.DEV_MAINCTL)
    net = dev_net_pb2.DevNet()
    req = dev_net_pb2.DrvWifiList()
    net.todev_WifiListUpload.CopyFrom(req)
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
    request = build_wifi_scan_request()
    if not await _send_encrypted_or_fail(client, request, "query_wifi_list protobuf(ScanWifi)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_wifiscan"):
            return None
        return msg.net.toapp_wifiscan.wifilist

    return await _wait_with_data_handler(client, timeout, data_handle, "query_wifi_list")


async def run(
    device_name: str,
    reply_timeout: float,
    success_interval: float,
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

        loop_count = 0
        while True:
            warmup = build_ble_sync_request(sync_value=2)
            if not await _send_encrypted_or_fail(client, warmup, "warmup protobuf(todev_ble_sync=2)"):
                return 4
            await asyncio.sleep(0.2)

            loop_count += 1
            raw_new_wifi = await query_wifi_list(client, timeout=reply_timeout)
            if raw_new_wifi is None:
                logger.error("scan #%s no matched protobuf response within %.1fs", loop_count, reply_timeout)
                heartbeat = build_ble_sync_request(sync_value=2)
                await _send_encrypted_or_fail(
                    client,
                    heartbeat,
                    "timeout-keepalive protobuf(todev_ble_sync=2)",
                )
            else:
                ssids = [wifi.ssid for wifi in raw_new_wifi] if raw_new_wifi else []
                logger.info("scan #%s ssids: %r", loop_count, ssids)
                await asyncio.sleep(success_interval)
    finally:
        await client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="Luba BLE Wi-Fi scan loop")
    parser.add_argument("--device", required=True, help="BLE device name, e.g. Luba-XXXX")
    parser.add_argument("--timeout", type=float, default=10.0, help="wait this long for one scan response")
    parser.add_argument("--interval", type=float, default=10.0, help="next scan delay after a successful response")
    args = parser.parse_args()
    raise SystemExit(
        asyncio.run(
            run(
                device_name=args.device,
                reply_timeout=args.timeout,
                success_interval=args.interval,
            )
        )
    )


if __name__ == "__main__":
    main()
