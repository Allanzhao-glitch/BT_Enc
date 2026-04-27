from __future__ import annotations

import argparse
import asyncio
import logging
import time
from typing import Any, Callable

from bluetooth_secure_client import BluetoothSecureClient
from msgbus.pb import Luba_msg_pb2, dev_net_pb2



class DebugAndErrorOnly(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno in (logging.DEBUG, logging.ERROR)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
handler.addFilter(DebugAndErrorOnly())

logger = logging.getLogger()
logger.handlers.clear()
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


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

def query_added_wifi_request() -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, 0)
    net = dev_net_pb2.DevNet()
    msg_ctrl = dev_net_pb2.DrvWifiList()
    msg_ctrl.NVS_Wifi_Upload = 1
    msg_ctrl.version = dev_net_pb2.VERSION_1
    net.todev_WifiListUpload.CopyFrom(msg_ctrl)
    msg.net.CopyFrom(net)
    return msg.SerializeToString()

def disconnect_wifi_request(ssid) -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, 15)
    net = dev_net_pb2.DevNet()
    msg_ctrl = dev_net_pb2.DrvWifiSet()
    msg_ctrl.configParam = dev_net_pb2.DisconnectWifi
    msg_ctrl.Confssid = ssid
    net.todev_Wifi_Configuration.CopyFrom(msg_ctrl)
    msg.net.CopyFrom(net)
    return msg.SerializeToString()

def forget_added_wifi_request(ssid) -> bytes:
    msg = _build_base_msg(Luba_msg_pb2.MSG_CMD_TYPE_ESP, 15)
    cmd = dev_net_pb2.DevNet()
    msg_ctrl = dev_net_pb2.DrvWifiSet()
    msg_ctrl.configParam = dev_net_pb2.ForgetWifi
    msg_ctrl.Confssid = ssid
    cmd.todev_Wifi_Configuration.CopyFrom(msg_ctrl)
    msg.net.CopyFrom(cmd)
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
            # logger.debug(
            #     "[%s] unmatched packet: msgtype=%s sender=%s rcver=%s net_oneof=%s",
            #     debug_name,
            #     msg.msgtype,
            #     msg.sender,
            #     msg.rcver,
            #     net_oneof,
            # )
        except Exception:
            pass

async def query_local_connect(client: BluetoothSecureClient, timeout: float):
    """查询本地连接状态"""
    request = build_local_connect_request()
    if not await _send_encrypted_or_fail(client, request, "query_local_connect protobuf(LocalConnect)"):
        return None
    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_ListUpload"):
            return None
        return msg.net.toapp_ListUpload.Memssid
    return await _wait_with_data_handler(client, timeout, data_handle, "query_local_connect")
    
async def query_wifi_list(client: BluetoothSecureClient, timeout: float):
    """扫描周围wifi网络"""
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

async def connect_new_wifi(client: BluetoothSecureClient, ssid, password: str, timeout: float):
    """连接新的wifi网络"""
    request = connect_new_wifi_request(ssid, password)
    if not await _send_encrypted_or_fail(client, request, "connect_new_wifi protobuf(WifiSet)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg,ssid):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_WifiMsg"):
            return None
        rsp = msg.net.toapp_WifiMsg.Msgssid
        return rsp
    return await _wait_with_data_handler(client, timeout, lambda msg: data_handle(msg, ssid), "connect_new_wifi")

async def query_added_wifi(client: BluetoothSecureClient, timeout: float):
    '''查询已添加的wifi网络'''
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

async def disconnect_wifi(client: BluetoothSecureClient, ssid, timeout: float):
    request = disconnect_wifi_request(ssid)
    if not await _send_encrypted_or_fail(client, request, "disconnect_wifi protobuf(WifiSet)"):
        return None
    
    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_WifiConf"):
            return None
        rsp = msg.net.toapp_WifiConf.Confssid
        return rsp
    return await _wait_with_data_handler(client, timeout, data_handle, "disconnect_wifi")

async def forget_added_wifi(client: BluetoothSecureClient, ssid, timeout: float):
    request = forget_added_wifi_request(ssid)
    if not await _send_encrypted_or_fail(client, request, "forget_added_wifi protobuf(WifiSet)"):
        return None
    
    def data_handle(msg: Luba_msg_pb2.LubaMsg):

        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_WifiConf"):
            return None
        rsp = msg.net.toapp_WifiConf.succFlag
        return rsp

    return await _wait_with_data_handler(client, timeout, data_handle, "forget_added_wifi")

async def connect_added_wifi(client: BluetoothSecureClient, ssid, timeout: float):
    """连接已添加的wifi网络"""
    request = connect_added_wifi_request(ssid)
    if not await _send_encrypted_or_fail(client, request, "connect_added_wifi protobuf(WifiSet)"):
        return None

    def data_handle(msg: Luba_msg_pb2.LubaMsg):
        if not msg.HasField("net"):
            return None
        if not msg.net.HasField("toapp_WifiConf"):
            return None
        rsp = msg.net.toapp_WifiConf.Confssid
        return rsp
    return await _wait_with_data_handler(client, timeout, data_handle, "connect_added_wifi")

async def run(
    device_name: str,
    reply_timeout: float,
) -> int:
    client = BluetoothSecureClient(device_name=device_name)

    if not await client.search_device(timeout=10):
        logger.error("device not found")
        return 1
    if not await client.connect(debug_services=False):
        logger.error("BLE connect failed")
        return 2

    try:
        #三次尝试握手
        if not await client.perform_handshake():
            logger.error("crypto handshake failed")
            return 3
        #发送心跳信息
        warmup = build_ble_sync_request(sync_value=2)
        if not await _send_encrypted_or_fail(client, warmup, "warmup protobuf(todev_ble_sync=2)"):
                return 4
        await asyncio.sleep(0.2)
        #读取最初wifi连接信息
        init_conn_wifi = await query_local_connect(client, timeout=reply_timeout)
        if init_conn_wifi is None:
            # logger.debug("query_local_connect no matched protobuf response within %.1fs", reply_timeout)
            # heartbeat = build_ble_sync_request(sync_value=2)
            # await _send_encrypted_or_fail(
            #         client,
            #         heartbeat,
            #         "timeout-keepalive protobuf(todev_ble_sync=2)",
            #     )
            logger.warning("query_local_connect no matched protobuf response within %.1fs", reply_timeout)
        else:
            logger.debug("init_conn_wifi: %r", init_conn_wifi)
        #扫描周围wifi网络
        raw_new_wifi = await query_wifi_list(client, timeout=reply_timeout)
        if raw_new_wifi is None:
            logger.warning("query_wifi_list no matched protobuf response within %.1fs", reply_timeout)
            # heartbeat = build_ble_sync_request(sync_value=2)
            # await _send_encrypted_or_fail(
            #         client,
            #         heartbeat,
            #         "timeout-keepalive protobuf(todev_ble_sync=2)",
            #     )
        else:
            new_wifi = [wifi.ssid for wifi in raw_new_wifi] if raw_new_wifi else []
            logger.debug("new_wifi: %r", new_wifi)
        new_conn_Wifi = "mammotion2.4G"
        new_conn_Wifi_password = "mammotion888."
        #检查连接wifi是否在已添加的wifi网络并连接
        if new_conn_Wifi in new_wifi:
            logger.debug("new_conn_Wifi %s is in scanned wifi", new_conn_Wifi)
            conn_new_wifi = await connect_new_wifi(client,new_conn_Wifi,new_conn_Wifi_password,timeout=reply_timeout)
            if conn_new_wifi is None:
                logger.error("connect_new_wifi no matched protobuf response within %.1fs", reply_timeout)
                # heartbeat = build_ble_sync_request(sync_value=2)
                # await _send_encrypted_or_fail(
                #     client,
                #     heartbeat,
                #     "timeout-keepalive protobuf(todev_ble_sync=2)",
                # )
            else:
                logger.debug("conn_new_wifi: %r", conn_new_wifi)
        else:
            logger.warning("new_conn_Wifi %s is not in scanned wifi", new_conn_Wifi)
            return 6
        
        #获取车端保存的ssid
        raw_added_wifi = await query_added_wifi(client,timeout=reply_timeout)
        if raw_added_wifi is None:
            logger.warning("query_added_wifi no matched protobuf response within %.1fs", reply_timeout)
            # heartbeat = build_ble_sync_request(sync_value=2)
            # await _send_encrypted_or_fail(
            #         client,
            #         heartbeat,
            #         "timeout-keepalive protobuf(todev_ble_sync=2)",
            #     )
        else:
            added_wifi = [wifi.Memssid for wifi in raw_added_wifi] if raw_added_wifi else []
            logger.debug("added_wifi: %r", added_wifi)
        #断开连接wifi
        if conn_new_wifi == new_conn_Wifi:
            logger.debug("conn_new_wifi %s is new_conn_Wifi %s, nneed to disconnect", conn_new_wifi, new_conn_Wifi)
            disconnect_wifi_rsp = await disconnect_wifi(client,new_conn_Wifi,timeout=reply_timeout)
            if disconnect_wifi_rsp is None:
                logger.error("disconnect_wifi no matched protobuf response within %.1fs", reply_timeout) 
                # heartbeat = build_ble_sync_request(sync_value=2)
                # await _send_encrypted_or_fail(
                #     client,
                #     heartbeat,
                #     "timeout-keepalive protobuf(todev_ble_sync=2)",
                # )
            else:
                logger.debug("disconnect_wifi_rsp: %r", disconnect_wifi_rsp)
        else:
            logger.error("conn_new_wifi %s is not new_conn_Wifi %s", conn_new_wifi, new_conn_Wifi)
            return 7
        
        #删除已添加的wifi
        if added_wifi is not None and conn_new_wifi in added_wifi:
            logger.debug("new_conn_Wifi %s is in added wifi", conn_new_wifi)
            forget_added_wifi_rsp = await forget_added_wifi(client,conn_new_wifi,timeout=reply_timeout)
            if forget_added_wifi_rsp is None:
                logger.warning("forget_added_wifi no matched protobuf response within %.1fs", reply_timeout) 
                # heartbeat = build_ble_sync_request(sync_value=2)
                # await _send_encrypted_or_fail(
                #     client,
                #     heartbeat,
                #     "timeout-keepalive protobuf(todev_ble_sync=2)",
                # )
            else:
                logger.debug("forget_added_wifi_rsp: %r", forget_added_wifi_rsp)
        else:
            logger.debug("new_conn_Wifi %s is not in added wifi", new_conn_Wifi)
            return 8
        #恢复原有wifi连接
        if init_conn_wifi is not None:
            logger.debug("init_conn_wifi %s is in init_conn_wifi", init_conn_wifi)
            reconnect_wifi = await connect_added_wifi(client,init_conn_wifi,timeout=reply_timeout)
            if reconnect_wifi is None:
                logger.debug("connect_added_wifi no matched protobuf response within %.1fs", reply_timeout)
                # heartbeat = build_ble_sync_request(sync_value=2)
                # await _send_encrypted_or_fail(
                #     client,
                #     heartbeat,
                #     "timeout-keepalive protobuf(todev_ble_sync=2)",
                # )
            elif reconnect_wifi == init_conn_wifi:
                logger.debug("reconnect_wifi_info: %r success", reconnect_wifi)
        else:
            logger.error("init_conn_wifi %s reconnect failed", init_conn_wifi)
    finally:
        await client.disconnect()

def main() -> None:
    parser = argparse.ArgumentParser(description="Luba BLE Wi-Fi scan loop")
    parser.add_argument("--device", required=True, help="BLE device name, e.g. Luba-XXXX")
    parser.add_argument("--timeout", type=float, default=30.0, help="response timeout seconds")
    args = parser.parse_args()
    raise SystemExit(
        asyncio.run(
            run(
                device_name=args.device,
                reply_timeout=args.timeout,
            )
        )
    )


if __name__ == "__main__":
    main()
