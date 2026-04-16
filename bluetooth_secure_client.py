"""
蓝牙安全客户端 - 集成Bleak蓝牙库的加密通讯实现

结合原有的BT_Enc_test.py的蓝牙连接功能,实现完整的加密通讯
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from enum import StrEnum

from bleak import BleakClient, BleakGATTCharacteristic, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.exc import BleakCharacteristicNotFoundError, BleakError
from bluetooth_crypto import BluetoothCryptoClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(asctime)s %(filename)s|%(lineno)d: %(message)s")
logger = logging.getLogger(__name__)


class BlufiCRC:
    """
    BluFi CRC 校验和计算 (参考 pyBlufi 实现)

    使用 CRC-16/XMODEM 算法
    """

    CRC_TB = [
        0x0000,
        0x1021,
        0x2042,
        0x3063,
        0x4084,
        0x50A5,
        0x60C6,
        0x70E7,
        0x8108,
        0x9129,
        0xA14A,
        0xB16B,
        0xC18C,
        0xD1AD,
        0xE1CE,
        0xF1EF,
        0x1231,
        0x0210,
        0x3273,
        0x2252,
        0x52B5,
        0x4294,
        0x72F7,
        0x62D6,
        0x9339,
        0x8318,
        0xB37B,
        0xA35A,
        0xD3BD,
        0xC39C,
        0xF3FF,
        0xE3DE,
        0x2462,
        0x3443,
        0x0420,
        0x1401,
        0x64E6,
        0x74C7,
        0x44A4,
        0x5485,
        0xA56A,
        0xB54B,
        0x8528,
        0x9509,
        0xE5EE,
        0xF5CF,
        0xC5AC,
        0xD58D,
        0x3653,
        0x2672,
        0x1611,
        0x0630,
        0x76D7,
        0x66F6,
        0x5695,
        0x46B4,
        0xB75B,
        0xA77A,
        0x9719,
        0x8738,
        0xF7DF,
        0xE7FE,
        0xD79D,
        0xC7BC,
        0x48C4,
        0x58E5,
        0x6886,
        0x78A7,
        0x0840,
        0x1861,
        0x2802,
        0x3823,
        0xC9CC,
        0xD9ED,
        0xE98E,
        0xF9AF,
        0x8948,
        0x9969,
        0xA90A,
        0xB92B,
        0x5AF5,
        0x4AD4,
        0x7AB7,
        0x6A96,
        0x1A71,
        0x0A50,
        0x3A33,
        0x2A12,
        0xDBFD,
        0xCBDC,
        0xFBBF,
        0xEB9E,
        0x9B79,
        0x8B58,
        0xBB3B,
        0xAB1A,
        0x6CA6,
        0x7C87,
        0x4CE4,
        0x5CC5,
        0x2C22,
        0x3C03,
        0x0C60,
        0x1C41,
        0xEDAE,
        0xFD8F,
        0xCDEC,
        0xDDCD,
        0xAD2A,
        0xBD0B,
        0x8D68,
        0x9D49,
        0x7E97,
        0x6EB6,
        0x5ED5,
        0x4EF4,
        0x3E13,
        0x2E32,
        0x1E51,
        0x0E70,
        0xFF9F,
        0xEFBE,
        0xDFDD,
        0xCFFC,
        0xBF1B,
        0xAF3A,
        0x9F59,
        0x8F78,
        0x9188,
        0x81A9,
        0xB1CA,
        0xA1EB,
        0xD10C,
        0xC12D,
        0xF14E,
        0xE16F,
        0x1080,
        0x00A1,
        0x30C2,
        0x20E3,
        0x5004,
        0x4025,
        0x7046,
        0x6067,
        0x83B9,
        0x9398,
        0xA3FB,
        0xB3DA,
        0xC33D,
        0xD31C,
        0xE37F,
        0xF35E,
        0x02B1,
        0x1290,
        0x22F3,
        0x32D2,
        0x4235,
        0x5214,
        0x6277,
        0x7256,
        0xB5EA,
        0xA5CB,
        0x95A8,
        0x8589,
        0xF56E,
        0xE54F,
        0xD52C,
        0xC50D,
        0x34E2,
        0x24C3,
        0x14A0,
        0x0481,
        0x7466,
        0x6447,
        0x5424,
        0x4405,
        0xA7DB,
        0xB7FA,
        0x8799,
        0x97B8,
        0xE75F,
        0xF77E,
        0xC71D,
        0xD73C,
        0x26D3,
        0x36F2,
        0x0691,
        0x16B0,
        0x6657,
        0x7676,
        0x4615,
        0x5634,
        0xD94C,
        0xC96D,
        0xF90E,
        0xE92F,
        0x99C8,
        0x89E9,
        0xB98A,
        0xA9AB,
        0x5844,
        0x4865,
        0x7806,
        0x6827,
        0x18C0,
        0x08E1,
        0x3882,
        0x28A3,
        0xCB7D,
        0xDB5C,
        0xEB3F,
        0xFB1E,
        0x8BF9,
        0x9BD8,
        0xABBB,
        0xBB9A,
        0x4A75,
        0x5A54,
        0x6A37,
        0x7A16,
        0x0AF1,
        0x1AD0,
        0x2AB3,
        0x3A92,
        0xFD2E,
        0xED0F,
        0xDD6C,
        0xCD4D,
        0xBDAA,
        0xAD8B,
        0x9DE8,
        0x8DC9,
        0x7C26,
        0x6C07,
        0x5C64,
        0x4C45,
        0x3CA2,
        0x2C83,
        0x1CE0,
        0x0CC1,
        0xEF1F,
        0xFF3E,
        0xCF5D,
        0xDF7C,
        0xAF9B,
        0xBFBA,
        0x8FD9,
        0x9FF8,
        0x6E17,
        0x7E36,
        0x4E55,
        0x5E74,
        0x2E93,
        0x3EB2,
        0x0ED1,
        0x1EF0,
    ]

    @staticmethod
    def calc_crc(crc: int, data: bytes) -> int:
        """
        计算 CRC-16 校验和

        Args:
            crc: 初始 CRC 值 (通常为 0)
            data: 要计算校验和的数据

        Returns:
            CRC-16 校验和
        """
        crc = (~crc) & 0xFFFF
        for byte in data:
            crc = BlufiCRC.CRC_TB[(crc >> 8) ^ (byte & 0xFF)] ^ (crc << 8)
            crc &= 0xFFFF
        return (~crc) & 0xFFFF


@dataclass
class BlufiPacket:
    """
    BluFi 协议数据包类

    用于封装 BluFi 协议解析后的数据，便于统一处理。
    属性说明:
        is_blufi (bool): 是否为 BluFi 格式数据包。
            - True: 数据包为 BluFi 协议格式（包含标准 BluFi 头部、序列号、类型等）
            - False: 非 BluFi 包，通常为握手响应等其他自定义格式 (如 KeyMatchHeader)
        seq (int): BluFi 序列号(0-255)。仅当 is_blufi 为 True 时有效，用于确保包顺序和分片重组。
        payload (bytes): 实际载荷数据（不含 BluFi 头部）。
            - 对于 BluFi 包，payload 为解析出的有效负载内容。
            - 对于非 BluFi 包，payload 可为完整接收数据（如握手响应结构体）。
    """

    is_blufi: bool
    """是否为 BluFi 协议包"""
    seq: int
    """BluFi 序列号"""
    payload: bytes
    """载荷数据（去掉 BluFi 头部）"""


class UUIDS(StrEnum):
    """蓝牙UUID配置"""

    SERVICE = "0000ffff-0000-1000-8000-00805f9b34fb"
    """服务UUID"""
    WRITE = "0000ff01-0000-1000-8000-00805f9b34fb"
    """写入特征UUID"""
    READ = "00002902-0000-1000-8000-00805f9b34fb"
    """读取特征UUID"""
    NOTIFY = "0000ff02-0000-1000-8000-00805f9b34fb"
    """通知特征UUID"""


class BluetoothSecureClient:
    """
    蓝牙安全客户端 - 实现加密通讯

    功能:
    1. 搜索并连接蓝牙设备
    2. 执行密钥交换握手
    3. 进行加密数据通讯
    """

    def __init__(self, device_name: str, mtu_size: int = 100):
        """
        初始化蓝牙安全客户端

        Args:
            device_name: 目标设备名称
        """
        self.device_name = device_name
        self.device: BLEDevice | None = None
        self.client: BleakClient | None = None
        self.crypto_client = BluetoothCryptoClient()
        self.handshake_completed = False
        self.notify_enabled = False  # 标记通知是否启用成功

        # 接收数据缓冲区
        self.receive_buffer = bytearray()
        self.receive_event = asyncio.Event()
        self.receive_complete = False  # 标记数据接收是否完整

        # ACK 确认机制
        self.ack_queue: dict[int, asyncio.Event] = {}  # seq -> Event
        self.ack_timeout = 5.0  # ACK 超时时间(秒)

        # BluFi 协议序列号
        self.blufi_seq = 0  # BluFi 协议序列号 (0-255 循环)

        # 分片接收相关
        self.fragment_timeout = 0.5  # 分片超时时间(秒)
        self.last_fragment_time = 0.0  # 上次接收分片的时间

        # BluFi 分片重组相关
        self.blufi_fragment_buffer = bytearray()  # BluFi 分片缓冲区
        self.blufi_expected_seq = 0  # 期望的 BluFi 序列号
        self.blufi_is_fragmenting = False  # 是否正在接收分片

        # MTU 和包大小限制 (参考 pyBlufi 实现)
        self.mtu_size = mtu_size
        # self.mtu_size = 100  # BLE 默认 MTU (Windows/Android 通常为 247)
        self.package_length_limit = -1  # 手动设置的包长度限制 (-1 表示使用 MTU)
        self.default_package_length = 20  # 默认包长度 (BLE 最小值)

    async def search_device(self, timeout: float = 10.0) -> bool:
        """
        搜索指定名称的设备

        Args:
            timeout: 搜索超时时间(秒)

        Returns:
            是否找到设备
        """
        logger.info(f"搜索设备: {self.device_name}")

        device = await BleakScanner.find_device_by_name(name=self.device_name, timeout=timeout)

        if device:
            self.device = device
            logger.info(f"[OK] 找到设备: {device.name} ({device.address})")
            return True
        else:
            logger.error(f"[X] 未找到设备: {self.device_name}")
            return False

    async def connect(self, debug_services: bool = False) -> bool:
        """
        连接蓝牙设备

        Args:
            debug_services: 是否打印所有服务和特征信息(用于调试)

        Returns:
            是否连接成功
        """
        if not self.device:
            logger.error("[X] 设备未找到,请先搜索设备")
            return False

        logger.info(f"连接设备: {self.device.name}")

        # 创建客户端 (增加超时时间)
        self.client = BleakClient(self.device, timeout=30.0)

        await self.client.connect()

        logger.info(f"[OK] 连接成功: {self.device.name}")

        # 等待GATT服务发现完成
        # Windows需要足够时间来稳定连接和发现服务
        logger.info("[!] 等待服务发现...")

        await asyncio.sleep(1.75)

        # 获取 MTU 大小 (参考 pyBlufi 实现)
        # Linux 的 bluez 不提供 MTU 获取接口，需要手动设置
        # try:
        #     if platform.system() != "Linux":
        #         self.mtu_size = self.client.mtu_size
        #         logger.info(f"[OK] MTU 大小: {self.mtu_size} 字节")
        #     else:
        #         logger.info(f"[!] Linux 平台无法自动获取 MTU，使用默认值: {self.mtu_size} 字节")
        # except Exception:
        #     logger.warning(f"[!] 无法获取 MTU 大小，使用默认值: {self.mtu_size} 字节")

        logger.info("[OK] 设备已就绪")

        # 调试模式:打印所有服务和特征
        if debug_services:
            await self._print_services()

        # await asyncio.sleep(1)

        # 启动通知 (带重试机制) - 必须成功才能继续
        # 注意: 不要在启动通知前检查is_connected,会导致误判
        try:
            # 直接启动通知,不要预先检查连接状态
            # Windows的is_connected在服务发现期间可能返回False
            await self.client.start_notify(UUIDS.NOTIFY, self._notification_handler)
            logger.info("[OK] 通知已启动")
            self.notify_enabled = True
            return True
        except BleakError:
            return False
        except OSError:
            logger.exception("[!] 系统错误,启动通知失败")
            return False

    async def _print_services(self):
        """打印设备的所有服务和特征(调试用)"""
        logger.info("\n" + "=" * 60)
        logger.info("设备服务和特征列表:")
        logger.info("=" * 60)

        try:
            # 尝试获取服务
            if not self.client.services:
                logger.warning("[!] 服务列表为空,尝试重新获取...")
                # 在某些平台上需要显式获取服务
                await asyncio.sleep(1)

            services = self.client.services
            if not services:
                logger.error("[X] 无法获取服务列表")
                return

            # 统计服务数量
            service_count = sum(1 for _ in services)
            logger.info(f"[OK] 找到 {service_count} 个服务\n")

            for service in services:
                logger.info(f"[服务] {service.uuid}")
                logger.info(f"  描述: {service.description}")

                for char in service.characteristics:
                    properties = ", ".join(char.properties)
                    logger.info(f"  [特征] {char.uuid}")
                    logger.info(f"    属性: {properties}")
                    logger.info(f"    描述: {char.description}")
                logger.info("")  # 空行分隔

            logger.info("=" * 60 + "\n")

        except Exception as e:
            logger.error(f"[X] 获取服务列表失败: {e}")
            raise

    def get_next_blufi_seq(self) -> int:
        """
        获取下一个 BluFi 序列号

        Returns:
            int: BluFi 序列号 (0-255 循环)
        """
        current_seq = self.blufi_seq
        self.blufi_seq = (self.blufi_seq + 1) % 256  # BluFi 序列号是 8 位, 0-255 循环
        return current_seq

    def reset_blufi_seq(self):
        """重置 BluFi 序列号"""
        self.blufi_seq = 0
        logger.info("[!] BluFi 序列号已重置")

    def set_package_length_limit(self, length_limit: int):
        """
        设置包长度限制 (参考 pyBlufi 的 setPostPackageLengthLimit)

        用于手动限制发送包的大小，特别是在某些平台无法获取 MTU 的情况下。

        Args:
            length_limit: 包长度限制 (字节)
                - 如果 <= 0，则使用 MTU 自动计算
                - 如果 > 0，则使用指定值 (会自动减去 4 字节 BLE 头部)

        Note:
            - ESP32 BLE NimBLE 可以支持最大 512 字节 MTU
            - BluFi 协议限制数据长度字段为 1 字节 (最大 255)
            - BLE Classic 可以支持更高的 MTU
        """
        if length_limit <= 0:
            self.package_length_limit = -1
            logger.info("[OK] 包长度限制已重置，将使用 MTU 自动计算")
        else:
            # 减去 4 字节: 3 字节 BLE 头部 + 1 字节保留 (BluFi 未使用)
            self.package_length_limit = max(length_limit - 4, self.default_package_length)
            logger.info(f"[OK] 包长度限制已设置: {self.package_length_limit} 字节")

    def get_max_fragment_size(self) -> int:
        """
        获取最大分片大小 (参考 pyBlufi 的 postContainData 实现)

        Returns:
            最大分片大小 (字节)
        """
        # 包长度限制 = 手动设置 > MTU > 默认值
        if self.package_length_limit > 0:
            pkg_limit = self.package_length_limit
        elif self.mtu_size > 0:
            pkg_limit = self.mtu_size - 4  # 减去 4 字节 BluFi 头部
        else:
            pkg_limit = self.default_package_length

        # 减去 BluFi 包头 (4 字节) 和分片总长度字段 (2 字节)
        max_frag_size = pkg_limit - 4 - 2

        logger.debug(f"[DEBUG] 最大分片大小: {max_frag_size} 字节 (包限制={pkg_limit})")
        return max_frag_size

    def parse_ack_packet(self, data: bytes) -> int | None:
        """
        解析 ACK 数据包 (参考 pyBlufi 的 parseAck 实现)

        ACK 包格式: [seq(1字节)]

        Args:
            data: ACK 数据

        Returns:
            ACK 的序列号，如果解析失败则返回 None
        """
        if len(data) > 0:
            ack_seq = data[0] & 0xFF
            logger.debug(f"[OK] 解析 ACK: seq={ack_seq}")
            return ack_seq
        else:
            logger.warning("[!] ACK 数据为空")
            return None

    async def wait_for_ack(self, seq: int, timeout: float | None = None) -> bool:
        """
        等待指定序列号的 ACK 确认

        Args:
            seq: 序列号
            timeout: 超时时间(秒)，None 表示使用默认超时

        Returns:
            是否收到 ACK
        """
        if timeout is None:
            timeout = self.ack_timeout

        # 创建事件
        event = asyncio.Event()
        self.ack_queue[seq] = event

        try:
            # 等待 ACK
            await asyncio.wait_for(event.wait(), timeout=timeout)
            logger.debug(f"[OK] 收到 ACK: seq={seq}")
            return True
        except asyncio.TimeoutError:
            logger.warning(f"[!] 等待 ACK 超时: seq={seq}")
            return False
        finally:
            # 清理事件
            if seq in self.ack_queue:
                del self.ack_queue[seq]

    def notify_ack_received(self, seq: int):
        """
        通知收到 ACK

        Args:
            seq: ACK 的序列号
        """
        if seq in self.ack_queue:
            self.ack_queue[seq].set()
            logger.debug(f"[OK] 触发 ACK 事件: seq={seq}")

    def create_blufi_packet(
        self,
        data: bytes,
        blufi_seq: int,
        packet_type: int = 0x04,
        frame_ctrl: int = 0x00,
        max_fragment_size: int = 0,  # 0 表示不分片
        enable_checksum: bool = False,  # 是否启用校验和
    ) -> list[bytes]:
        """
        创建 BluFi 协议数据包 (支持分片) - 完全兼容 pyBlufi 实现

        BluFi 数据包格式:
            [0] Type: 包类型 (例如 0x04 表示自定义数据)
            [1] Frame Control: 帧控制字段
                - Bit 0: 加密标志
                - Bit 1: 校验标志
                - Bit 2: 数据方向
                - Bit 3: 需要应答
                - Bit 4: 分片标志
                - Bit 5-7: 保留
            [2] Sequence: 序列号 (0-255)
            [3] Length: 载荷长度
            [4:] Payload: 载荷数据
                - 如果是分片包，前2字节为总长度(小端序)

        Args:
            data: 原始载荷数据
            blufi_seq: BluFi 序列号 (0-255)
            packet_type: 包类型 (默认 0x04)
            frame_ctrl: 帧控制字段 (默认 0x00)
            max_fragment_size: 最大分片大小 (0 表示不分片, 通常为 MTU-4-2=242, 减去2字节总长度字段)

        Returns:
            list[bytes]: BluFi 数据包列表 (如果分片则返回多个包)
        """

        packets = []
        data_len = len(data)

        # 如果启用校验和，设置 Frame Control 的 Bit 1
        if enable_checksum:
            frame_ctrl |= 0x02

        # BluFi 协议限制: Length 字段只有 1 字节，最大 255
        BLUFI_MAX_PAYLOAD_LEN = 255

        # 如果请求分片，限制分片大小不超过协议最大值
        if max_fragment_size > BLUFI_MAX_PAYLOAD_LEN:
            logger.warning(f"[!] 分片大小 {max_fragment_size} 超过协议限制，调整为 {BLUFI_MAX_PAYLOAD_LEN}")
            max_fragment_size = BLUFI_MAX_PAYLOAD_LEN

        # 如果不需要分片或数据足够小
        if max_fragment_size == 0 or data_len <= max_fragment_size:
            # 单个完整包
            if data_len > BLUFI_MAX_PAYLOAD_LEN:
                # 数据超过单包限制，强制分片
                logger.warning(f"[!] 数据 {data_len} 字节超过单包限制，强制分片")
                max_fragment_size = BLUFI_MAX_PAYLOAD_LEN
            else:
                # 计算校验和 (参考 pyBlufi 的 getPostBytes 实现)
                if enable_checksum:
                    # 校验和计算: CRC(seq + data_len + data)
                    checksum_data = struct.pack("<BB", blufi_seq, data_len)
                    crc = BlufiCRC.calc_crc(0, checksum_data)
                    if data_len > 0:
                        crc = BlufiCRC.calc_crc(crc, data)
                    checksum_bytes = struct.pack("<H", crc)  # 小端序 2 字节
                    blufi_packet = bytes([packet_type, frame_ctrl, blufi_seq, data_len]) + data + checksum_bytes
                else:
                    blufi_packet = bytes([packet_type, frame_ctrl, blufi_seq, data_len]) + data

                packets.append(blufi_packet)
                logger.info(
                    f"[OK] 创建 BluFi 包: 类型=0x{packet_type:02x}, seq={blufi_seq}, "
                    f"大小={data_len}字节, 校验={'是' if enable_checksum else '否'}"
                )
                return packets

        # 需要分片 - 参考 pyBlufi 的 postContainData 实现
        offset = 0
        seq = blufi_seq
        frag_index = 0

        # 每个分片需要减去2字节用于存储总长度字段
        actual_frag_size = max_fragment_size - 2

        while offset < data_len:
            # 计算当前分片的实际数据大小
            remaining = data_len - offset
            current_frag_data_size = min(remaining, actual_frag_size)
            frag_data = data[offset : offset + current_frag_data_size]

            # 判断是否还有后续分片
            has_more_frags = (offset + current_frag_data_size) < data_len

            # 设置分片标志
            if has_more_frags:
                # 还有后续分片,设置分片标志 (Bit 4)
                frag_ctrl = frame_ctrl | 0x10
            else:
                # 最后一个分片,不设置分片标志
                frag_ctrl = frame_ctrl

            # 对齐 msgbus.blufibus.post_contain_data:
            # 每个 has_frag=True 的分片都带 2 字节 total_len
            if has_more_frags:
                total_len = data_len
                frag_payload = struct.pack("<H", total_len) + frag_data
            else:
                frag_payload = frag_data

            payload_len = len(frag_payload)

            # BluFi 协议限制检查
            if payload_len > BLUFI_MAX_PAYLOAD_LEN:
                raise ValueError(f"分片载荷 {payload_len} 字节超过协议限制 {BLUFI_MAX_PAYLOAD_LEN}")

            # 计算校验和 (如果启用)
            if enable_checksum:
                # 校验和计算: CRC(seq + payload_len + frag_payload)
                checksum_data = struct.pack("<BB", seq, payload_len)
                crc = BlufiCRC.calc_crc(0, checksum_data)
                if payload_len > 0:
                    crc = BlufiCRC.calc_crc(crc, frag_payload)
                checksum_bytes = struct.pack("<H", crc)
                # 创建分片包: [Type][FrameCtrl][Seq][Length][Payload][Checksum]
                frag_packet = bytes([packet_type, frag_ctrl, seq, payload_len]) + frag_payload + checksum_bytes
            else:
                # 创建分片包: [Type][FrameCtrl][Seq][Length][Payload]
                frag_packet = bytes([packet_type, frag_ctrl, seq, payload_len]) + frag_payload

            packets.append(frag_packet)

            logger.info(
                f"[OK] 创建 BluFi 分片 #{frag_index}: 类型=0x{packet_type:02x}, "
                f"seq={seq}, 载荷={payload_len}字节 (数据={current_frag_data_size}字节), "
                f"分片={'是' if has_more_frags else '否'}"
            )

            offset += current_frag_data_size
            seq = (seq + 1) % 256
            frag_index += 1

        logger.info(f"[OK] BluFi 分片完成: 总计 {frag_index} 个分片, 原始数据 {data_len} 字节")

        return packets

    def parse_blufi_packet(self, data: bytearray) -> tuple[bool, int, int, bytes] | None:
        """
        解析 BluFi 协议数据包 (支持分片) - 完全兼容 pyBlufi 实现

        BluFi 帧格式:
        - Byte 0: Type (类型字段)
        - Byte 1: Frame Control (帧控制字段)
            - Bit 0: 加密标志 (1=加密, 0=未加密)
            - Bit 1: 校验标志 (1=有校验, 0=无校验)
            - Bit 2: 数据方向 (1=发送, 0=接收)
            - Bit 3: 需要应答 (1=需要, 0=不需要)
            - Bit 4: 分片标志 (1=分片, 0=完整)
            - Bit 5-7: 保留
        - Byte 2: Sequence (序列号)
        - Byte 3: Data Length (数据长度)
        - Byte 4+: Data (数据)
            - 如果是分片，前2字节为总长度(小端序)，后面是实际数据

        Args:
            data: 接收到的原始数据

        Returns:
            tuple: (is_frag, seq, frame_ctrl, payload) 或 None
                - is_frag: 是否是分片
                - seq: 序列号
                - frame_ctrl: 帧控制字段
                - payload: 载荷数据 (如果是分片，已去除总长度字段)
        """

        try:
            if len(data) < 4:
                logger.warning(f"[!] 数据包太短: {len(data)} 字节")
                return None

            packet_type = data[0]
            frame_ctrl = data[1]
            sequence = data[2]
            length = data[3]

            # 检查长度
            if len(data) < 4 + length:
                logger.warning(f"[!] 数据包长度不足: 期望 {4 + length}, 实际 {len(data)}")
                return None

            # 提取载荷
            payload = bytes(data[4 : 4 + length])

            # 解析帧控制字段
            is_encrypted = (frame_ctrl & 0x01) != 0
            has_checksum = (frame_ctrl & 0x02) != 0
            data_direction = (frame_ctrl & 0x04) != 0  # noqa: F841 - 保留用于协议完整性
            require_ack = (frame_ctrl & 0x08) != 0  # noqa: F841 - 保留用于协议完整性
            is_frag = (frame_ctrl & 0x10) != 0  # Bit 4: 分片标志

            # 验证校验和 (如果启用) - 参考 pyBlufi 的 parseNotification 实现
            if has_checksum:
                if len(data) < 4 + length + 2:
                    logger.warning(f"[!] 校验和数据不足: 期望 {4 + length + 2}, 实际 {len(data)}")
                    return None

                # 提取校验和 (最后 2 字节，小端序)
                received_checksum = struct.unpack("<H", data[4 + length : 4 + length + 2])[0]

                # 计算校验和: CRC(seq + length + payload)
                checksum_data = struct.pack("<BB", sequence, length)
                calc_crc = BlufiCRC.calc_crc(0, checksum_data)
                if length > 0:
                    calc_crc = BlufiCRC.calc_crc(calc_crc, payload)

                if received_checksum != calc_crc:
                    logger.error(f"[X] 校验和验证失败: 接收=0x{received_checksum:04x}, 计算=0x{calc_crc:04x}")
                    return None
                else:
                    logger.debug("[OK] 校验和验证通过")

            # 如果是分片包，提取总长度字段并去除
            # 参考 pyBlufi 的 parseNotification 实现
            if is_frag and len(payload) >= 2:
                # 前2字节是总长度(小端序)
                total_len = struct.unpack("<H", payload[:2])[0]
                # 实际数据从第3字节开始
                actual_payload = payload[2:]
                logger.info(
                    f"[OK] BluFi分片包解析: 类型=0x{packet_type:02x}, 帧控制=0x{frame_ctrl:02x}, "
                    f"seq={sequence}, 总长度={total_len}字节, 当前分片数据={len(actual_payload)}字节, "
                    f"加密={'是' if is_encrypted else '否'}"
                )
                return (is_frag, sequence, frame_ctrl, actual_payload)
            else:
                logger.info(
                    f"[OK] BluFi包解析: 类型=0x{packet_type:02x}, 帧控制=0x{frame_ctrl:02x}, "
                    f"seq={sequence}, 载荷={length}字节, "
                    f"分片={'是' if is_frag else '否'}, 加密={'是' if is_encrypted else '否'}"
                )
                return (is_frag, sequence, frame_ctrl, payload)

        except Exception:
            logger.exception("[X] BluFi包解析失败")
            return None

    def _notification_handler(self, sender: BleakGATTCharacteristic, data: bytearray):
        """
        蓝牙通知回调处理函数 (支持 BluFi 分片重组)

        Args:
            sender: 发送者 (BleakGATTCharacteristic - 触发通知的特征对象)
            data: 接收到的数据
        """
        logger.info(f"[DEBUG] _notification_handler 被调用: {len(data)} 字节")

        current_time = time.time()

        # 检查是否是新的数据包 (距离上次接收超过超时时间)
        if current_time - self.last_fragment_time > self.fragment_timeout:
            # 新的数据包,清空缓冲区
            if self.receive_buffer:
                logger.info(f"[!] 上一个数据包超时,清空缓冲区 ({len(self.receive_buffer)} 字节)")
            self.receive_buffer.clear()
            self.receive_complete = False

            # 清空 BluFi 分片缓冲区
            if self.blufi_fragment_buffer:
                logger.info(f"[!] BluFi 分片超时,清空分片缓冲区 ({len(self.blufi_fragment_buffer)} 字节)")
            self.blufi_fragment_buffer.clear()
            self.blufi_is_fragmenting = False

        self.last_fragment_time = current_time

        logger.info(f"[OK] 接收通知数据: {len(data)} 字节, hex: {data.hex()}")

        # 尝试解析 BluFi 包
        if len(data) >= 4:
            blufi_result = self.parse_blufi_packet(data)

            if blufi_result is not None:
                is_frag, seq, frame_ctrl, payload = blufi_result

                # 检查是否是 ACK 包 (Type=0x00, SubType=0x00)
                # Type 字段: [SubType(6bit)][PackageType(2bit)]
                packet_type = data[0]
                pkg_type = packet_type & 0b11  # 低 2 位
                sub_type = (packet_type & 0b11111100) >> 2  # 高 6 位

                # CTRL.PACKAGE_VALUE = 0x00, CTRL.SUBTYPE_ACK = 0x00
                if pkg_type == 0x00 and sub_type == 0x00:
                    # 这是一个 ACK 包
                    ack_seq = self.parse_ack_packet(payload)
                    if ack_seq is not None:
                        logger.info(f"[OK] 接收 ACK: seq={ack_seq}")
                        self.notify_ack_received(ack_seq)
                    return  # ACK 包处理完毕，不继续处理

                # 处理 BluFi 分片
                if is_frag:
                    # 这是一个分片
                    logger.info(f"[OK] 接收 BluFi 分片: seq={seq}, 载荷={len(payload)}字节")

                    # 检查序列号是否连续
                    if not self.blufi_is_fragmenting:
                        # 第一个分片
                        logger.info(f"[OK] 开始 BluFi 分片重组: seq={seq}")
                        self.blufi_fragment_buffer.clear()
                        self.blufi_fragment_buffer.extend(payload)
                        self.blufi_expected_seq = (seq + 1) % 256
                        self.blufi_is_fragmenting = True
                    elif seq == self.blufi_expected_seq:
                        # 后续分片,序列号正确
                        logger.info(f"[OK] 追加 BluFi 分片: seq={seq}, 累积={len(self.blufi_fragment_buffer) + len(payload)}字节")
                        self.blufi_fragment_buffer.extend(payload)
                        self.blufi_expected_seq = (seq + 1) % 256
                    else:
                        # 序列号不匹配,丢弃之前的分片,重新开始
                        logger.warning(f"[!] BluFi 分片序列号不匹配: 期望={self.blufi_expected_seq}, 实际={seq}, 重新开始")
                        self.blufi_fragment_buffer.clear()
                        self.blufi_fragment_buffer.extend(payload)
                        self.blufi_expected_seq = (seq + 1) % 256

                    # 分片未完成,继续等待
                    return

                else:
                    # 这是完整的包或最后一个分片
                    if self.blufi_is_fragmenting:
                        # 最后一个分片
                        logger.info(f"[OK] 接收 BluFi 最后分片: seq={seq}, 载荷={len(payload)}字节")
                        self.blufi_fragment_buffer.extend(payload)

                        # 分片重组完成
                        logger.info(f"[OK] BluFi 分片重组完成: 总计={len(self.blufi_fragment_buffer)}字节")
                        self.receive_buffer.clear()
                        self.receive_buffer.extend(self.blufi_fragment_buffer)
                        self.blufi_fragment_buffer.clear()
                        self.blufi_is_fragmenting = False
                        self.receive_complete = True
                        self.receive_event.set()
                        return
                    else:
                        # 完整的单个 BluFi 包
                        logger.info(f"[OK] 接收完整 BluFi 包: seq={seq}, 载荷={len(payload)}字节")
                        self.receive_buffer.clear()
                        self.receive_buffer.extend(payload)
                        self.receive_complete = True
                        self.receive_event.set()
                        return

        # 不是 BluFi 包,可能是握手阶段的数据
        # 累积接收数据
        self.receive_buffer.extend(data)
        logger.info(f"[OK] 缓冲区累积(非BluFi): {len(self.receive_buffer)} 字节")

        # 检查是否是完整的握手响应包 (KeyMatchHeader)
        # KeyMatchHeader 格式: [client_pub_len(1字节)][is_change(1字节)][data(变长)]
        if len(self.receive_buffer) >= 2:
            # 读取预期数据长度
            is_change = self.receive_buffer[1]
            if is_change == 0x14:  # PAIR_STAGE_STATUS_SUCC
                # 第2次握手响应: 2字节头部 + 64字节hex字符串 = 66字节
                expected_length = 66
                if len(self.receive_buffer) >= expected_length:
                    logger.info(f"[OK] 接收完整握手响应: {len(self.receive_buffer)} 字节")
                    self.receive_complete = True
                    self.receive_event.set()
                    return
                else:
                    logger.info(
                        f"[!] 握手响应未完整,期望 {expected_length} 字节,当前 {len(self.receive_buffer)} 字节,继续等待..."
                    )
            elif is_change == 0x17:  # PAIR_STAGE_DEVICE_INFO
                # 设备信息包 (protobuf),长度不固定
                # 等待更多数据或超时
                logger.info(f"[!] 接收设备信息包,当前 {len(self.receive_buffer)} 字节,继续等待...")
            else:
                # 其他类型的包,假设当前数据已完整
                logger.info(f"[OK] 接收其他类型数据包: {len(self.receive_buffer)} 字节 (is_change=0x{is_change:02x})")
                self.receive_complete = True
                self.receive_event.set()
                return

        # 数据包未完整,继续等待
        logger.info(f"[!] 数据包未完整,继续等待... (当前 {len(self.receive_buffer)} 字节)")

    async def _wait_for_response(self, timeout: float = 10.0) -> bytes:
        """
        等待接收响应数据 (仅通知模式)

        支持分片数据接收:
        - 如果数据未完整,会持续等待直到超时
        - 超时后返回已接收的数据

        Args:
            timeout: 超时时间(秒)

        Returns:
            接收到的数据

        Raises:
            RuntimeError: 如果通知未启用
            asyncio.TimeoutError: 如果等待超时且未接收到任何数据
        """
        if not self.notify_enabled:
            raise RuntimeError("通知模式未启用,无法接收数据!")

        start_time = time.time()
        last_buffer_size = 0

        try:
            while True:
                # 计算剩余超时时间
                elapsed = time.time() - start_time
                remaining_timeout = timeout - elapsed

                if remaining_timeout <= 0:
                    # 总超时,检查是否有部分数据
                    if self.receive_buffer:
                        logger.warning(f"[!] 等待超时,返回部分数据: {len(self.receive_buffer)} 字节")
                        data = bytes(self.receive_buffer)
                        self.receive_buffer.clear()
                        self.receive_event.clear()
                        self.receive_complete = False
                        return data
                    else:
                        logger.error("[X] 等待响应超时且未接收到任何数据")
                        raise asyncio.TimeoutError("未接收到任何数据")

                try:
                    # 等待数据接收事件或超时
                    await asyncio.wait_for(self.receive_event.wait(), timeout=min(remaining_timeout, 1.0))

                    # 检查数据是否完整
                    if self.receive_complete:
                        # 数据接收完整
                        data = bytes(self.receive_buffer)
                        logger.info(f"[OK] 接收完整数据: {len(data)} 字节")

                        # 清空缓冲区和事件
                        self.receive_buffer.clear()
                        self.receive_event.clear()
                        self.receive_complete = False

                        return data
                    else:
                        # 数据未完整,继续等待
                        logger.info(f"[!] 数据未完整 ({len(self.receive_buffer)} 字节),继续等待...")
                        self.receive_event.clear()  # 清除事件,等待下一个分片
                        continue

                except asyncio.TimeoutError:
                    # 分片接收超时,检查缓冲区大小是否增长
                    current_size = len(self.receive_buffer)
                    if current_size > 0 and current_size == last_buffer_size:
                        # 缓冲区没有增长,认为数据接收完毕
                        logger.info(f"[OK] 分片接收完成(超时): {current_size} 字节")
                        data = bytes(self.receive_buffer)
                        self.receive_buffer.clear()
                        self.receive_event.clear()
                        self.receive_complete = False
                        return data
                    else:
                        # 缓冲区增长,继续等待
                        last_buffer_size = current_size
                        continue

        except asyncio.TimeoutError:
            logger.error("[X] 等待响应超时")
            raise

    async def perform_handshake(self) -> bool:
        """
        执行密钥交换握手

        Returns:
            是否握手成功
        """
        if not self.client:
            logger.error("[X] 客户端未初始化")
            return False

        try:
            logger.info("\n" + "=" * 60)
            logger.info("开始密钥交换握手")
            logger.info("=" * 60 + "\n")

            # ==================== 第1次握手 ====================
            # 发送客户端加密公钥
            request = await self.crypto_client.handshake_step1_send_public_key()

            # 参考 ble_client.py: 握手也需要 BluFi 封装
            # send_data() 中: head = [77, 0, seqs, len_data]  # 77 = 0x4D
            # 包类型使用 0x4D (握手和通讯都使用相同类型)
            blufi_seq = self.get_next_blufi_seq()
            blufi_packets = self.create_blufi_packet(request, blufi_seq, packet_type=0x4D)

            logger.info("[→] 发送握手请求:")
            logger.info(f"    KeyMatchHeader: {len(request)} 字节")
            logger.info(f"    BluFi包数量: {len(blufi_packets)} (type=0x4D, seq={blufi_seq})")

            # 发送所有分片
            for i, blufi_packet in enumerate(blufi_packets):
                logger.info(f"    发送分片 #{i}: {len(blufi_packet)} 字节, hex: {blufi_packet.hex()}")
                try:
                    # 使用 write with response 确保数据真正发送到设备
                    await self.client.write_gatt_char(UUIDS.WRITE, blufi_packet, response=True)
                    logger.info(f"[OK] 分片 #{i} 使用 write-with-response 发送成功")
                except Exception:
                    logger.exception(f"[!] 分片 #{i} write-with-response 失败,尝试 write-without-response...")
                    # 失败则尝试 write without response
                    await self.client.write_gatt_char(UUIDS.WRITE, blufi_packet, response=False)
                    logger.info(f"[OK] 分片 #{i} 使用 write-without-response 发送成功")

                # 分片之间稍微延迟
                if i < len(blufi_packets) - 1:
                    await asyncio.sleep(0.02)

            # 给设备一点时间处理数据
            await asyncio.sleep(0.1)

            # 等待服务器响应
            response = await self._wait_for_response()
            logger.info(f"[DEBUG] 收到第2次握手响应: {len(response)} 字节, hex: {response.hex()}")

            # ==================== 第2次握手 ====================
            # 处理服务器公钥
            success = await self.crypto_client.handshake_step2_receive_server_key(response)

            if not success:
                logger.error("[X] 处理服务器响应失败")
                return False

            # ==================== 第3次握手 ====================
            # 发送确认
            confirm = await self.crypto_client.handshake_step3_confirm()

            # 握手确认也需要 BluFi 封装,包类型使用 0x4D
            blufi_seq = self.get_next_blufi_seq()
            blufi_confirm_packets = self.create_blufi_packet(confirm, blufi_seq, packet_type=0x4D)

            logger.info("[→] 发送确认:")
            logger.info(f"    确认数据: {len(confirm)} 字节")
            logger.info(f"    BluFi包数量: {len(blufi_confirm_packets)} (type=0x4D, seq={blufi_seq})")

            # 发送所有分片
            for i, blufi_confirm in enumerate(blufi_confirm_packets):
                logger.info(f"    发送分片 #{i}: {len(blufi_confirm)} 字节, hex: {blufi_confirm.hex()}")
                try:
                    await self.client.write_gatt_char(UUIDS.WRITE, blufi_confirm, response=True)
                    logger.info(f"[OK] 分片 #{i} 使用 write-with-response 发送成功")
                except Exception:
                    logger.exception(f"[!] 分片 #{i} write-with-response 失败,尝试 write-without-response...")
                    await self.client.write_gatt_char(UUIDS.WRITE, blufi_confirm, response=False)
                    logger.info(f"[OK] 分片 #{i} 使用 write-without-response 发送成功")

                # 分片之间稍微延迟
                if i < len(blufi_confirm_packets) - 1:
                    await asyncio.sleep(0.02)

            # 获取第3次握手使用的序列号
            handshake3_seq = blufi_seq
            logger.info(f"[DEBUG] 第3次握手使用的序列号: {handshake3_seq}")

            self.handshake_completed = True

            # 重置BluFi序列号
            # 服务器期望下一个是 seq=2
            # get_next_blufi_seq() 是先返回当前值再递增
            # 所以需要将序列号设置为 2，这样下一个 get_next_blufi_seq() 返回 2
            self.blufi_seq = 2  # 下一个 get_next_blufi_seq() 返回 2
            self.blufi_expected_seq = 2

            logger.info(f"[!] BluFi序列号已重置，blufi_seq={self.blufi_seq}，下一个序列号将为 {self.blufi_seq}")

            logger.info("\n" + "=" * 60)
            logger.info("密钥交换握手完成!")
            logger.info("=" * 60 + "\n")

            # 等待服务器准备好接收加密数据
            await asyncio.sleep(0.2)

            return True

        except BleakCharacteristicNotFoundError:
            logger.exception("[X] 特征未找到,无法进行握手")
            return False

        except Exception:
            logger.exception("[X] 握手失败")
            return False

    async def send_encrypted_data(self, data: bytes, require_ack: bool = False) -> bool:
        """
        发送加密数据 (使用 BluFi 协议，支持自动分片)

        Args:
            data: 明文数据
            require_ack: 是否需要 ACK 确认

        Returns:
            是否发送成功
        """
        if not self.handshake_completed:
            logger.error("[X] 未完成握手,无法发送加密数据")
            return False

        try:
            # 加密数据
            encrypted = await self.crypto_client.encrypt_send_data(data)

            # 获取最大分片大小 (自动根据 MTU 计算)
            max_frag_size = self.get_max_fragment_size()

            # 设置 Frame Control
            # Bit 0: 加密标志 (必须设置！)
            # Bit 3: 需要应答
            frame_ctrl = 0x01  # 加密标志
            if require_ack:
                frame_ctrl |= 0x08  # Bit 3: Require ACK

            # 使用BluFi协议封装 (支持分片)
            blufi_seq = self.get_next_blufi_seq()
            logger.info(f"[DEBUG] 发送加密数据 - 当前序列号: {blufi_seq}, blufi_seq状态: {self.blufi_seq}")
            blufi_packets = self.create_blufi_packet(
                encrypted,
                blufi_seq,
                packet_type=0x4D,
                frame_ctrl=frame_ctrl,
                max_fragment_size=max_frag_size,
            )

            logger.info("[→] 发送加密数据:")
            logger.info(f"    明文: {len(data)} 字节")
            logger.info(f"    加密后: {len(encrypted)} 字节")
            logger.info(f"    加密数据(hex): {encrypted.hex()}")
            logger.info(f"    最大分片: {max_frag_size} 字节")
            logger.info(f"    BluFi包数量: {len(blufi_packets)} (起始seq={blufi_seq})")
            logger.info(f"    需要ACK: {'是' if require_ack else '否'}")

            # 发送所有分片 (参考 pyBlufi 的延迟策略)
            for fragment, blufi_packet in enumerate(blufi_packets):
                # 从包中提取序列号，不应再调用 get_next_blufi_seq()
                current_seq = blufi_packet[2]
                logger.info(f"    发送分片 #{fragment}: {len(blufi_packet)} 字节, seq={current_seq}")

                try:
                    # 优先使用 write-with-response 确保可靠传输
                    await self.client.write_gatt_char(UUIDS.WRITE, blufi_packet, response=True)
                except Exception:
                    # 失败则尝试 write-without-response
                    logger.debug(f"[!] 分片 #{fragment} write-with-response 失败，尝试 write-without-response")
                    await self.client.write_gatt_char(UUIDS.WRITE, blufi_packet, response=False)

                # 如果需要 ACK，等待确认
                if require_ack:
                    ack_received = await self.wait_for_ack(current_seq, timeout=self.ack_timeout)
                    if not ack_received:
                        logger.error(f"[X] 分片 #{fragment} ACK 超时，发送失败")
                        return False

                # 分片之间延迟 50ms (参考 pyBlufi 实现)
                if fragment < len(blufi_packets) - 1:
                    await asyncio.sleep(0.05)

            # 更新 blufi_seq 为下一个可用序列号
            # 获取最后一个分片的序列号，然后 +1
            if blufi_packets:
                last_packet = blufi_packets[-1]
                last_seq = last_packet[2]
                self.blufi_seq = (last_seq + 1) % 256
                logger.debug(f"[DEBUG] 发送完成，更新 blufi_seq 为: {self.blufi_seq}")

            logger.info("[OK] 发送加密数据成功")

            return True

        except Exception:
            logger.exception("[X] 发送失败")
            return False

    async def receive_encrypted_data(self, timeout: float = 10.0) -> bytes | None:
        """
        接收并解密数据

        Args:
            timeout: 超时时间(秒)

        Returns:
            解密后的明文数据
        """
        if not self.handshake_completed:
            logger.error("[X] 未完成握手,无法接收加密数据")
            return None

        try:
            # 等待接收数据
            encrypted = await self._wait_for_response(timeout)

            # 解密数据
            plaintext = await self.crypto_client.decrypt_receive_data(encrypted)

            logger.info(f"[OK] 接收解密数据: {len(plaintext)} 字节")
            return plaintext

        except Exception:
            logger.exception("[X] 接收失败")
            return None

    async def disconnect(self):
        """断开连接"""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            logger.info("[OK] 已断开连接")

    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出"""
        await self.disconnect()
