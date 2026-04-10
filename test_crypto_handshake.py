from __future__ import annotations

import asyncio
import logging
import os

from bluetooth_secure_client import BluetoothSecureClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(asctime)s %(filename)s|%(lineno)d: %(message)s")
logger = logging.getLogger(__name__)


async def demo_secure_communication(device_name: str):
    """演示安全通讯流程"""

    # 目标设备名称 (修改为你的设备名称)
    DEVICE_NAME = device_name

    async with BluetoothSecureClient(DEVICE_NAME) as client:
        # 1. 搜索设备
        if not await client.search_device():
            logger.error("未找到设备")
            return

        # 2. 连接设备 (强制使用通知模式)
        # 注意: 必须使用通知模式才能正确接收握手响应
        if not await client.connect():
            logger.error("连接失败")
            return

        # 2.5. 测试写入方法 (可选,可能导致连接断开)
        # await client.test_write_methods()

        # 3. 执行握手
        if not await client.perform_handshake():
            logger.error("握手失败")
            return

        # 4. 发送加密消息, 依次发送100字节, 256字节, 512字节, 1K(1024字节)的随机数据
        test_sizes = [100, 256, 512, 1024]
        # test_sizes = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

        for size in test_sizes:
            test_message = os.urandom(size)
            if await client.send_encrypted_data(test_message):
                logger.info(f"[OK] 发送加密消息: {size}字节，首16字节: {test_message[:16]!r} 总长: {len(test_message)} bytes")

                # 5. 接收加密响应 (可选)
                try:
                    logger.info("[!] 开始等待响应...")
                    response = await client.receive_encrypted_data(timeout=10.0)
                    if response:
                        # logger.info(f"[OK] 接收响应: {response.hex()}")
                        logger.info(f"[OK] 接收响应: {response}")
                except asyncio.TimeoutError:
                    logger.warning("未收到响应(可能设备不回复)")
                except UnicodeDecodeError:
                    logger.exception("[X] 解密响应失败(可能是protobuf格式)")
                except Exception:
                    logger.exception("[X] 其他错误")

        logger.info("[OK] 安全通讯演示完成")


if __name__ == "__main__":
    # asyncio.run(demo_secure_communication("Luba-VA7VA49Z"))
    # asyncio.run(demo_secure_communication("Luba-MBU5LMMD"))
    asyncio.run(demo_secure_communication("Luba-LAC9T5BM"))
