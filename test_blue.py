from bluetooth_secure_client import BluetoothSecureClient
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'radar'))
from radar.protobuf_msg import MessagePB, ProtoBufType, light_ctrl
from radar.pb import mctrl_sys_pb2, Luba_msg_pb2


async def main(device_name: str = "YourDeviceName"):
    async with BluetoothSecureClient(device_name) as client:
        if await client.search_device():
            if await client.connect():
                if await client.perform_handshake():
                    print("[OK] 密钥交换完成")
                    print("[→] 发送开灯命令...")

                    cmd_data = light_ctrl(on=True).create_msg()
                    print(f"[→] 开灯命令: {len(cmd_data)} 字节")
                    print(f"[→] 命令数据(hex): {cmd_data.hex()}")

                    await client.send_encrypted_data(cmd_data)
                    print("[OK] 开灯命令已发送")

                    await asyncio.sleep(2)

                    print("[→] 发送关灯命令...")
                    cmd_data = light_ctrl(on=False).create_msg()
                    await client.send_encrypted_data(cmd_data)
                    print("[OK] 关灯命令已发送")
                else:
                    print("[X] 密钥交换失败")
        else:
            print("[X] 设备未找到")


if __name__ == "__main__":
    asyncio.run(main("Luba-VAG56M9R"))