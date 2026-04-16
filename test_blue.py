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

                    cmd_data = light_ctrl(hex_data="1").create_msg()
                    print(f"[→] 开灯命令: {len(cmd_data)} 字节")
                    print(f"[→] 命令数据(hex): {cmd_data.hex()}")

                    await client.send_encrypted_data(cmd_data)
                    print("[OK] 开灯命令已发送")

                    # 等待并接收设备响应
                    print("[←] 等待设备响应...")
                    try:
                        response = await client.receive_encrypted_data(timeout=5.0)
                        if response:
                            print(f"[←] 收到响应: {len(response)} 字节")
                            print(f"[←] 响应数据(hex): {response.hex()}")
                        else:
                            print("[!] 未收到响应")
                    except Exception as e:
                        print(f"[!] 接收响应失败: {e}")

                    await asyncio.sleep(2)

                    print("[→] 发送关灯命令...")
                    cmd_data = light_ctrl(hex_data="1").create_msg()
                    await client.send_encrypted_data(cmd_data)
                    print("[OK] 关灯命令已发送")

                    # 等待并接收设备响应
                    print("[←] 等待设备响应...")
                    try:
                        response = await client.receive_encrypted_data(timeout=5.0)
                        if response:
                            print(f"[←] 收到响应: {len(response)} 字节")
                            print(f"[←] 响应数据(hex): {response.hex()}")
                        else:
                            print("[!] 未收到响应")
                    except Exception as e:
                        print(f"[!] 接收响应失败: {e}")
                else:
                    print("[X] 密钥交换失败")
        else:
            print("[X] 设备未找到")


if __name__ == "__main__":
    asyncio.run(main("Luba-VAG56M9R"))