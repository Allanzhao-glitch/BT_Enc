"""
BluFi 传输机制使用示例

演示如何使用完善后的 BluFi 协议进行数据传输
"""

import asyncio

from bluetooth_secure_client import BluetoothSecureClient


async def basic_example():
    """基本使用示例"""
    print("=" * 60)
    print("基本使用示例")
    print("=" * 60)

    # 创建客户端
    client = BluetoothSecureClient("BLUFI_DEVICE")

    try:
        # 1. 搜索设备
        print("\n[1] 搜索设备...")
        if not await client.search_device(timeout=10.0):
            print("❌ 未找到设备")
            return

        # 2. 连接设备
        print("\n[2] 连接设备...")
        if not await client.connect():
            print("❌ 连接失败")
            return

        print(f"✅ MTU 大小: {client.mtu_size} 字节")
        print(f"✅ 最大分片: {client.get_max_fragment_size()} 字节")

        # 3. 执行握手
        print("\n[3] 执行握手...")
        if not await client.perform_handshake():
            print("❌ 握手失败")
            return

        # 4. 发送小数据（不分片）
        print("\n[4] 发送小数据（不分片）...")
        small_data = b"Hello, BluFi!"
        if await client.send_encrypted_data(small_data):
            print(f"✅ 发送成功: {len(small_data)} 字节")

        await asyncio.sleep(1)

        # 5. 发送大数据（自动分片）
        print("\n[5] 发送大数据（自动分片）...")
        large_data = b"X" * 500  # 500 字节，会自动分片
        if await client.send_encrypted_data(large_data):
            print(f"✅ 发送成功: {len(large_data)} 字节")

        await asyncio.sleep(1)

        # 6. 接收数据
        print("\n[6] 等待接收数据...")
        response = await client.receive_encrypted_data(timeout=5.0)
        if response:
            print(f"✅ 接收成功: {len(response)} 字节")
            print(f"   数据: {response[:50]}...")  # 显示前 50 字节

    finally:
        # 断开连接
        print("\n[7] 断开连接...")
        await client.disconnect()
        print("✅ 已断开")


async def advanced_example():
    """高级配置示例"""
    print("\n" + "=" * 60)
    print("高级配置示例")
    print("=" * 60)

    client = BluetoothSecureClient("BLUFI_DEVICE")

    try:
        # 搜索并连接
        if not await client.search_device():
            return
        if not await client.connect():
            return

        # 手动设置包长度限制（适用于 Linux 或特殊场景）
        print("\n[配置] 手动设置包长度限制...")
        client.set_package_length_limit(256)
        print(f"✅ 包长度限制: {client.package_length_limit} 字节")
        print(f"✅ 最大分片: {client.get_max_fragment_size()} 字节")

        # 执行握手
        if not await client.perform_handshake():
            return

        # 配置 ACK 超时时间
        print("\n[配置] 设置 ACK 超时时间...")
        client.ack_timeout = 10.0  # 10 秒
        print(f"✅ ACK 超时: {client.ack_timeout} 秒")

        # 发送数据并要求 ACK 确认
        print("\n[发送] 发送数据并要求 ACK...")
        data = b"Important data that needs ACK"
        success = await client.send_encrypted_data(data, require_ack=True)
        if success:
            print("✅ 发送成功，已收到 ACK")
        else:
            print("❌ 发送失败，ACK 超时")

    finally:
        await client.disconnect()


async def stress_test():
    """压力测试示例"""
    print("\n" + "=" * 60)
    print("压力测试示例")
    print("=" * 60)

    client = BluetoothSecureClient("BLUFI_DEVICE")

    try:
        # 搜索并连接
        if not await client.search_device():
            return
        if not await client.connect():
            return
        if not await client.perform_handshake():
            return

        # 测试不同大小的数据
        test_sizes = [10, 50, 100, 200, 500, 1000, 2000, 5000]

        print("\n[测试] 发送不同大小的数据...")
        for size in test_sizes:
            data = b"X" * size
            print(f"\n  测试 {size} 字节...")

            start_time = asyncio.get_event_loop().time()
            success = await client.send_encrypted_data(data)
            elapsed = asyncio.get_event_loop().time() - start_time

            if success:
                print(f"  ✅ 成功: {size} 字节, 耗时 {elapsed:.3f} 秒")
            else:
                print(f"  ❌ 失败: {size} 字节")

            await asyncio.sleep(0.5)  # 间隔

        print("\n✅ 压力测试完成")

    finally:
        await client.disconnect()


async def checksum_test():
    """校验和测试示例"""
    print("\n" + "=" * 60)
    print("校验和测试示例")
    print("=" * 60)

    client = BluetoothSecureClient("BLUFI_DEVICE")

    # 测试创建带校验和的包
    print("\n[测试] 创建带校验和的 BluFi 包...")
    test_data = b"Test data with checksum"
    packets = client.create_blufi_packet(test_data, blufi_seq=0, packet_type=0x04, enable_checksum=True)

    print(f"✅ 创建成功: {len(packets)} 个包")
    for i, packet in enumerate(packets):
        print(f"   包 #{i}: {len(packet)} 字节, hex: {packet.hex()}")

    # 测试解析带校验和的包
    print("\n[测试] 解析带校验和的 BluFi 包...")
    result = client.parse_blufi_packet(bytearray(packets[0]))
    if result:
        is_frag, seq, frame_ctrl, payload = result
        print("✅ 解析成功:")
        print(f"   分片: {'是' if is_frag else '否'}")
        print(f"   序列号: {seq}")
        print(f"   帧控制: 0x{frame_ctrl:02x}")
        print(f"   载荷: {len(payload)} 字节")
        print(f"   校验和: {'已验证' if (frame_ctrl & 0x02) else '未启用'}")
    else:
        print("❌ 解析失败")


async def fragmentation_test():
    """分片测试示例"""
    print("\n" + "=" * 60)
    print("分片测试示例")
    print("=" * 60)

    client = BluetoothSecureClient("BLUFI_DEVICE")

    # 测试分片创建
    print("\n[测试] 创建分片包...")
    large_data = b"A" * 1000  # 1000 字节，肯定会分片

    # 设置较小的分片大小以测试分片功能
    max_frag_size = 100  # 每个分片最多 100 字节

    packets = client.create_blufi_packet(large_data, blufi_seq=0, packet_type=0x04, max_fragment_size=max_frag_size)

    print(f"✅ 创建成功: {len(packets)} 个分片")
    print(f"   原始数据: {len(large_data)} 字节")
    print(f"   分片大小: {max_frag_size} 字节")

    # 显示每个分片的信息
    for i, packet in enumerate(packets):
        result = client.parse_blufi_packet(bytearray(packet))
        if result:
            is_frag, seq, frame_ctrl, payload = result
            print(f"\n   分片 #{i}:")
            print(f"     序列号: {seq}")
            print(f"     包大小: {len(packet)} 字节")
            print(f"     载荷: {len(payload)} 字节")
            print(f"     分片标志: {'是' if is_frag else '否'}")


async def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("BluFi 传输机制使用示例")
    print("=" * 60)

    # 选择要运行的示例
    examples = {
        "1": ("基本使用示例", basic_example),
        "2": ("高级配置示例", advanced_example),
        "3": ("压力测试示例", stress_test),
        "4": ("校验和测试示例", checksum_test),
        "5": ("分片测试示例", fragmentation_test),
    }

    print("\n请选择要运行的示例:")
    for key, (name, _) in examples.items():
        print(f"  {key}. {name}")
    print("  0. 退出")

    choice = input("\n请输入选项 (0-5): ").strip()

    if choice == "0":
        print("退出")
        return

    if choice in examples:
        name, func = examples[choice]
        print(f"\n运行: {name}")
        await func()
    else:
        print("无效选项")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n用户中断")
    except Exception as e:
        print(f"\n\n错误: {e}")
        import traceback

        traceback.print_exc()
