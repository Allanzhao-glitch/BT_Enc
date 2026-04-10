"""
BluFi 分片功能测试脚本

测试 create_blufi_packet 和 parse_blufi_packet 的分片功能
"""

import sys

from bluetooth_secure_client import BluetoothSecureClient


def test_create_single_packet():
    """测试创建单个完整包"""
    print("\n" + "=" * 60)
    print("测试 1: 创建单个完整包 (不分片)")
    print("=" * 60)

    client = BluetoothSecureClient("TEST_DEVICE")

    # 创建小数据包 (不需要分片)
    data = b"Hello, BluFi!"
    seq = 0

    packets = client.create_blufi_packet(data=data, blufi_seq=seq, packet_type=0x04, frame_ctrl=0x00, max_fragment_size=244)

    print(f"\n数据长度: {len(data)} 字节")
    print(f"生成包数量: {len(packets)}")

    assert len(packets) == 1, "应该生成 1 个包"

    packet = packets[0]
    print(f"包内容 (hex): {packet.hex()}")
    print(f"包长度: {len(packet)} 字节")

    # 验证包结构
    assert packet[0] == 0x04, "Type 应该是 0x04"
    assert packet[1] == 0x00, "Frame Control 应该是 0x00 (无分片标志)"
    assert packet[2] == seq, f"Sequence 应该是 {seq}"
    assert packet[3] == len(data), f"Length 应该是 {len(data)}"
    assert packet[4:] == data, "Payload 应该匹配原始数据"

    print("\n✓ 测试通过!")


def test_create_fragmented_packets():
    """测试创建分片包"""
    print("\n" + "=" * 60)
    print("测试 2: 创建分片包")
    print("=" * 60)

    client = BluetoothSecureClient("TEST_DEVICE")

    # 创建大数据包 (需要分片)
    data = b"X" * 500  # 500 字节
    seq = 0
    max_frag_size = 244

    packets = client.create_blufi_packet(
        data=data, blufi_seq=seq, packet_type=0x04, frame_ctrl=0x00, max_fragment_size=max_frag_size
    )

    print(f"\n数据长度: {len(data)} 字节")
    print(f"最大分片大小: {max_frag_size} 字节")
    print(f"生成包数量: {len(packets)}")

    # 计算预期分片数量
    expected_frags = (len(data) + max_frag_size - 1) // max_frag_size
    assert len(packets) == expected_frags, f"应该生成 {expected_frags} 个分片"

    # 验证每个分片
    offset = 0
    for i, packet in enumerate(packets):
        print(f"\n分片 #{i}:")
        print(f"  长度: {len(packet)} 字节")
        print(f"  Type: 0x{packet[0]:02x}")
        print(f"  Frame Control: 0x{packet[1]:02x}")
        print(f"  Sequence: {packet[2]}")
        print(f"  Payload Length: {packet[3]}")

        # 验证 Type
        assert packet[0] == 0x04, "Type 应该是 0x04"

        # 验证 Frame Control (分片标志)
        if i < len(packets) - 1:
            # 不是最后一个分片,应该有分片标志
            assert (packet[1] & 0x10) != 0, f"分片 #{i} 应该有分片标志 (Bit 4)"
            print("  ✓ 有分片标志")
        else:
            # 最后一个分片,不应该有分片标志
            assert (packet[1] & 0x10) == 0, f"分片 #{i} 不应该有分片标志"
            print("  ✓ 无分片标志 (最后一个分片)")

        # 验证序列号
        expected_seq = (seq + i) % 256
        assert packet[2] == expected_seq, f"Sequence 应该是 {expected_seq}"

        # 验证载荷
        payload_len = packet[3]
        payload = packet[4:]
        assert len(payload) == payload_len, "Payload 长度应该匹配"

        # 验证载荷内容
        expected_payload = data[offset : offset + payload_len]
        assert payload == expected_payload, "Payload 内容应该匹配"

        offset += payload_len

    # 验证所有数据都被分片
    assert offset == len(data), "所有数据都应该被分片"

    print("\n✓ 测试通过!")


def test_parse_single_packet():
    """测试解析单个完整包"""
    print("\n" + "=" * 60)
    print("测试 3: 解析单个完整包")
    print("=" * 60)

    client = BluetoothSecureClient("TEST_DEVICE")

    # 构造一个完整包
    packet_type = 0x04
    frame_ctrl = 0x00  # 无分片标志
    seq = 5
    payload = b"Test Data"
    length = len(payload)

    packet = bytearray([packet_type, frame_ctrl, seq, length]) + payload

    print(f"\n包内容 (hex): {packet.hex()}")
    print(f"包长度: {len(packet)} 字节")

    # 解析包
    result = client.parse_blufi_packet(packet)

    assert result is not None, "解析应该成功"

    is_frag, parsed_seq, parsed_frame_ctrl, parsed_payload = result

    print("\n解析结果:")
    print(f"  是否分片: {is_frag}")
    print(f"  序列号: {parsed_seq}")
    print(f"  帧控制: 0x{parsed_frame_ctrl:02x}")
    print(f"  载荷: {parsed_payload}")

    assert is_frag == False, "不应该是分片"
    assert parsed_seq == seq, f"序列号应该是 {seq}"
    assert parsed_frame_ctrl == frame_ctrl, f"帧控制应该是 0x{frame_ctrl:02x}"
    assert parsed_payload == payload, "载荷应该匹配"

    print("\n✓ 测试通过!")


def test_parse_fragmented_packet():
    """测试解析分片包"""
    print("\n" + "=" * 60)
    print("测试 4: 解析分片包")
    print("=" * 60)

    client = BluetoothSecureClient("TEST_DEVICE")

    # 构造一个分片包
    packet_type = 0x04
    frame_ctrl = 0x10  # 有分片标志 (Bit 4)
    seq = 10
    payload = b"Fragment Data"
    length = len(payload)

    packet = bytearray([packet_type, frame_ctrl, seq, length]) + payload

    print(f"\n包内容 (hex): {packet.hex()}")
    print(f"包长度: {len(packet)} 字节")

    # 解析包
    result = client.parse_blufi_packet(packet)

    assert result is not None, "解析应该成功"

    is_frag, parsed_seq, parsed_frame_ctrl, parsed_payload = result

    print("\n解析结果:")
    print(f"  是否分片: {is_frag}")
    print(f"  序列号: {parsed_seq}")
    print(f"  帧控制: 0x{parsed_frame_ctrl:02x}")
    print(f"  载荷: {parsed_payload}")

    assert is_frag == True, "应该是分片"
    assert parsed_seq == seq, f"序列号应该是 {seq}"
    assert parsed_frame_ctrl == frame_ctrl, f"帧控制应该是 0x{frame_ctrl:02x}"
    assert parsed_payload == payload, "载荷应该匹配"

    print("\n✓ 测试通过!")


def test_round_trip():
    """测试创建和解析的往返"""
    print("\n" + "=" * 60)
    print("测试 5: 创建和解析往返测试")
    print("=" * 60)

    client = BluetoothSecureClient("TEST_DEVICE")

    # 创建分片包
    original_data = b"Round Trip Test Data" * 20  # 400 字节
    seq = 0

    print(f"\n原始数据长度: {len(original_data)} 字节")

    packets = client.create_blufi_packet(
        data=original_data, blufi_seq=seq, packet_type=0x04, frame_ctrl=0x00, max_fragment_size=150
    )

    print(f"生成分片数量: {len(packets)}")

    # 解析并重组
    reassembled_data = bytearray()

    for i, packet in enumerate(packets):
        result = client.parse_blufi_packet(bytearray(packet))
        assert result is not None, f"分片 #{i} 解析失败"

        is_frag, parsed_seq, parsed_frame_ctrl, parsed_payload = result

        print(f"\n分片 #{i}:")
        print(f"  序列号: {parsed_seq}")
        print(f"  是否分片: {is_frag}")
        print(f"  载荷长度: {len(parsed_payload)} 字节")

        # 验证序列号
        expected_seq = (seq + i) % 256
        assert parsed_seq == expected_seq, f"序列号应该是 {expected_seq}"

        # 验证分片标志
        if i < len(packets) - 1:
            assert is_frag == True, f"分片 #{i} 应该有分片标志"
        else:
            assert is_frag == False, f"分片 #{i} 不应该有分片标志"

        # 重组数据
        reassembled_data.extend(parsed_payload)

    print(f"\n重组后数据长度: {len(reassembled_data)} 字节")

    # 验证重组后的数据
    assert bytes(reassembled_data) == original_data, "重组后的数据应该与原始数据一致"

    print("\n✓ 测试通过! 数据完整重组成功!")


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("BluFi 分片功能测试")
    print("=" * 60)

    try:
        test_create_single_packet()
        test_create_fragmented_packets()
        test_parse_single_packet()
        test_parse_fragmented_packet()
        test_round_trip()

        print("\n" + "=" * 60)
        print("所有测试通过! ✓")
        print("=" * 60 + "\n")

        return 0

    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ 测试出错: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
