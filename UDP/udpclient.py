import socket  # 导入套接字模块用于网络通信
import time  # 导入时间模块用于计算RTT
import struct  # 导入结构体模块用于打包/解包二进制数据
import sys  # 导入系统模块用于命令行参数处理
import random  # 导入随机数模块用于随机分割数据
import pandas as pd  # 导入pandas用于RTT统计分析

# 定义数据包头部格式（网络字节序）
# 类型 (1字节): 0=SYN(同步请求), 1=SYN_ACK(同步确认), 2=DATA(数据), 3=ACK(确认), 4=ESTABLISH(连接建立)
# 序号 (2字节): 数据封包序号（无符号短整型）
# 确认号 (2字节): ACK封包的确认号（无符号短整型）
# 负载长度 (2字节): 数据负载的字节长度（无符号短整型）
# 校验和 (2字节): 头部+负载的简单校验和（无符号短整型）
header_format = '!BHHHH'
header_size = struct.calcsize(header_format)  # 计算头部字节长度


def create_packet(packet_type, seq_num=0, ack_num=0, payload=b''):
    """
    创建数据包（头部+负载）
    :param packet_type: 数据包类型（0-4）
    :param seq_num: 序号（默认0）
    :param ack_num: 确认号（默认0）
    :param payload: 负载数据（字节类型，默认空）
    :return: 完整数据包（头部+负载的字节流）
    """
    payload_len = len(payload)  # 计算负载长度
    checksum = 0  # 示例代码未实现具体校验和计算逻辑，保持0
    # 打包头部（使用预定义的结构体格式）
    header = struct.pack(header_format, packet_type, seq_num, ack_num, payload_len, checksum)
    return header + payload  # 返回头部+负载的完整数据包


def parse_packet(packet):
    """
    解析数据包（分离头部和负载）
    :param packet: 完整数据包（字节流）
    :return: (类型, 序号, 确认号, 负载长度, 校验和, 负载数据) 元组
    """
    if len(packet) < header_size:
        raise ValueError("数据包过短，无法包含完整头部")
    header_bytes = packet[:header_size]  # 提取头部字节（前header_size字节）
    payload_bytes = packet[header_size:]  # 提取负载字节（剩余部分）

    # 解包头部（按预定义格式解析）
    packet_type, seq_num, ack_num, payload_len, checksum = struct.unpack(header_format, header_bytes)
    return packet_type, seq_num, ack_num, payload_len, checksum, payload_bytes


def split_random(data, Lmin=40, Lmax=80):
    """
    随机分割数据为多个数据段（模拟实际网络中的分片）
    :param data: 原始字符串数据
    :param Lmin: 数据段最小长度（默认40）
    :param Lmax: 数据段最大长度（默认80）
    :return: 分割后的元组列表（(数据段字节, 起始字节位置)）
    """
    chunks = [('null'.encode(), 0)]  # 初始占位元素（索引0不使用）
    total_size = len(data)  # 总数据长度
    current = 0  # 当前处理位置

    while current < total_size:
        remaining = total_size - current  # 剩余数据长度
        if remaining <= Lmin:
            chunk_size = remaining  # 剩余数据不足最小长度时全取
        else:
            # 随机生成数据段长度（在Lmin到Lmax之间，不超过剩余长度）
            chunk_size = random.randint(Lmin, min(Lmax, remaining))
        # 添加数据段（字节数据, 起始字节位置）
        chunks.append((data[current:current + chunk_size].encode(), current))
        current += chunk_size  # 更新当前处理位置

    return chunks


def main():
    TIMEOUT_MS = 300  # 超时时间（毫秒）

    # 检查命令行参数数量（需传入服务器IP和端口）
    if len(sys.argv) != 3:
        print("使用方法: python udpclient.py <服务器IP> <服务器端口>")
        sys.exit(1)

    server_ip = sys.argv[1]  # 从命令行参数获取服务器IP
    server_port = int(sys.argv[2])  # 从命令行参数获取服务器端口

    # 创建UDP套接字（AF_INET表示IPv4，SOCK_DGRAM表示UDP）
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 设置套接字超时时间（单位：秒）
    client_socket.settimeout(TIMEOUT_MS / 1000.0)

    print(f"客户端已启动，正在连接 {server_ip}:{server_port}")

    rtts = []  # 存储所有测量到的RTT（Round-Trip Time，往返时间）
    retransmission_cnt = 0  # 记录重传次数
    initial_transmission_cnt = 0  # 记录初始传输次数

    # 生成测试数据（800个数字用空格连接的字符串）
    total_message = ''
    for i in range(800):
        if i > 0:
            total_message += ' '
        total_message += f'{i}'
    # 随机分割数据为多个数据段（用于模拟实际传输的分片）
    segments_to_send = split_random(total_message)

    len_segments = len(segments_to_send)  # 总数据段数量

    # 握手阶段
    print("正在发起握手...\n")
    syn_packet = create_packet(0)  # 创建SYN包（类型0）
    handshake_successful = False  # 握手成功标志
    retries = 0  # 重试次数
    max_handshake_retries = 5  # 最大握手重试次数

    # 循环尝试握手直到成功或达到最大重试次数
    while not handshake_successful and retries < max_handshake_retries:
        try:
            # 向服务器发送SYN包
            client_socket.sendto(syn_packet, (server_ip, server_port))
            print(f"已发送SYN包，尝试次数：{retries + 1}")
            # 接收服务器响应（最大接收1024字节）
            response, _ = client_socket.recvfrom(1024)
            # 解析数据包获取类型字段
            pkt_type, _, _, _, _, _ = parse_packet(response)

            if pkt_type == 1:  # 类型1：SYN_ACK（同步确认）
                print("收到SYN_ACK包，握手成功。")
                # 创建连接建立包（类型4，携带总数据段数）
                establish_message = create_packet(4, len_segments)
                client_socket.sendto(establish_message, (server_ip, server_port))
                handshake_successful = True  # 标记握手成功
            else:
                print("握手过程中接收到意外类型的数据包。")
        except socket.timeout:
            print("超时，正在重试...")
            retries += 1  # 重试次数+1
        except Exception as e:
            print(f"握手错误: {e}")
            break  # 出现异常时退出循环

    if not handshake_successful:
        print("多次重试后握手仍未成功，程序退出。")
        return  # 握手失败则结束程序

    print("数据传输开始！\n")

    # Go-Back-N协议实现
    base = 1  # 窗口基序号（第一个未确认的包）
    next_seq_num = 1  # 下一个要发送的包序号
    window_size = 5  # 滑动窗口大小
    sent_packets = {}  # 存储已发送但未确认的包（键：序号，值：(包数据, 发送时间, 起始字节)）

    # 循环直到所有数据段都被确认
    while base < len_segments:
        # 填充窗口：发送未发送的包（不超过窗口大小）
        while next_seq_num < len_segments and next_seq_num < base + window_size:
            # 获取当前数据段的负载和起始字节位置
            segment, start_byte = segments_to_send[next_seq_num]
            # 创建DATA包（类型2，携带当前序号）
            packet = create_packet(2, next_seq_num, 0, segment)
            # 向服务器发送数据包
            client_socket.sendto(packet, (server_ip, server_port))
            send_time = time.time()  # 记录发送时间（用于计算RTT）
            # 存储已发送包的信息（序号: (包数据, 发送时间, 起始字节)）
            sent_packets[next_seq_num] = (packet, send_time, start_byte)

            # 计算结束字节位置并输出发送信息
            end_byte = start_byte + len(segment) - 1
            print(f"客户端已发送第 {next_seq_num} 号包（{start_byte}-{end_byte} 字节）")

            initial_transmission_cnt += 1  # 初始传输次数+1
            next_seq_num += 1  # 下一个待发送序号+1

        # 等待ACK或处理超时
        try:
            # 接收服务器返回的ACK包（最大接收1024字节）
            ack_response, _ = client_socket.recvfrom(1024)
            # 解析数据包获取类型和确认号
            pkt_type, _, ack_num, _, _, _ = parse_packet(ack_response)

            if pkt_type == 3:  # 类型3：ACK（确认包）
                # 计算RTT（仅处理有效ACK）
                if ack_num >= base:  # ACK确认号大于等于当前窗口基序号
                    # 处理所有被这个ACK确认的包（累计确认）
                    for i in range(base, ack_num + 1):
                        if i in sent_packets:
                            # 获取包的发送时间计算RTT（当前时间-发送时间）
                            packet_data_stored, send_time_float, _ = sent_packets[i]
                            rtt = (time.time() - send_time_float) * 1000  # 转换为毫秒
                            rtts.append(rtt)  # 记录RTT
                            del sent_packets[i]  # 从已发送未确认列表中移除
                            # 输出确认信息和RTT
                            print(f"第 {i} 号包已被服务器接收，RTT为 {rtt:.2f} 毫秒")
                    base = ack_num + 1  # 窗口基序号后移（新的未确认起始点）
                else:
                    print(f"收到重复或无效的ACK {ack_num}（当前窗口基序号为 {base}）")
            else:
                print(f"数据传输过程中接收到意外类型的数据包 {pkt_type}")

        except socket.timeout:
            # 超时处理：从窗口基序号开始重传所有未确认的包
            print(f"{base} 号包超时，正在从 {base} 号包开始重传...")
            retransmission_cnt += (next_seq_num - base)  # 重传次数累加

            # 遍历窗口内所有未确认的包
            for seq_to_retransmit in range(base, next_seq_num):
                if seq_to_retransmit in sent_packets:
                    # 获取包数据并重新发送
                    packet_data, _, start_byte = sent_packets[seq_to_retransmit]
                    client_socket.sendto(packet_data, (server_ip, server_port))
                    # 更新发送时间（用于重新计算RTT）
                    sent_packets[seq_to_retransmit] = (packet_data, time.time(), start_byte)

                    # 计算结束字节位置并输出重传信息
                    end_byte = start_byte + len(packet_data) - 1
                    print(f"重传第 {seq_to_retransmit} 号包（{start_byte}-{end_byte} 字节）")
                else:
                    print(f"未找到 {seq_to_retransmit} 号包，无法重传")
        except Exception as e:
            print(f"数据传输过程中发生错误: {e}")
            break  # 出现异常时退出循环

    print("数据传输完成。\n")

    print("统计结果：\n")

    # 计算丢包率（重传次数 / 总传输次数）
    total_transmissions = initial_transmission_cnt + retransmission_cnt  # 总传输次数
    if total_transmissions > 0:
        packet_loss_rate = (retransmission_cnt / total_transmissions) * 100  # 转换为百分比
    else:
        packet_loss_rate = 0  # 无传输时丢包率为0
    print(f"丢包率: {packet_loss_rate:.2f}%")

    # RTT统计分析（使用pandas）
    if rtts:
        rtt_series = pd.Series(rtts)  # 转换为pandas序列
        min_rtt = rtt_series.min()  # 最小RTT
        max_rtt = rtt_series.max()  # 最大RTT
        avg_rtt = rtt_series.mean()  # 平均RTT
        std_rtt = rtt_series.std()  # RTT标准差
        print(f"整个过程中最大RTT: {max_rtt:.2f} 毫秒")
        print(f"整个过程中最小RTT: {min_rtt:.2f} 毫秒")
        print(f"整个过程中平均RTT: {avg_rtt:.2f} 毫秒")
        print(f"整个过程中RTT标准差: {std_rtt:.2f} 毫秒")
    else:
        print("未收集到RTT数据。")

    client_socket.close()  # 关闭套接字
    print("客户端已关闭。")


if __name__ == '__main__':
    main()  # 执行主函数