import socket  # 导入套接字模块用于网络通信
import struct  # 导入结构体模块用于处理二进制数据
import random  # 导入随机数模块用于随机分块
import sys  # 导入系统模块用于命令行参数处理


def reverse_file_chunks(data, Lmin, Lmax):
    """
    将文件数据按随机长度分块
    :param data: 原始文件字节数据
    :param Lmin: 分块最小长度
    :param Lmax: 分块最大长度
    :return: 分块后的字节数据列表
    """
    chunks = []  # 存储分块结果
    total_size = len(data)  # 总数据长度
    current = 0  # 当前处理位置

    while current < total_size:
        remaining = total_size - current  # 剩余未处理数据长度
        if remaining <= Lmin:
            chunk_size = remaining  # 剩余数据不足时全取
        else:
            # 生成随机分块长度（在Lmin到Lmax之间，不超过剩余长度）
            chunk_size = random.randint(Lmin, min(Lmax, remaining))
        chunks.append(data[current:current + chunk_size])  # 添加分块数据
        current += chunk_size  # 更新当前处理位置
    return chunks


def main():
    """主函数：客户端主逻辑流程"""
    # 检查命令行参数（需传入服务器IP、端口、输入文件、分块最小/最大长度）
    if len(sys.argv) != 6:
        print("使用方法: python reversetcpclient.py <服务器IP> <服务器端口> <输入文件> <分块最小长度> <分块最大长度>")
        sys.exit(1)

    server_ip = sys.argv[1]  # 服务器IP地址
    server_port = int(sys.argv[2])  # 服务器端口号
    input_file = sys.argv[3]  # 输入文件名
    Lmin = int(sys.argv[4])  # 分块最小长度
    Lmax = int(sys.argv[5])  # 分块最大长度
    if Lmin > Lmax:
        print("输入的分块最小长度与分块最大长度有误，请重新尝试。")
        sys.exit(1)
    # 读取输入文件内容
    try:
        with open(input_file, 'r', encoding='ascii') as f:
            file_text = f.read()  # 读取ASCII文本
    except UnicodeDecodeError:
        print("错误：输入文件不是ASCII文本")
        sys.exit(1)
    if not file_text:
        print("错误：输入文件为空")
        sys.exit(1)

    file_data = file_text.encode('ascii')  # 转换为字节数据
    # 按随机长度分块（模拟实际网络传输的分片场景）
    chunks = reverse_file_chunks(file_data, Lmin, Lmax)

    n_chunks = len(chunks)  # 总分块数
    if n_chunks == 0:
        print("错误：分块数为0（请检查分块最小/最大长度是否合理）")
        sys.exit(1)

    # 创建TCP套接字并连接服务器
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((server_ip, server_port))  # 连接服务器
            print(f"已连接到服务器 {server_ip}:{server_port}")

            # 发送初始化报文（类型1，包含分块总数，共6字节）
            init_packet = struct.pack('>HI', 1, n_chunks)
            sock.sendall(init_packet)
            print(f"已发送初始化报文，分块总数：{n_chunks}")

            # 接收服务器同意报文（确保收到2字节）
            agree_data = b''
            while len(agree_data) < 2:
                chunk = sock.recv(2 - len(agree_data))
                if not chunk:
                    print("错误：服务器断开连接，未收到同意报文")
                    return
                agree_data += chunk

            # 验证同意报文类型（类型2）
            if struct.unpack('>H', agree_data)[0] != 2:
                print("协议错误：未收到预期的同意报文")
                return
            print("已收到服务器同意报文，准备开始数据传输")

            reversed_chunks = []  # 存储反转后的分块数据

            # 循环处理每个分块（发送请求并接收反转结果）
            for i, chunk in enumerate(chunks):
                # 发送反转请求（类型3，包含分块长度和数据）
                header = struct.pack('>HI', 3, len(chunk))
                sock.sendall(header + chunk)
                print(f"已发送第 {i + 1} 块数据，长度：{len(chunk)} 字节")

                # 接收响应头（确保收到6字节）
                ans_header = b''
                while len(ans_header) < 6:
                    chunk = sock.recv(6 - len(ans_header))
                    if not chunk:
                        print("错误：服务器断开连接，未收到响应头")
                        return
                    ans_header += chunk

                # 解析响应头（类型4，包含反转数据长度）
                ans_type, ans_length = struct.unpack('>HI', ans_header)
                if ans_type != 4:
                    print(f"意外的数据包类型：{ans_type}（预期类型4）")
                    return

                # 接收完整的反转数据
                reversed_data = b''
                while len(reversed_data) < ans_length:
                    chunk = sock.recv(ans_length - len(reversed_data))
                    if not chunk:
                        print("错误：服务器断开连接，未收到反转数据")
                        return
                    reversed_data += chunk

                # 打印反转结果（尝试解码为ASCII，失败则显示字节数据）
                try:
                    text = reversed_data.decode('ascii')
                except:
                    text = str(reversed_data)
                print(f"第 {i + 1} 块反转结果：{text}")

                # 按顺序保存反转数据（插入到列表头部以保持整体反转顺序）
                reversed_chunks.insert(0, reversed_data)

            # 保存完整反转文件
            output_file = 'output.txt'
            with open(output_file, 'wb') as f:
                for chunk in reversed_chunks:
                    f.write(chunk)
            print(f"反转文件已保存至 {output_file}")

        except ConnectionRefusedError:
            print(f"错误：无法连接到服务器 {server_ip}:{server_port}（请检查服务器是否运行）")
        except Exception as e:
            print(f"程序运行时发生错误：{e}")


if __name__ == '__main__':
    main()  # 执行主函数