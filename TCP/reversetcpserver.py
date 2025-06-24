import socket  # 导入套接字模块，用于网络通信
import struct  # 导入结构体模块，用于处理二进制数据
import threading  # 导入线程模块，用于多线程处理客户端连接


def handle_client(conn, addr):
    """处理客户端连接的函数"""
    print(f"新连接来自 {addr}")  # 输出新连接的客户端地址

    try:
        # 循环接收初始化报文（确保接收到完整的6字节数据）
        init_data = b''
        while len(init_data) < 6:
            # 按需接收剩余字节（最多接收6 - 当前已接收长度字节）
            chunk = conn.recv(6 - len(init_data))
            if not chunk:  # 如果接收数据为空，说明客户端断开连接
                print("客户端在发送初始化报文前断开连接")
                return
            init_data += chunk  # 累加接收到的数据

        # 解包初始化报文（大端序：>H 表示2字节无符号短整型，>I 表示4字节无符号整型）
        pkt_type, n_chunks = struct.unpack('>HI', init_data)
        if pkt_type != 1:  # 检查数据包类型是否为1（初始化类型）
            print(f"无效的数据包类型: {pkt_type}")
            return

        # 发送同意报文（2字节，类型为2）
        conn.sendall(struct.pack('>H', 2))

        # 处理每个数据块（确保数据块数量有效）
        if n_chunks <= 0:
            print("无效的数据块数量: 0")
            return

        # 循环处理每个数据块
        for _ in range(n_chunks):
            # 循环接收请求头（确保接收到完整的6字节）
            req_header = b''
            while len(req_header) < 6:
                chunk = conn.recv(6 - len(req_header))
                if not chunk:  # 客户端断开连接
                    print("客户端在发送数据块头部时断开连接")
                    return
                req_header += chunk  # 累加接收到的头部数据

            # 解包请求头（类型和数据长度）
            pkt_type, data_len = struct.unpack('>HI', req_header)
            if pkt_type != 3:  # 检查数据包类型是否为3（数据请求类型）
                print(f"无效的数据包类型: {pkt_type}")
                return

            # 循环接收完整数据（确保接收到指定长度的data_len字节）
            data = b''
            while len(data) < data_len:
                chunk = conn.recv(data_len - len(data))
                if not chunk:  # 客户端断开连接
                    print("客户端在发送数据块内容时断开连接")
                    return
                data += chunk  # 累加接收到的数据内容

            # 反转数据（字节级反转，例如 b'abc' 转为 b'cba'）
            reversed_data = data[::-1]

            # 发送响应（响应头6字节 + 反转后的数据）
            # 响应头格式：类型4（响应类型） + 反转数据的长度
            header = struct.pack('>HI', 4, len(reversed_data))
            conn.sendall(header + reversed_data)  # 发送完整响应

    finally:
        conn.close()  # 确保关闭连接
        print(f"连接已关闭: {addr}")  # 输出连接关闭信息


def main():
    """主函数：创建服务器并监听客户端连接"""
    host = '0.0.0.0'  # 监听所有网络接口
    port = 12345  # 监听端口号

    # 创建TCP套接字（AF_INET表示IPv4，SOCK_STREAM表示TCP）
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 设置套接字选项，允许地址重用（避免端口占用问题）
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 绑定地址和端口
    server.bind((host, port))
    # 开始监听，最大等待连接数为5
    server.listen(5)
    print(f"服务器正在监听 {host}:{port}")  # 输出服务器监听信息

    # 无限循环接受客户端连接
    while True:
        conn, addr = server.accept()  # 阻塞等待客户端连接
        # 创建新线程处理客户端连接
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()  # 启动线程


if __name__ == '__main__':
    main()  # 执行主函数