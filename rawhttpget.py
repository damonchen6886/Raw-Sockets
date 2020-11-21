import socket
import sys
import os
import random
from urllib.parse import urlparse
import time
from struct import pack, unpack

# reference: https://www.binarytides.com/raw-socket-programming-in-python-linux/

# set flag value
#    urg   |   ack   |   psh    |   rst   |    syn    |  fin    |
#               1          0          0          0         1     =  16+1 = 17

#    urg   |   ack   |   psh    |   rst   |    syn    |  fin    |
#               1          1          0          0         1     =  16+8+1 =25
FIN_ACK = 17
FIN_ACK_PSH = 25
TIME_OUT =60
MAX_CWND = 1000
VAIID_HTTP = "200 OK"
class RawHttpGet:

    # constructor
    def __init__(self):
        self.valid_HTTP = '200 OK'
        self.start_time = ""
        self.src_ip = ""
        self.dest_ip = ""
        self.src_port = random.randint(1024, 65535)
        self.dest_port = 80
        self.congestionWindow = 1
        self.buffer_size = 65535
        # congestion window
        self.cwnd = 1

    def reset(self):
        self.dest_port = 0
        self.src_port = 0

    # Ip header
    def getIpHeader(self, id=54321):
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = id  # Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton(self.src_ip)  # Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton(self.dest_ip)

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                         ip_check, ip_saddr, ip_daddr)
        return ip_header

    def getTcpHeader(self, tcp_seq, tcp_ack_seq, content, flag, tcp_doff=5):
        # tcp header fields
        tcp_src = self.src_port
        tcp_des = 80
        tcp_window = socket.htons(5840)  # maximum allowed window size

        tcp_check = 0
        tcp_urg_ptr = 0
        tcp_offset_res = (tcp_doff << 4) + 0
        # validate flag each time
        tcp_flags = self.getFlags(flag)
        # the ! in the pack format string means network order

        # print(str(tcp_urg_ptr) + "********************************")
        tcp_header = pack('!HHLLBBHHH', tcp_src, tcp_des, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window,
                          tcp_check, tcp_urg_ptr)
        # print(tcp_header)
        tcp_check = self.checkHeader(tcp_header, content)
        tcp_header = pack('!HHLLBBH', tcp_src, tcp_des, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)
        return tcp_header

    # check the tcp header and return the check result
    def checkHeader(self, tcp_header, content):
        source_address = socket.inet_aton(self.src_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(content)
        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header + content.encode('utf-8')
        tcp_check = self.checksum(psh)

        return tcp_check
    # checksum, attribution from link provided by professor https://www.binarytides.com/raw-socket-programming-in-python-linux/
    def checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i + 1] << 8)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        # complement and mask to 4 byte short
        s = ~s & 0xffff
        return s

    def get_localhost_ip(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = ''
        try:
            # ping google in order to get local machine ip
            sock.connect(("8.8.8.8", 99))
            ip = sock.getsockname()[0]
        except socket.error:
            ip = "Unknown Ip address"
        finally:
            sock.close()
        return str(ip)

    def getFlags(self, flag):
        # table
        #    urg   |   ack   |   psh    |   rst   |    syn    |  fin    |

        tcp_fin = 0
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0

        if flag == 'SYN':
            tcp_syn = 1
        elif flag == 'ACK':
            tcp_ack = 1
        elif flag == 'FIN':
            tcp_fin = 1
        elif flag == 'PSH-ACK':
            tcp_psh = 1
            tcp_ack = 1
        elif flag == 'FIN-ACK':
            tcp_ack = 1
            tcp_fin = 1

        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        return tcp_flags


    # first step of three-handshack
    def first_handshake(self, send_socket,  dest_ip):
        # track the packet utility time
        self.start_time = time.time()
        # init a packet
        init_pack = ''
        # construct ip_header
        ip_header = self.getIpHeader()
        # construct tcp_header, default is seq = 0, ack = 0, content is empty, flag = 'SYN'
        tcp_header = self.getTcpHeader(0, 0, '', 'SYN')
        # construct the header
        headers = ip_header + tcp_header
        # send the syn packet
        send_socket.sendto(headers, (dest_ip, 0))

    def send_ack(self, send_socket, src_port,  dest_ip, tcp_headers):

        ip_header = self.getIpHeader(54321)

        # tcp header fields
        tcp_source_port = src_port
        tcp_seq = tcp_headers[3]
        tcp_ack_seq = tcp_headers[2] + 1
        flag = 'ACK'  # ack packet with empty packet
        tcp_header = self.getTcpHeader(tcp_seq, tcp_ack_seq, '', flag)
        ack_packet = ip_header + tcp_header
        send_socket.sendto(ack_packet, (dest_ip, 0))

    # handle the data of requests and return the ack packet
    def sec_third_handshake(self, send_sock, recv_sock, buffer_size, src_ip, dest_ip, src_port):

        packet = recv_sock.recvfrom(buffer_size)
        received_packet = packet[0]
        # first 20 character is ip-header
        ip_header = received_packet[0:20]
        unpack_ip_header = unpack('!BBHHHBBH4s4s', ip_header)
        # ipv version
        version_ihl = unpack_ip_header[0]
        temp = (version_ihl & 0xF)
        ip_header_length = temp * 4
        src_addr = socket.inet_ntoa(unpack_ip_header[8])
        dest_addr = socket.inet_ntoa(unpack_ip_header[9])
        # second 20 character is tcp-header
        tcp_header = received_packet[ip_header_length:ip_header_length + 20]
        unpack_tcp_header = unpack('!HHLLBBHHH', tcp_header)

        if src_addr == dest_ip and dest_addr == src_ip and unpack_tcp_header[5] == 18 and src_port == \
                unpack_tcp_header[1] and ((time.time() - self.start_time) < TIME_OUT):
            self.send_ack(send_sock, src_port,  dest_ip, unpack_tcp_header)


        else:
            # if out of time, resend the request
            self.cwnd += 1
            self.first_handshake(send_sock, dest_ip)

        return unpack_tcp_header, unpack_ip_header[4]

    # http get for file request
    def http_request(self, send_sock, dest_ip,  tcp_header, path, hostname):

        ip_header = self.getIpHeader(54321)

        tcp_seq = tcp_header[3]
        tcp_ack_seq = tcp_header[2] + 1
        flag = 'PSH-ACK'
        request_httpdata = 'GET ' + path + ' HTTP/1.0\r\nHOST: ' + hostname + '\r\n\r\n'
        if len(request_httpdata) % 2 != 0:
            request_httpdata = request_httpdata + " "
        tcp_header4ack = self.getTcpHeader(tcp_seq, tcp_ack_seq, request_httpdata, flag)
        http_req = ip_header + tcp_header4ack + request_httpdata.encode('utf-8')
        send_sock.sendto(http_req, (dest_ip, 0))

    # handle the url parsing issue
    def get_filename(self, url):
        file_path = " "
        empty = ""
        url_path = url.path
        if url_path == empty:
            path_url = "/"
            file_path = "index.html"
        else:
            length_of_path = len(url_path)
            last_char = url_path[length_of_path - 1]
            if last_char == "/":
                path_url = "/"
                file_path = "index.html"
            else:
                path_url = url_path
                split_name = url_path.rsplit("/", 1)
                file_path = split_name[1]
        return file_path, path_url


    # write to file
    def to_file(self, path, dic):
        # get the packet-data by mapping sorted key
        http_response = b''
        for key in sorted(dic):
            http_response = http_response + dic[key]

        file = open(path, "wb")

        content = http_response.split(b'\r\n\r\n', 1)

        http_header = content[0]
        # print(http_header)
        # print(http_header.decode())
        # print(type(http_header.decode()))
        # if http response code is not 200: exit the program
        if VAIID_HTTP not in http_header.decode().upper():
            print("HTTP response not 200")
            sys.exit()
        if len(content) > 1:
            file.write(content[1])
        else:
            file.write(content[0])

    def receive_data_to_file(self, send_sock, recv_sock, buffer_size, dest_ip, src_port, path):
        # map key: sequencenumber int value: data byte
        # save all the packet data to a dictionary, each pair represent a packet received from server
        map = {}
        count = 0
        while True:
            # print("map")
            # print(map)
            start_time = time.process_time()
            packet = recv_sock.recvfrom(buffer_size)
            received_packet = packet[0]
            # first 20 character is ip-header
            ip_header = received_packet[0:20]
            unpack_ip_header = unpack('!BBHHHBBH4s4s', ip_header)
            # ipv version
            version_ihl = unpack_ip_header[0]
            ip_header_length = (version_ihl & 0xF) * 4
            src_addr = socket.inet_ntoa(unpack_ip_header[8])
            # second 20 character is tcp-header
            tcp_header = received_packet[ip_header_length:ip_header_length + 20]
            unpack_tcp_header = unpack('!HHLLBBHHH', tcp_header)
            # print("unpack_tcp_header")
            # print(unpack_tcp_header)

            dest_port = unpack_tcp_header[1]
            seq_num = unpack_tcp_header[2]
            doff_reserved = unpack_tcp_header[4]
            tcp_header_length = ((doff_reserved >> 4) * 4)
            flags = unpack_tcp_header[5]

            # calculate the total header length
            header_size = ip_header_length + tcp_header_length
            # remaining is content
            data_size = len(received_packet) - header_size
            # print("dest_port")
            # print(dest_port)
            # print("src_port")
            # print(src_port)
            # print("src_addr")
            # print(src_addr)
            # print("dest_ip")
            # print(dest_ip)
            if dest_port == src_port and src_addr == dest_ip and data_size > 0:
                count = count + 1
                data = received_packet[header_size:]
                cur_time = time.process_time()
                # handle the congestion window
                if cur_time -start_time < TIME_OUT or self.cwnd == MAX_CWND:
                    self.cwnd = 1
                else:
                    self.cwnd += 1
                map[seq_num] = data
                # teardown initiation
                teardown_initiator = ""
                ip_header_4ack = self.getIpHeader(54321)
                tcp_source = src_port
                self.src_port = tcp_source
                tcp_seq = unpack_tcp_header[3]
                tcp_ack_seq = seq_num + data_size
                flag = "ACK"
                data_for_teardown = ""
                tcp_header4ack = self.getTcpHeader(tcp_seq, tcp_ack_seq, data_for_teardown, flag)
                teardown_initiator = ip_header_4ack + tcp_header4ack + data_for_teardown.encode('utf-8')
                send_sock.sendto(teardown_initiator, (dest_ip, 0))


            # if flag = "FIN_ACK" or "FIN_ACK_PSH", should return disconnection request
            if (flags == FIN_ACK or flags == FIN_ACK_PSH) and dest_port == src_port and src_addr == dest_ip and data_size == 0:
                # disconnect with the server (download completed)
                #init fin_packet
                fin_packet = ""
                ip_header_4ack = self.getIpHeader(54321)
                tcp_source = src_port
                self.src_port = tcp_source
                tcp_seq = unpack_tcp_header[3]
                tcp_ack_seq = seq_num + 1
                flag = "FIN-ACK"
                data_in_fin = ""
                tcp_header_4ack = self.getTcpHeader(tcp_seq, tcp_ack_seq, data_in_fin, flag)
                fin_packet = ip_header_4ack + tcp_header_4ack + data_in_fin.encode('utf-8')
                send_sock.sendto(fin_packet, (dest_ip, 0))

                self.to_file(path, map)
                break
            elif dest_port == src_port and src_addr == dest_ip and data_size == 0 and count > 0:
                self.to_file(path, map)
                break

    def rawhttpget(self):
        os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
        url_parameter = sys.argv[1]
        # Divides the url into single strings of distinct strings
        split_url = urlparse(url_parameter)
        hostname = split_url.netloc
        self.src_ip = self.get_localhost_ip()
        self.dest_ip = socket.gethostbyname(urlparse(url_parameter).hostname)
        file_path, path_url = self.get_filename(split_url)
        # create raw socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error as msg:
            print('Socket could not be created. Error Code: ' + str(msg[0]) + ' Message: ' + str(msg[1]))
            sys.exit()

        # Create a recieve raw socke
        try:
            self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print('Receive socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()
        # initiate 3 way handshake
        while True:
            self.first_handshake(self.sock,  self.dest_ip)
            tcp_header, off_set = self.sec_third_handshake(self.sock, self.recv_socket, self.buffer_size, self.src_ip,
                                                           self.dest_ip, self.src_port)
            if str(off_set) == "0":
                break
        #print(str(tcp_header) + "tcp----------" + str(off_set))
        self.http_request(self.sock, self.dest_ip, tcp_header, path_url, hostname)
        self.receive_data_to_file(self.sock, self.recv_socket, self.buffer_size, self.dest_ip, self.src_port, file_path)

        self.sock.close()
        self.recv_socket.close()
        sys.exit()


if __name__ == "__main__":
    rawhttpGet = RawHttpGet()
    rawhttpGet.rawhttpget()
