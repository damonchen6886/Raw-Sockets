import socket
import sys
import os
import re
import random
from urllib.parse import urlparse
import time
from struct import pack, unpack

# set flag value
FIN_ACK = 17
FIN_ACK_PSH =25

class RawHttpGet():
    
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
    
    def reset(self):
        self.dest_port = 0
        self.src_port = 0
    
    # Ip header
    def getIpHeader(self, packet_id = 54321):
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0	# kernel will fill the correct total length
        ip_id = packet_id	#Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0	# kernel will fill the correct checksum
        ip_saddr = socket.inet_aton( self.src_ip )	#Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton( self.dest_ip )

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        return ip_header
        
    def getTcpHeader(self, tcp_seq, tcp_ack_seq, content, flag, tcp_doff=5):
        # tcp header fields
        tcp_src = self.src_port
        tcp_des = 80
        tcp_window =socket.htons(5840) #	maximum allowed window size
        
        tcp_check = 0
        tcp_urg_ptr = 0
        tcp_offset_res = (tcp_doff << 4) + 0
        # validate flag each time
        tcp_flags = self.getFlags(flag) # return value TCP_FIN + (TCP_SYN << 1) + (TCP_RST << 2) + (TCP_PSH <<3) + (TCP_ACK << 4) + (TCP_URG << 5)
        # the ! in the pack format string means network order
        # print(tcp_flags)
        # print(tcp_src)
        # print(tcp_des)
        # print(tcp_seq)
        # print(tcp_ack_seq)
        # print(tcp_offset_res)
        # print(tcp_flags)
        # print(tcp_window)
        # print(tcp_check)
        # print(str(tcp_urg_ptr) + "********************************")
        tcp_header = pack('!HHLLBBHHH' , tcp_src, tcp_des, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
        # print(tcp_header)
        tcp_check = self.checkHeader(tcp_header, content)
        tcp_header = pack('!HHLLBBH', tcp_src, tcp_des, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)
        return tcp_header  

    # pseudo header fields
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
    
    def checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i+1] << 8 )
            s = s + w
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        return s


    def get_localhost_ip(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = ''
        try:
            sock.connect(("8.8.8.8",99))
            ip = sock.getsockname()[0]
        except socket.error:
            ip = "Unknown Ip address"
        finally:
            sock.close()
        return str(ip)
    
    def getFlags(self, flag):
        # init state
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
    
    # write to file
    def to_file(self, path, dic):
        # get the packet-data by mapping sorted key
        sorted_sequence = sorted(dic.keys()) # In Python 3 dict.iterkeys() was replaced with dict.keys().
        http_response = b''
        for key in sorted(dic):
            http_response = http_response + dic[key]

        file = open(path, "wb")

        content = http_response.split(b'\r\n\r\n',1)
        print(type(content[1]))
        if(len(content) >1):
            file.write(content[1])
        else:
            file.write(content[0])
        


                    
    ## basic function (generate_syn)
    # first step of three-handshack
    def generate_syn(self, send_socket, src_ip, dest_ip, src_port):
        # track the packet utility time
        self.start_time = time.time()
        # init a packet
        init_pack = ''
        # construct ip_header
        ip_header = self.getIpHeader()
        # construct tcp_header, default is seq = 0, ack = 0, content is empty, flag = 'SYN'
        tcp_header = self.getTcpHeader(0,0,'','SYN')
        # construct the header
        headers = ip_header + tcp_header
        # send the syn packet
        send_socket.sendto(headers, (dest_ip, 0))
        
        
    def send_ack(self, send_socket, src_port, src_ip, dest_ip, tcp_headers):
        ack_packet = ''
        ip_header = self.getIpHeader(54322)
        
        # tcp header fields
        tcp_source_port = src_port
        tcp_seq = tcp_headers[3] 
        tcp_ack_seq = tcp_headers[2] + 1
        flag = 'ACK' # ack packet with empty packet
        tcp_header = self.getTcpHeader(tcp_seq, tcp_ack_seq, '', flag)
        ack_packet = ip_header + tcp_header
        send_socket.sendto(ack_packet,(dest_ip, 0))
    
    # handle the data of requests and return the ack packet
    def get_synack_send_ack(self, send_sock, recv_sock, buffer_size, src_ip, dest_ip, src_port):
        # Block this thread with listening
        while True:
            packet = recv_sock.recvfrom(buffer_size)
            received_packet = packet[0]
            # first 20 character is ip-header
            ip_header = received_packet[0:20]
            unpack_ip_header = unpack('!BBHHHBBH4s4s' , ip_header)
            # ipv version
            version_ihl = unpack_ip_header[0]
            # version = version_ihl >> 4
            temp = (version_ihl & 0xF)
            ip_header_length = temp * 4
            # ttl = unpack_ip_header[5]
            # protocol = unpack_ip_header[6]
            src_addr = socket.inet_ntoa(unpack_ip_header[8])
            dest_addr = socket.inet_ntoa(unpack_ip_header[9])
            # second 20 character is tcp-header
            tcp_header = received_packet[ip_header_length:ip_header_length+20]
            unpack_tcp_header = unpack('!HHLLBBHHH' , tcp_header)
            
            # dest_port = unpack_tcp_header[1]
            # seq_number = unpack_tcp_header[2]
            doff_reserved = unpack_tcp_header[4]
            tcp_temp = doff_reserved >> 4
            tcp_header_length = tcp_temp * 4 # slightly change
            
            # calculate the total header length
            header_size = ip_header_length + tcp_header_length
            # remaining is content
            # data_size = len(received_packet) - header_size
            # truncate for data
            # data = received_packet[header_size:]
            
            if src_addr == dest_ip and dest_addr == src_ip and unpack_tcp_header[5] == 18 and src_port == unpack_tcp_header[1] and ((time.time() - self.start_time) < 60):
                self.send_ack(send_sock, src_port, src_ip, dest_ip, unpack_tcp_header)
                break
            else :
                # if out of time, resend the request
                self.generate_syn(send_sock, src_ip, dest_ip, src_port)
                break
        return unpack_tcp_header, unpack_ip_header[4]
    
    # http get for file request
    def http_get_file(self, send_sock, src_ip, dest_ip, src_port, tcp_header, path, hostname):
        http_request = ''
        ip_header = self.getIpHeader(54323)
        # tcp-header
        # tcp_source = src_port
        tcp_seq = tcp_header[3]
        tcp_ack_seq = tcp_header[2] + 1
        flag = 'PSH-ACK'
        request_httpdata = 'GET '+path+' HTTP/1.0\r\nHOST: '+hostname+'\r\n\r\n'
        if len(request_httpdata) % 2 != 0:
            request_httpdata = request_httpdata + " "
        tcp_header4ack = self.getTcpHeader(tcp_seq, tcp_ack_seq, request_httpdata, flag)
        http_request = ip_header + tcp_header4ack + request_httpdata.encode('utf-8')
        send_sock.sendto(http_request, (dest_ip, 0))
    
    # handle the url parsing issue
    def get_filename(self, url):
        file_path = " "
        empty = ""
        url_path = url.path
        if url_path == empty:
            path_url = "/"
            file_path = "index.html"
        else :
            length_of_path = len(url_path)
            last_char = url_path[length_of_path - 1]
            if last_char == "/":
                path_url = "/"
                file_path = "index.html"
            else :
                path_url = url_path
                split_name = url_path.rsplit("/", 1)
                file_path = split_name[1]
        return file_path, path_url
    
    def download_file(self, send_sock, recv_sock, buffer_size, src_ip, dest_ip, src_port, path):
        # map key: int value: byte
        map = {}
        count = 0
        while True:
            # print("map")
            # print(map)
            packet = recv_sock.recvfrom(buffer_size)
            received_packet = packet[0]
            # first 20 character is ip-header
            ip_header = received_packet[0:20]
            unpack_ip_header = unpack('!BBHHHBBH4s4s' , ip_header)
            # ipv version
            version_ihl = unpack_ip_header[0]
            # version = version_ihl >> 4
            ip_header_length = (version_ihl & 0xF) * 4
            # ttl = unpack_ip_header[5]
            # protocol = unpack_ip_header[6]
            src_addr = socket.inet_ntoa(unpack_ip_header[8])
            # dest_addr = socket.inet_ntoa(unpack_ip_header[9])
            # second 20 character is tcp-header
            tcp_header = received_packet[ip_header_length:ip_header_length+20]
            unpack_tcp_header = unpack('!HHLLBBHHH' , tcp_header)
            # print("unpack_tcp_header")
            # print(unpack_tcp_header)
            
            dest_port = unpack_tcp_header[1]
            seq_num = unpack_tcp_header[2]
            doff_reserved = unpack_tcp_header[4]
            tcp_header_length = ((doff_reserved >> 4) * 4) # slightly change
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
            if dest_port == src_port and src_addr == dest_ip and data_size > 0 :
                count = count + 1
                data = received_packet[header_size:]
                map[seq_num] = data
                # teardown initiation
                teardown_initiator = ""
                ip_header_4ack = self.getIpHeader(54322)
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
                fin_packet = ""
                ip_header_4ack = self.getIpHeader(54322)
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
        #Divides the url into single strings of distinct strings
        split_url = urlparse(url_parameter)
        hostname = split_url.netloc
        self.src_ip = self.get_localhost_ip()
        self.dest_ip = socket.gethostbyname(urlparse(url_parameter).hostname)
        fp, path_url = self.get_filename(split_url)    
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
        while True:
            self.generate_syn(self.sock, self.src_ip, self.dest_ip, self.src_port)
            tcp_header, off_set = self.get_synack_send_ack(self.sock, self.recv_socket, self.buffer_size, self.src_ip, self.dest_ip, self.src_port) 
            if str(off_set) == "0":
                break
        print(str(tcp_header) + "tcp----------" + str(off_set))  
        self.http_get_file(self.sock, self.src_ip, self.dest_ip, self.src_port, tcp_header, path_url, hostname)
        self.download_file(self.sock, self.recv_socket, self.buffer_size, self.src_ip, self.dest_ip, self.src_port, fp)
        
        self.sock.close()
        self.recv_socket.close()
        sys.exit()
     
if __name__ == "__main__":
    rawhttpGet = RawHttpGet()
    rawhttpGet.rawhttpget()
        
    ## def tcp_checkSum(self, header, header_vals, )