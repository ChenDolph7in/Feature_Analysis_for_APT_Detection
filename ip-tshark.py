import os, sys
import threading
from time import sleep
from threading import Thread


class myThread(threading.Thread):
    def __init__(self, command):
        threading.Thread.__init__(self)
        self.command = command

    def run(self):
        print(self.command)
        os.system(self.command)


def field_parse(path):
    filelist = os.listdir(path)
    i = 0
    # VPN_ADDRESS = "'ip.addr==223.166.157.73 or ip.addr==120.241.126.212'"
    for file in filelist:
        if "pcap" in file:
            command0 = "tshark -r " + path + file + "  -T fields -e frame.number -e frame.time_relative -e ip.proto -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.len -e ip.hdr_len -e tcp.flags -e tcp.hdr_len -e tls.record.version -e ip.flags.mf -e tcp.ack -e tls.record.content_type -E header=n -E separator=, -E quote=n -E occurrence=f > ./fields/pre_fields/" + str(
                i) + ".csv 2>&1"

            command1 = "tshark -r " + path + file + "  -T fields -e frame.number -e frame.time_relative -e ip.proto -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tls.handshake.certificate -E header=n -E separator=, -E quote=n -E occurrence=a > ./fields/certificates/" + str(
                i) + ".csv 2>&1"

            command2 = "tshark -r " + path + file + "  -T fields -e frame.number -e frame.time_relative -e ip.proto -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tls.handshake.extensions_server_name -E header=n -E separator=, -E quote=n -E occurrence=a > ./fields/sni_lists/" + str(
                i) + ".csv 2>&1"

            thread_list = []
            try:
                mythread0 = myThread(command0)
                mythread0.start()
                thread_list.append(mythread0)
                mythread1 = myThread(command1)
                mythread1.start()
                thread_list.append(mythread1)
                mythread2 = myThread(command2)
                mythread2.start()
                thread_list.append(mythread2)
                for mythread in thread_list:
                    mythread.join()
            except:
                print("Error: unable to start thread")
            mythread0.join(5)
            mythread1.join(5)
            mythread2.join(5)
            print(i)
            '''
            index增加
            '''
            multi_ocurrence_merge(i)
            i += 1
    print('end')
    return i


def multi_ocurrence_merge(j):
    '''
            多值字段连接
    '''
    print("link : ", j);
    pre_field = open("./fields/pre_fields/" + str(j) + ".csv", 'r')
    certificate = open("./fields/certificates/" + str(j) + ".csv", 'r')
    sni_list = open("./fields/sni_lists/" + str(j) + ".csv", 'r')
    five_tuple = open("./five_tuples/" + str(j) + ".csv", 'w')
    while True:
        l1 = pre_field.readline()
        l2 = certificate.readline()
        l3 = sni_list.readline()

        if not l1:
            pre_field.close()
            certificate.close()
            sni_list.close()
            five_tuple.close()
            break
        d1 = l1[:-1].split(',')
        d2 = l2[:-1].split(',')[9:]
        d3 = l3[:-1].split(',')[9:]
        # print(d1)
        # print(d2)
        # print(d3)
        # print(','.join(d1 + [';'.join(d2)] + [';'.join(d3)]))
        five_tuple.write(','.join(d1 + [';'.join(d2)] + [';'.join(d3)]) + "\n")


if __name__ == '__main__':
    i = field_parse('./raw_data/')
    # if not os.path.exists("./five_tuples/0.csv"):
    #     sleep(5)

