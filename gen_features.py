# encoding=UTF-8
import OpenSSL
import time, os, sys, json
import numpy as np
import pandas as pd

from dateutil import parser

LOCAL_IP_ADDRESS = '10.0.2.15'  # local host ip address


def parse_x509(x509_data):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes.fromhex(x509_data))
    certIssue = cert.get_issuer()
    certSubject = cert.get_subject()
    notAfter = parser.parse(cert.get_notAfter().decode("utf-8"))
    notBefore = parser.parse(cert.get_notBefore().decode("utf-8"))

    SAN = ""
    ex_num = cert.get_extension_count()
    for i in range(ex_num):
        ex = cert.get_extension(i)
        ex_name = ex.get_short_name().decode("utf-8")
        if ex_name == 'subjectAltName':
            SAN = str(ex)
    return certIssue.commonName, certSubject.commonName, notBefore, notAfter, cert.has_expired(), SAN


def parse_tcp(flags_str):
    flags = []
    num = int(flags_str, 16)
    num = bin(num)[2:]
    # print(num)
    for i in range(len(num)):
        flags.append(num[len(num) - 1 - i])
    if len(num) < 8:
        for i in range(8 - len(num)):
            flags.append("0")
    return flags[0:8]


def gen_conn_state(flag_list, ack_list):
    # flags: FIN,SYN,RST,PSH,ACK,URG,ECE,CWR
    flag_list = np.array(flag_list)
    ack_list = np.array(ack_list)

    flag_ack_list = np.c_[flag_list, ack_list]

    client2server = flag_ack_list[np.where(flag_ack_list[:, 0] == "->")][:, 1:]
    server2client = flag_ack_list[np.where(flag_ack_list[:, 0] == "<-")][:, 1:]

    # The string of conn_state is on the perspective of client (originator)
    # reference from http://www.takakura.com/Kyoto_data/BenchmarkData-Description-v5.pdf
    conn_state = []
    for i in client2server:
        if (i == ['0', '1', '0', '0', '0', '0', '0', '0', '0']).all():
            conn_state.append("SYN sent")
            break

    for i in server2client:
        if (i == ['0', '1', '0', '0', '1', '0', '0', '0', '1']).all():
            conn_state.append("SYN-ACK received")
            break

    for i in client2server:
        if (i == ['0', '0', '0', '0', '1', '0', '0', '0', '1']).all():
            conn_state.append("ACK sent")
            break

    for i in client2server:
        if (i[:-1] == ['0', '0', '1', '0', '1', '0', '0', '0']).all() or (
                i[:-1] == ['0', '0', '1', '0', '0', '0', '0', '0']).all():
            conn_state.append("RST sent")
            break

    for i in server2client:
        if (i[:-1] == ['0', '0', '1', '0', '1', '0', '0', '0']).all() or (
                i[:-1] == ['0', '0', '1', '0', '0', '0', '0', '0']).all():
            conn_state.append("RST received")
            break

    FIN_sent = ""
    FIN_receive = ""
    for i in flag_ack_list:
        if FIN_sent == "" and i[1] == '1':
            FIN_sent = i[0]
        if FIN_sent != "" and i[1] == '1':
            FIN_receive = i[0]
            break
    # print(conn_state)
    # print("FIN senter : ",FIN_sent)
    # print("FIN receiver : ",FIN_receive)

    # generate connection state
    if "SYN sent" not in conn_state and "SYN-ACK received" not in conn_state:
        # No SYN seen, just midstream traffic (a “partial connection” that was not later closed)
        return "OTH"
    elif "SYN sent" in conn_state and len(conn_state) == 1:
        # Connection attempt seen, no reply
        return "S0"
    elif "SYN sent" in conn_state and "RST received" in conn_state:
        # Connection attempt rejected
        return "REJ"
    elif "SYN sent" in conn_state and "SYN-ACK received" not in conn_state and "RST sent" in conn_state:
        # Originator sent a SYN followed by a RST, we never saw a SYN ACK from the responder
        return "RSTOS0"
    elif "SYN sent" in conn_state and "SYN-ACK received" not in conn_state and FIN_sent == "->":
        #  Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open)
        return "SH"
    elif "SYN sent" not in conn_state and "SYN-ACK received" in conn_state and "RST received" in conn_state:
        #  Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator
        return "RSTRH"
    elif "SYN sent" not in conn_state and "SYN-ACK received" in conn_state and FIN_sent == "<-":
        # Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator
        return "SHR"
    elif "SYN sent" in conn_state and "SYN-ACK received" in conn_state and "ACK sent" in conn_state:
        # Connection established
        if "RST sent" not in conn_state and "RST received" not in conn_state and FIN_sent == "" and FIN_receive == "":
            # Connection established, not terminated
            return "S1"
        elif "RST sent" not in conn_state and "RST received" not in conn_state and (
                FIN_sent != "" and FIN_receive != ""):
            # Normal establishment and termination
            return "SF"
        elif "RST sent" not in conn_state and "RST received" not in conn_state and (
                FIN_sent == "->" and FIN_receive == ""):
            # Connection established and close attempt by originator seen (but no reply from responder)
            return "S2"
        elif "RST sent" not in conn_state and "RST received" not in conn_state and (
                FIN_sent == "<-" and FIN_receive == ""):
            # Connection established and close attempt by responder seen (but no reply from originator)
            return "S3"
        elif "RST sent" in conn_state:
            # Connection established, originator aborted (sent a RST)
            return "RSTO"
        elif "RST received" in conn_state:
            # Established, responder aborted
            return "RSTR"
    return "Error"


def gen_flow(filename):
    f_dic = {}
    f_dic['tcp'] = {}
    f_dic['udp'] = {}
    f_dic['more_seg_flag'] = {}
    f_dic['ip_hdr_len'] = {}
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line[0:-1].split(",")
            try:
                timestamp = float(line[1])
            except Exception as e:
                break
            proto = line[2]
            ip_src = line[3]
            ip_dst = line[4]
            ip_len = int(line[9]) if len(line[9])>0 else 0

            # new
            ip_hdr_len = int(line[10]) if len(line[10])>0 else 0
            tcp_flags = line[11]
            tcp_hdr_len = line[12]
            tls_version = line[13]
            more_seg_flag = line[14]
            tcp_ack = line[15]
            tls_content_type = line[16]
            certs = line[17]
            sni = line[18]
            # new end

            direction = '->'
            if proto == '6':
                if int(line[5]) > int(line[6]):
                    port_client = line[5]
                    port_server = line[6]
                    direction = '->'
                else:
                    port_client = line[6]
                    port_server = line[5]
                    direction = '<-'
                key = port_client + '<->' + port_server
                if key not in f_dic['more_seg_flag'].keys():
                    if more_seg_flag == '1':
                        f_dic['more_seg_flag'][key] = {}
                        f_dic['more_seg_flag'][key]['->'] = []
                        f_dic['more_seg_flag'][key]['<-'] = []
                        f_dic['more_seg_flag'][key][direction].append(ip_len)
                else:
                    if more_seg_flag == '1':
                        f_dic['more_seg_flag'][key][direction].append(ip_len)

                if key not in f_dic['ip_hdr_len'].keys():
                    f_dic['ip_hdr_len'][key] = {}
                    f_dic['ip_hdr_len'][key]['->'] = 0
                    f_dic['ip_hdr_len'][key]['<-'] = 0
                    f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
                else:
                    f_dic['ip_hdr_len'][key][direction] += ip_hdr_len

                if key not in f_dic['tcp'].keys():
                    f_dic['tcp'][key] = {}
                    f_dic['tcp'][key]['->'] = []
                    f_dic['tcp'][key]['<-'] = []
                    f_dic['tcp'][key]['<->'] = []
                    f_dic['tcp'][key][direction].append(ip_len)
                    f_dic['tcp'][key]['time'] = {}
                    f_dic['tcp'][key]['time'][direction] = [timestamp]
                    f_dic['tcp'][key]['time']['<->'] = [timestamp]
                    # new
                    f_dic['tcp'][key]['tcp_flag'] = [direction + ":" + tcp_flags]
                    f_dic['tcp'][key]['tcp_ack'] = [tcp_ack]
                    if tls_content_type != '':
                        f_dic['tcp'][key]['tls_content_type'] = [tls_content_type]
                    else:
                        f_dic['tcp'][key]['tls_content_type'] = []
                    if tls_version != '':
                        f_dic['tcp'][key]['tls_version'] = [tls_version]
                    else:
                        f_dic['tcp'][key]['tls_version'] = []
                    if certs != '':
                        f_dic['tcp'][key]['certs'] = [certs]
                    else:
                        f_dic['tcp'][key]['certs'] = []
                    if sni != '':
                        f_dic['tcp'][key]['sni'] = [sni]
                    else:
                        f_dic['tcp'][key]['sni'] = []
                    # new end
                else:
                    if direction not in f_dic['tcp'][key]['time'].keys():
                        f_dic['tcp'][key]['time'][direction] = [timestamp]
                    f_dic['tcp'][key][direction].append(ip_len)
                    f_dic['tcp'][key]['time'][direction].append(timestamp)
                f_dic['tcp'][key]['<->'].append(ip_len)
                f_dic['tcp'][key]['time']['<->'].append(timestamp)
                # new
                f_dic['tcp'][key]['tcp_flag'].append(direction + ":" + tcp_flags)
                f_dic['tcp'][key]['tcp_ack'].append(tcp_ack)
                if tls_content_type != '': f_dic['tcp'][key]['tls_content_type'].append(tls_content_type)

                if tls_version != '': f_dic['tcp'][key]['tls_version'].append(tls_version)
                if certs != '': f_dic['tcp'][key]['certs'].append(certs)
                if sni != '' and sni not in f_dic['tcp'][key]['sni']: f_dic['tcp'][key]['sni'].append(sni)
                # new end
            # else:
            #     if int(line[7]) > int(line[8]):
            #         port_client = line[7]
            #         port_server = line[8]
            #         direction = '->'
            #     else:
            #         port_client = line[8]
            #         port_server = line[7]
            #         direction = '<-'
            #     key = port_client + '<->' + port_server
            #     if key not in f_dic['more_seg_flag'].keys():
            #         if more_seg_flag == '1':
            #             f_dic['more_seg_flag'][key] = {}
            #             f_dic['more_seg_flag'][key]['->'] = []
            #             f_dic['more_seg_flag'][key]['<-'] = []
            #             f_dic['more_seg_flag'][key][direction].append(ip_len)
            #     else:
            #         if more_seg_flag == '1':
            #             f_dic['more_seg_flag'][key][direction].append(ip_len)
            #
            #     if key not in f_dic['ip_hdr_len'].keys():
            #         f_dic['ip_hdr_len'][key] = {}
            #         f_dic['ip_hdr_len'][key]['->'] = 0
            #         f_dic['ip_hdr_len'][key]['<-'] = 0
            #         f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
            #     else:
            #         f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
            #
            #     if key not in f_dic['udp'].keys():
            #         f_dic['udp'][key] = {}
            #         f_dic['udp'][key]['->'] = []
            #         f_dic['udp'][key]['<-'] = []
            #         f_dic['udp'][key]['<->'] = []
            #         f_dic['udp'][key][direction].append(ip_len)
            #         f_dic['udp'][key]['time'] = {}
            #         f_dic['udp'][key]['time'][direction] = [timestamp]
            #         f_dic['udp'][key]['time']['<->'] = [timestamp]
            #     else:
            #         if direction not in f_dic['udp'][key]['time'].keys():
            #             f_dic['udp'][key]['time'][direction] = [timestamp]
            #         f_dic['udp'][key][direction].append(ip_len)
            #         f_dic['udp'][key]['time'][direction].append(timestamp)
            #     f_dic['udp'][key]['<->'].append(ip_len)
            #     f_dic['udp'][key]['time']['<->'].append(timestamp)
        return f_dic


def get_statistical_fraturs(list, timestamp_list):
    duration = timestamp_list[-1] - timestamp_list[0] if len(timestamp_list) > 0 else 0

    if len(list) > 0:
        f_max = max(list)
        f_min = min(list)
        f_mean = np.mean(list)
        f_var = np.var(list)
        f_std = np.std(list, ddof=1)
        f_sum = sum(list)
        f_pkts_num = len(list)
        if duration < 0.1:
            f_speed = 0
        else:
            f_speed = f_sum / duration
        f_10_p = np.percentile(list, 10)
        f_20_p = np.percentile(list, 20)
        f_30_p = np.percentile(list, 30)
        f_40_p = np.percentile(list, 40)
        f_50_p = np.percentile(list, 50)
        f_60_p = np.percentile(list, 60)
        f_70_p = np.percentile(list, 70)
        f_80_p = np.percentile(list, 80)
        f_90_p = np.percentile(list, 90)
    else:
        f_max, f_min, f_mean, f_var, f_std, f_sum, f_pkts_num, f_speed = 0, 0, 0, 0, 0, 0, 0, 0
        f_10_p, f_20_p, f_30_p, f_40_p, f_50_p, f_60_p, f_70_p, f_80_p, f_90_p = 0, 0, 0, 0, 0, 0, 0, 0, 0

    flow_IAT_list = []
    for i in range(len(timestamp_list) - 1):
        flow_IAT_list.append(timestamp_list[i + 1] - timestamp_list[i])
    if len(flow_IAT_list) > 0:
        IAT_min = min(flow_IAT_list)
        IAT_max = max(flow_IAT_list)
        IAT_avg = np.mean(flow_IAT_list)
        IAT_std = np.std(flow_IAT_list, ddof=1)
        IAT_total = np.sum(flow_IAT_list)
    else:
        IAT_min, IAT_max, IAT_avg, IAT_std, IAT_total = 0, 0, 0, 0, 0
    return f_sum, f_pkts_num, duration, f_speed, f_max, f_min, f_mean, f_var, f_std, f_10_p, f_20_p, f_30_p, f_40_p, f_50_p, f_60_p, f_70_p, f_80_p, f_90_p, IAT_min, IAT_max, IAT_avg, IAT_std, IAT_total


def get_sample_features(file, f_dic):
    f_list = []
    tag = 4
    for key in f_dic['tcp'].keys():
        proto = 'tcp'
        if '->' in f_dic[proto][key]['time'].keys():
            send = get_statistical_fraturs(f_dic[proto][key]['->'], f_dic[proto][key]['time']['->'])
        else:
            send = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<-' in f_dic[proto][key]['time'].keys():
            receive = get_statistical_fraturs(f_dic[proto][key]['<-'], f_dic[proto][key]['time']['<-'])
        else:
            receive = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<->' in f_dic[proto][key]['time'].keys():
            total = get_statistical_fraturs(f_dic[proto][key]['<->'], f_dic[proto][key]['time']['<->'])
        else:
            total = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        records = []
        records.append(file[:-4])
        records.append(tag)
        records.append(1)  # proto=='tcp'
        records.append(f_dic[proto][key]['time']['<->'][0])
        records.append(f_dic['ip_hdr_len'][key]['->'])
        records.append(f_dic['ip_hdr_len'][key]['<-'])
        for i in send:
            records.append(i)
        for i in receive:
            records.append(i)
        for i in total:
            records.append(i)

        records.append(";".join(f_dic['tcp'][key]['tcp_flag']))

        flags_list = []
        c_FIN_cnt = 0
        c_SYN_cnt = 0
        c_RST_cnt = 0
        c_PSH_cnt = 0
        c_ACK_cnt = 0
        c_URG_cnt = 0
        c_ECE_cnt = 0
        c_CWR_cnt = 0
        try:

            for i in f_dic['tcp'][key]['tcp_flag']:
                line = i.split(":")
                flags = parse_tcp(line[1])
                flags_list.append([line[0]] + flags)
            t_flags_list = np.array(flags_list)
            c_flags_list = t_flags_list[np.where(t_flags_list[:, 0] == "->")]
            s_flags_list = t_flags_list[np.where(t_flags_list[:, 0] == "<-")]
            c_FIN_cnt = np.sum(c_flags_list[:, 1] == '1')
            c_SYN_cnt = np.sum(c_flags_list[:, 2] == '1')
            c_RST_cnt = np.sum(c_flags_list[:, 3] == '1')
            c_PSH_cnt = np.sum(c_flags_list[:, 4] == '1')
            c_ACK_cnt = np.sum(c_flags_list[:, 5] == '1')
            c_URG_cnt = np.sum(c_flags_list[:, 6] == '1')
            c_ECE_cnt = np.sum(c_flags_list[:, 7] == '1')
            c_CWR_cnt = np.sum(c_flags_list[:, 8] == '1')
        except Exception as e:
            print(flags_list)
            print(e)
        records.append(c_FIN_cnt)
        records.append(c_SYN_cnt)
        records.append(c_RST_cnt)
        records.append(c_PSH_cnt)
        records.append(c_ACK_cnt)
        records.append(c_URG_cnt)
        records.append(c_ECE_cnt)
        records.append(c_CWR_cnt)
        s_FIN_cnt = np.sum(s_flags_list[:, 1] == '1')
        s_SYN_cnt = np.sum(s_flags_list[:, 2] == '1')
        s_RST_cnt = np.sum(s_flags_list[:, 3] == '1')
        s_PSH_cnt = np.sum(s_flags_list[:, 4] == '1')
        s_ACK_cnt = np.sum(s_flags_list[:, 5] == '1')
        s_URG_cnt = np.sum(s_flags_list[:, 6] == '1')
        s_ECE_cnt = np.sum(s_flags_list[:, 7] == '1')
        s_CWR_cnt = np.sum(s_flags_list[:, 8] == '1')
        records.append(s_FIN_cnt)
        records.append(s_SYN_cnt)
        records.append(s_RST_cnt)
        records.append(s_PSH_cnt)
        records.append(s_ACK_cnt)
        records.append(s_URG_cnt)
        records.append(s_ECE_cnt)
        records.append(s_CWR_cnt)
        t_FIN_cnt = np.sum(t_flags_list[:, 1] == '1')
        t_SYN_cnt = np.sum(t_flags_list[:, 2] == '1')
        t_RST_cnt = np.sum(t_flags_list[:, 3] == '1')
        t_PSH_cnt = np.sum(t_flags_list[:, 4] == '1')
        t_ACK_cnt = np.sum(t_flags_list[:, 5] == '1')
        t_URG_cnt = np.sum(t_flags_list[:, 6] == '1')
        t_ECE_cnt = np.sum(t_flags_list[:, 7] == '1')
        t_CWR_cnt = np.sum(t_flags_list[:, 8] == '1')
        records.append(t_FIN_cnt)
        records.append(t_SYN_cnt)
        records.append(t_RST_cnt)
        records.append(t_PSH_cnt)
        records.append(t_ACK_cnt)
        records.append(t_URG_cnt)
        records.append(t_ECE_cnt)
        records.append(t_CWR_cnt)

        records.append(";".join(f_dic['tcp'][key]['tcp_ack']))
        conn_state = gen_conn_state(flags_list, f_dic['tcp'][key]['tcp_ack'])
        records.append(conn_state)
        if key in f_dic['more_seg_flag']:
            records.append(";".join(f_dic['more_seg_flag'][key]['->']))
            records.append(";".join(f_dic['more_seg_flag'][key]['<-']))

        else:
            records.append("")
            records.append("")
        records.append(";".join(f_dic['tcp'][key]['tls_version']))
        records.append(";".join(f_dic['tcp'][key]['tls_content_type']))
        CCS_cnt = f_dic['tcp'][key]['tls_content_type'].count('22')
        records.append(CCS_cnt)

        records.append(";".join(f_dic['tcp'][key]['certs']))
        records.append(";".join(f_dic['tcp'][key]['sni']))

        f_list.append(records)

    for key in f_dic['udp'].keys():
        proto = 'udp'
        if '->' in f_dic[proto][key]['time'].keys():
            send = get_statistical_fraturs(f_dic[proto][key]['->'], f_dic[proto][key]['time']['->'])
        else:
            send = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<-' in f_dic[proto][key]['time'].keys():
            receive = get_statistical_fraturs(f_dic[proto][key]['<-'], f_dic[proto][key]['time']['<-'])
        else:
            receive = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<->' in f_dic[proto][key]['time'].keys():
            total = get_statistical_fraturs(f_dic[proto][key]['<->'], f_dic[proto][key]['time']['<->'])
        else:
            total = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        records = []
        records.append(file[:-4])
        records.append(tag)
        records.append(0)  # proto=='udp'
        records.append(f_dic[proto][key]['time']['<->'][0])
        records.append(f_dic['ip_hdr_len'][key]['->'])
        records.append(f_dic['ip_hdr_len'][key]['<-'])
        for i in send:
            records.append(i)
        for i in receive:
            records.append(i)
        for i in total:
            records.append(i)
        # f_list.append(records)
    return f_list


def read_batch():
    filelist = os.listdir('./session/')
    f_list_all = []
    for file in filelist:
        if '.csv' in file and 'output' not in file:
            f_dic = gen_flow('./session/' + file)
            f_list = get_sample_features(file, f_dic)
            for i in f_list:
                f_list_all.append(i)
            f_list = []
    name = ['file', 'tag', 'proto', 'timestamp', 'c_hdr_len', 's_hdr_len',
            'c_sum', 'c_pkts_num', 'c_duration', 'c_speed', 'c_max', 'c_min', 'c_mean',
            'c_var', 'c_std', 'c_10_p', 'c_20_p', 'c_30_p', 'c_40_p', 'c_50_p', 'c_60_p', 'c_70_p', 'c_80_p', 'c_90_p',
            'c_iat_min', 'c_iat_max', 'c_iat_avg', 'c_iat_std', 'c_iat_total',
            's_sum', 's_pkts_num', 's_duration', 's_speed', 's_max', 's_min', 's_mean', 's_var', 's_std', 's_10_p',
            's_20_p', 's_30_p', 's_40_p', 's_50_p', 's_60_p', 's_70_p', 's_80_p', 's_90_p',
            's_iat_min', 's_iat_max', 's_iat_avg', 's_iat_std', 's_iat_total',
            't_sum', 't_pkts_num', 't_duration', 't_speed', 't_max', 't_min', 't_mean', 't_var', 't_std', 't_10_p',
            't_20_p', 't_30_p', 't_40_p', 't_50_p', 't_60_p', 't_70_p', 't_80_p', 't_90_p',
            't_iat_min', 't_iat_max', 't_iat_avg', 't_iat_std', 't_iat_total'
            ]
    # FIN, SYN, RST, PSH, ACK, URG, ECE, CWR
    new_name = ['tcp_flag', 'c_FIN_cnt', 'c_SYN_cnt', 'c_RST_cnt', 'c_PSH_cnt', 'c_ACK_cnt', 'c_URG_cnt', 'c_ECE_cnt',
                'c_CWR_cnt',
                's_FIN_cnt', 's_SYN_cnt', 's_RST_cnt', 's_PSH_cnt', 's_ACK_cnt', 's_URG_cnt', 's_ECE_cnt', 's_CWR_cnt',
                't_FIN_cnt', 't_SYN_cnt', 't_RST_cnt', 't_PSH_cnt', 't_ACK_cnt', 't_URG_cnt', 't_ECE_cnt', 't_CWR_cnt',
                'tcp_ack', 'conn_state', 'fw_seg', 'bw_seg', 'tls_version', 'tls_content_type', 'CCS_cnt',
                'certs', 'sni']
    csvdata = pd.DataFrame(columns=name + new_name, data=f_list_all)
    csvdata.to_csv("output.csv", encoding='utf-8')


if __name__ == '__main__':
    read_batch()
