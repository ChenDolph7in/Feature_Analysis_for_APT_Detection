import pandas as pd
import numpy as np
import OpenSSL
import difflib
from dateutil import parser
import datetime

pd.set_option('display.max_columns', 8)


def is_nan(input):
    return input != input or input == 0

def cal_similarity(str1, str2):
    return difflib.SequenceMatcher(None, str1, str2).ratio()

def parse_tls_version(tls_version):
    version_list = tls_version.split(";")

    version = int(version_list[0], 16)
    if version == 769:  # 0x0301
        return 1  # tls 1.0
    elif version == 770:  # 0x0302
        return 2  # tls 1.1
    elif version == 771:  # 0x0303
        return 3  # tls 1.2
    else:
        return 4


def self_cert_detect(cert_list):
    for x509_data in cert_list:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes.fromhex(x509_data))
        certIssue = cert.get_issuer()
        certSubject = cert.get_subject()
        # issue = {}
        # subject = {}
        # for item in certIssue.get_components():
        #     key = item[0].decode("utf-8")
        #     if key not in issue.keys():
        #         issue[key] = [item[1].decode("utf-8")]
        #     else:
        #         issue[key].append(item[1].decode("utf-8"))
        # for item in certSubject.get_components():
        #     key = item[0].decode("utf-8")
        #     if key not in subject.keys():
        #         subject[key] = [item[1].decode("utf-8")]
        #     else:
        #         subject[key].append(item[1].decode("utf-8"))
        issue = []
        subject = []
        for item in certIssue.get_components():
            issue.append(item[1].decode("utf-8"))
        for item in certSubject.get_components():
            subject.append(item[1].decode("utf-8"))

        # issue = certIssue.commonName
        # subject = certSubject.commonName

        similarity = cal_similarity(issue, subject)

        if similarity > 0.9:
            return 1
        else:
            return 0


def parse_x509_cert(cert_list, sni_list):
    # valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag
    valid_list = []
    expire_flag = 0
    age_list = []
    san_dns_total_list = []
    consistent_flag = 0
    now_time = datetime.datetime.now()
    for x509_data in cert_list:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes.fromhex(x509_data))
        notBefore = parser.parse(cert.get_notBefore().decode("utf-8")).replace(tzinfo=None)
        notAfter = parser.parse(cert.get_notAfter().decode("utf-8")).replace(tzinfo=None)

        valid_seconds = (notAfter - notBefore).total_seconds()
        valid_list.append(valid_seconds)
        life_seconds = (now_time - notBefore).total_seconds()
        if cert.has_expired():
            expire_flag = 1
        age = life_seconds / valid_seconds
        age_list.append(age)
        san_dns_list = []
        for i in range(cert.get_extension_count()):
            extension = cert.get_extension(i)
            short_name = extension.get_short_name()
            if short_name == 'subjectAltName':
                san_dns = str(extension)
                san_dns_list = [i.split(":")[1] for i in san_dns.split(",")]
        if len(san_dns_list) > 0:
            san_dns_total_list += san_dns_list
        if len(san_dns_list) != 0 and len(sni_list) != 0 and consistent_flag == 0:

            if cal_similarity(san_dns_list, sni_list) > 0.9:
                consistent_flag = 1
            # for i in san_dns_list:
            #     for j in sni_list:
            #         if cal_similarity(i, j) > 0.9:
            #             consistent_flag = 1

    valid_avg = np.mean(valid_list) if len(valid_list) > 0 else 0
    valid_std = np.std(valid_list) if len(valid_list) > 0 else 0
    age_avg = np.mean(age_list) if len(age_list) > 0 else 0

    san_dns_num_avg = len(san_dns_total_list) / len(cert_list) if len(cert_list) != 0 else 0
    return valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag


def parse_features():
    lines = pd.read_csv('output.csv', sep=',', encoding='utf-8').iloc[:, 1:]
    # expand five tuple data from filename string
    five_tuple_data = lines['file'].str.split('_', expand=True)
    five_tuple_data_column = ['origin_file', 'proto', 'ip.src', 'port.src', 'ip.dst', 'port.dst']

    # get total data and columns
    data = np.hstack((five_tuple_data.values, lines.values))
    column = list(five_tuple_data_column) + list(lines.columns)
    data = data[data[:, 9].argsort()]

    # start parse
    feature_list = []
    for i in range(len(data)):
        line = data[i]
        ip_src = line[2]
        port_src = line[3]
        ip_dst = line[4]
        port_dst = line[5]
        proto = line[8]
        label = line[7]

        SSL_flag = 0 if is_nan(line[110]) else 1
        TLS_version = parse_tls_version(line[110]) if not is_nan(line[110]) else 0
        sni_flag = 1 if not is_nan(line[114]) else 0
        cert_list = line[113].split(";") if not is_nan(line[113]) else []
        cert_chain_len = len(cert_list)
        self_cert_flag = self_cert_detect(cert_list)
        # dga_flag

        sni_list = line[114].split(";") if not is_nan(line[114]) else []
        valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag = parse_x509_cert(cert_list,
                                                                                                       sni_list)
        cert_num = len(cert_list)

        fw_pkt_l_max = line[16]
        fw_pkt_l_min = line[17]
        fw_pkt_l_avg = line[18]
        fw_pkt_l_var = line[19]
        fw_pkt_l_std = line[20]

        bw_pkt_l_max = line[39]
        bw_pkt_l_min = line[40]
        bw_pkt_l_avg = line[41]
        bw_pkt_l_var = line[42]
        bw_pkt_l_std = line[43]

        fl_pkt_l_max = line[62]
        fl_pkt_l_min = line[63]
        fl_pkt_l_avg = line[64]
        fl_pkt_l_var = line[65]
        fl_pkt_l_std = line[66]

        fw_byt_s = line[15]
        bw_byt_s = line[38]
        fl_byt_s = line[61]

        fw_duration = line[14]
        bw_duration = line[37]
        fl_duration = line[60]
        fw_pkt_s = line[13] / fw_duration if not is_nan(fw_duration) and fw_duration > 0.1 else 0
        bw_pkt_s = line[36] / bw_duration if not is_nan(bw_duration) and bw_duration > 0.1 else 0
        fl_pkt_s = line[59] / fl_duration if not is_nan(fl_duration) and fl_duration > 0.1 else 0

        fw_iat_min = line[30]
        fw_iat_max = line[31]
        fw_iat_avg = line[32]
        fw_iat_std = line[33]
        fw_iat_tot = line[34]

        bw_iat_min = line[53]
        bw_iat_max = line[54]
        bw_iat_avg = line[55]
        bw_iat_std = line[56]
        bw_iat_tot = line[57]

        fl_iat_min = line[76]
        fl_iat_max = line[77]
        fl_iat_avg = line[78]
        fl_iat_std = line[79]
        fl_iat_tot = line[80]

        fw_fin_cnt = line[82]
        fw_syn_cnt = line[83]
        fw_rst_cnt = line[84]
        fw_psh_cnt = line[85]
        fw_ack_cnt = line[86]
        fw_urg_cnt = line[87]
        fw_ece_cnt = line[88]
        fw_cwr_cnt = line[89]

        bw_fin_cnt = line[90]
        bw_syn_cnt = line[91]
        bw_rst_cnt = line[92]
        bw_psh_cnt = line[93]
        bw_ack_cnt = line[94]
        bw_urg_cnt = line[95]
        bw_ece_cnt = line[96]
        bw_cwr_cnt = line[97]

        fl_fin_cnt = line[98]
        fl_syn_cnt = line[99]
        fl_rst_cnt = line[100]
        fl_psh_cnt = line[101]
        fl_ack_cnt = line[102]
        fl_urg_cnt = line[103]
        fl_ece_cnt = line[104]
        fl_cwr_cnt = line[105]

        fw_10_p = line[21]
        fw_20_p = line[22]
        fw_30_p = line[23]
        fw_40_p = line[24]
        fw_50_p = line[25]
        fw_60_p = line[26]
        fw_70_p = line[27]
        fw_80_p = line[28]
        fw_90_p = line[29]

        bw_10_p = line[44]
        bw_20_p = line[45]
        bw_30_p = line[46]
        bw_40_p = line[47]
        bw_50_p = line[48]
        bw_60_p = line[49]
        bw_70_p = line[50]
        bw_80_p = line[51]
        bw_90_p = line[52]

        fl_10_p = line[67]
        fl_20_p = line[68]
        fl_30_p = line[69]
        fl_40_p = line[70]
        fl_50_p = line[71]
        fl_60_p = line[72]
        fl_70_p = line[73]
        fl_80_p = line[74]
        fl_90_p = line[75]

        fw_hdr_len = line[10]
        bw_hdr_len = line[11]

        down_up_ratio = line[35] / line[12] if not is_nan(line[12]) else 0
        # pkt_size_avg =

        fw_seg_avg = np.mean(line[108].split(";")) if not is_nan(line[108]) else 0
        bw_seg_avg = np.mean(line[109].split(";")) if not is_nan(line[109]) else 0
        fw_seg_cnt = len(line[108].split(";")) if not is_nan(line[108]) else 0
        bw_seg_cnt = len(line[109].split(";")) if not is_nan(line[109]) else 0
        fl_seg_cnt = fw_seg_cnt + bw_seg_cnt
        conn_state = line[107]
        timestamp = line[9]

        # 基于时间的网络流量统计特征
        last_2_s_list = data[np.where((data[:, 9] <= timestamp) & (data[:, 9] > timestamp - 2))]

        last_2_same_host_list = last_2_s_list[np.where(last_2_s_list[:, 4] == ip_dst)]
        count = len(last_2_same_host_list)
        serror_list = last_2_same_host_list[np.where(
            (last_2_same_host_list[:, 107] == 'S0') & (last_2_same_host_list[:, 107] == 'S1') & (
                    last_2_same_host_list[:, 107] == 'S2') & (
                    last_2_same_host_list[:, 107] == 'S3'))]
        serror_rate = len(serror_list) / count if count > 0 else 0
        rerror_list = last_2_same_host_list[np.where(last_2_same_host_list[:, 107] == 'REJ')]
        rerror_rate = len(rerror_list) / count if count > 0 else 0
        last_2_host_srv_list = last_2_same_host_list[np.where(last_2_same_host_list[:, 8] == proto)]
        host_srv_cnt = len(last_2_host_srv_list)
        same_srv_rate = host_srv_cnt / count if count > 0 else 0
        diff_srv_rate = 1 - same_srv_rate

        last_2_same_src_list = last_2_s_list[np.where(last_2_s_list[:, 8] == proto)]
        srv_count = len(last_2_same_src_list)
        srv_serror_list = last_2_s_list[np.where(
            (last_2_same_src_list[:, 107] == 'S0') & (last_2_same_src_list[:, 107] == 'S1') & (
                    last_2_same_src_list[:, 107] == 'S2') & (
                    last_2_same_src_list[:, 107] == 'S3'))]
        srv_rerror_list = last_2_same_src_list[np.where(last_2_same_src_list[:, 107] == 'REJ')]
        srv_serror_rate = len(srv_serror_list) / srv_count if srv_count > 0 else 0
        srv_rerror_rate = len(srv_rerror_list) / srv_count if srv_count > 0 else 0
        srv_same_host_rate = host_srv_cnt / srv_count if srv_count > 0 else 0
        srv_diff_host_rate = 1 - srv_same_host_rate

        # 基于主机的网络流量统计特征
        first = i - 100 if (i - 100) > 0 else 1
        last_100_list = data[0:first, :]
        last_100_cnt = len(last_100_list)
        same_host_list = last_100_list[np.where(last_100_list[:, 4] == ip_dst)]
        same_host_srv_list = last_100_list[np.where((last_100_list[:, 4] == ip_dst) & (last_100_list[:, 8] == proto))]
        dst_host_count = len(same_host_list)
        dst_host_srv_count = len(same_host_srv_list)
        dst_host_same_srv_rate = dst_host_count / last_100_cnt if last_100_cnt > 0 else 0
        dst_host_diff_srv_rate = 1 - dst_host_same_srv_rate
        same_host_sport_list = last_100_list[
            np.where((last_100_list[:, 4] == ip_dst) & (last_100_list[:, 3] == port_src))]
        dst_host_same_src_port_rate = len(same_host_sport_list) / last_100_cnt if last_100_cnt > 0 else 0
        diff_sip_list = same_host_srv_list[np.where(same_host_srv_list[:, 2] != ip_src)]
        dst_host_srv_diff_host_rate = len(diff_sip_list) / dst_host_srv_count if dst_host_srv_count > 0 else 0

        dst_host_serror_list = same_host_list[np.where(
            (same_host_list[:, 107] == 'S0') & (same_host_list[:, 107] == 'S1') & (
                    same_host_list[:, 107] == 'S2') & (
                    same_host_list[:, 107] == 'S3'))]
        dst_host_serror_rate = len(dst_host_serror_list) / dst_host_count if dst_host_count > 0 else 0
        dst_host_rerror_list = same_host_list[np.where(same_host_list[:, 107] == 'REJ')]
        dst_host_rerror_rate = len(dst_host_rerror_list) / dst_host_count if dst_host_count > 0 else 0

        dst_host_srv_serror_list = same_host_srv_list[np.where(
            (same_host_srv_list[:, 107] == 'S0') & (same_host_srv_list[:, 107] == 'S1') & (
                    same_host_srv_list[:, 107] == 'S2') & (
                    same_host_srv_list[:, 107] == 'S3'))]
        dst_host_srv_serror_rate = len(dst_host_srv_serror_list) / dst_host_srv_count if dst_host_srv_count > 0 else 0
        dst_host_srv_rerror_list = same_host_srv_list[np.where(same_host_srv_list[:, 107] == 'REJ')]
        dst_host_srv_rerror_rate = len(dst_host_srv_rerror_list) / dst_host_srv_count if dst_host_srv_count > 0 else 0

        new_line = [ip_src, port_src, ip_dst, port_dst, proto, label, timestamp, SSL_flag, TLS_version, sni_flag,
                    cert_chain_len, self_cert_flag,
                    valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag, cert_num,
                    fw_pkt_l_max, fw_pkt_l_min, fw_pkt_l_avg, fw_pkt_l_var, fw_pkt_l_std, fw_byt_s,
                    fw_pkt_s, fw_iat_min, fw_iat_max, fw_iat_avg, fw_iat_std, fw_iat_tot,
                    fw_fin_cnt, fw_syn_cnt, fw_rst_cnt, fw_psh_cnt, fw_ack_cnt, fw_urg_cnt, fw_ece_cnt,
                    fw_cwr_cnt, fw_10_p, fw_20_p, fw_30_p, fw_40_p, fw_50_p, fw_60_p, fw_70_p, fw_80_p, fw_90_p, fw_duration,
                    bw_pkt_l_max, bw_pkt_l_min, bw_pkt_l_avg, bw_pkt_l_var, bw_pkt_l_std, bw_byt_s,
                    bw_pkt_s, bw_iat_min, bw_iat_max, bw_iat_avg, bw_iat_std, bw_iat_tot,
                    bw_fin_cnt, bw_syn_cnt, bw_rst_cnt, bw_psh_cnt, bw_ack_cnt, bw_urg_cnt, bw_ece_cnt,
                    bw_cwr_cnt, bw_10_p, bw_20_p, bw_30_p, bw_40_p, bw_50_p, bw_60_p, bw_70_p, bw_80_p, bw_90_p, bw_duration,
                    fl_pkt_l_max, fl_pkt_l_min, fl_pkt_l_avg, fl_pkt_l_var, fl_pkt_l_std, fl_byt_s,
                    fl_pkt_s, fl_iat_min, fl_iat_max, fl_iat_avg, fl_iat_std, fl_iat_tot,
                    fl_fin_cnt, fl_syn_cnt, fl_rst_cnt, fl_psh_cnt, fl_ack_cnt, fl_urg_cnt, fl_ece_cnt,
                    fl_cwr_cnt, fl_10_p, fl_20_p, fl_30_p, fl_40_p, fl_50_p, fl_60_p, fl_70_p, fl_80_p, fl_90_p, fl_duration,
                    fw_hdr_len, bw_hdr_len, down_up_ratio, fw_seg_avg, bw_seg_avg, fl_seg_cnt, conn_state,
                    count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate,
                    diff_srv_rate, srv_diff_host_rate, srv_same_host_rate,
                    dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
                    dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
                    dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate
                    ]
        feature_list.append(new_line)
    column = ['ip.src', 'port.src', 'ip.dst', 'port.dst', 'proto', 'tag', 'timestamp', 'ssl_flag', 'tls_version',
              'sni_flag',
              'cert_chain_len', 'self_cert_flag',
              'valid_avg', 'valid_std', 'expire_flag', 'age_avg', 'san_dns_num_avg', 'consistent_flag', 'cert_num',
              'fw_pkt_l_max', 'fw_pkt_l_min ', 'fw_pkt_l_avg', 'fw_pkt_l_var', 'fw_pkt_l_std', 'fw_byt_s',
              'fw_pkt_s', 'fw_iat_min', 'fw_iat_max', 'fw_iat_avg', 'fw_iat_std', 'fw_iat_tot',
              'fw_fin_cnt', 'fw_syn_cnt', 'fw_rst_cnt', 'fw_psh_cnt', 'fw_ack_cnt', 'fw_urg_cnt', 'fw_ece_cnt',
              'fw_cwr_cnt', 'fw_10_p', 'fw_20_p', 'fw_30_p', 'fw_40_p', 'fw_50_p', 'fw_60_p', 'fw_70_p', 'fw_80_p',
              'fw_90_p', 'fw_duration',
              'bw_pkt_l_max', 'bw_pkt_l_min ', 'bw_pkt_l_avg', 'bw_pkt_l_var', 'bw_pkt_l_std', 'bw_byt_s',
              'bw_pkt_s', 'bw_iat_min', 'bw_iat_max', 'bw_iat_avg', 'bw_iat_std', 'bw_iat_tot',
              'bw_fin_cnt', 'bw_syn_cnt', 'bw_rst_cnt', 'bw_psh_cnt', 'bw_ack_cnt', 'bw_urg_cnt', 'bw_ece_cnt',
              'bw_cwr_cnt', 'bw_10_p', 'bw_20_p', 'bw_30_p', 'bw_40_p', 'bw_50_p', 'bw_60_p', 'bw_70_p', 'bw_80_p',
              'bw_90_p', 'bw_duration',
              'fl_pkt_l_max', 'fl_pkt_l_min ', 'fl_pkt_l_avg', 'fl_pkt_l_var', 'fl_pkt_l_std', 'fl_byt_s',
              'fl_pkt_s', 'fl_iat_min', 'fl_iat_max', 'fl_iat_avg', 'fl_iat_std', 'fl_iat_tot',
              'fl_fin_cnt', 'fl_syn_cnt', 'fl_rst_cnt', 'fl_psh_cnt', 'fl_ack_cnt', 'fl_urg_cnt', 'fl_ece_cnt',
              'fl_cwr_cnt', 'fl_10_p', 'fl_20_p', 'fl_30_p', 'fl_40_p', 'fl_50_p', 'fl_60_p', 'fl_70_p', 'fl_80_p',
              'fl_90_p', 'fl_duration',
              'fw_hdr_len', 'bw_hdr_len', 'down_up_ratio', 'fw_seg_avg', 'bw_seg_avg', 'fl_seg_cnt', 'conn_state',
              'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
              'diff_srv_rate', 'srv_diff_host_rate', 'srv_same_host_rate',
              'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
              'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
              'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
              ]
    csvdata = pd.DataFrame(columns=column, data=feature_list)
    csvdata.to_csv("output_2.csv", encoding='utf-8')


if __name__ == '__main__':
    parse_features()
