import pandas as pd
import numpy as np


def gen_in_list(list, low, top):
    ret_list = []
    for i in list:
        if i > low and i < top:
            ret_list.append(i)
    return ret_list


def parse_features():
    lines = pd.read_csv('output.csv', sep=',', encoding='utf-8').iloc[:, [1, 4, 7, 8, 9, 30, 31, 32, 53, 54, 55]]
    # expand five tuple data from filename string
    five_tuple_data = lines['file'].str.split('_', expand=True)
    five_tuple_data_column = ['origin_file', 'proto_1', 'ip.src', 'port.src', 'ip.dst', 'port.dst']

    # get total data and columns
    data = np.hstack((five_tuple_data.values, lines.values))
    column = list(five_tuple_data_column) + list(lines.columns)
    # print(column)
    # print(data)
    total_dict = {}
    for line in data:
        key = line[2] + ";" + line[4] + ":" + line[5] + ";" + line[1]

        if key not in total_dict.keys():
            total_dict[key] = [line]
        else:
            total_dict[key].append(line)
    feature_list = []
    for key in total_dict:
        ip_src = line[2]
        ip_dst = line[4]
        port_dst = line[5]
        proto = line[1]

        # print("key: ",total_dict[key])
        group = total_dict[key]
        timestamp_list = []
        c_sum_list = []
        c_pkt_sum_list = []
        c_duration_list = []
        s_sum_list = []
        s_pkt_sum_list = []
        s_duration_list = []
        t_sum_list = []
        t_pkt_sum_list = []
        t_duration_list = []
        for i in group:
            timestamp_list.append(i[7])
            c_sum_list.append(i[8])
            c_pkt_sum_list.append(i[9])
            c_duration_list.append(i[10])
            s_sum_list.append(i[11])
            s_pkt_sum_list.append(i[12])
            s_duration_list.append(i[13])
            t_sum_list.append(i[14])
            t_pkt_sum_list.append(i[15])
            t_duration_list.append(i[16])

        c_duration_avg = np.mean(c_duration_list) if len(c_duration_list) > 0 else 0
        c_duration_std = np.std(c_duration_list, ddof=1) if len(c_duration_list) > 0 else 0
        s_duration_avg = np.mean(s_duration_list) if len(s_duration_list) > 0 else 0
        s_duration_std = np.std(s_duration_list, ddof=1) if len(s_duration_list) > 0 else 0
        t_duration_avg = np.mean(t_duration_list) if len(t_duration_list) > 0 else 0
        t_duration_std = np.std(t_duration_list, ddof=1) if len(t_duration_list) > 0 else 0

        timestamp_list.sort()
        interval_list = []
        for i in range(len(timestamp_list) - 1):
            interval_list.append(timestamp_list[i + 1] - timestamp_list[i])
        # interval_list.sort(reverse=True)

        period_list = []
        for i in range(len(interval_list) - 1):
            period_list.append(abs(interval_list[i + 1] - interval_list[i]))
        period_avg = np.mean(period_list) if len(period_list) > 0 else 0
        period_std = np.std(period_list, ddof=1) if len(period_list) > 0 else 0

        c_payload_sum = np.sum(c_sum_list) if len(c_sum_list) > 0 else 0
        s_payload_sum = np.sum(s_sum_list) if len(s_sum_list) > 0 else 0
        t_payload_sum = np.sum(t_sum_list) if len(t_sum_list) > 0 else 0
        c_pkt_sum = np.sum(c_pkt_sum_list) if len(c_pkt_sum_list) > 0 else 0
        s_pkt_sum = np.sum(s_pkt_sum_list) if len(s_pkt_sum_list) > 0 else 0
        t_pkt_sum = np.sum(t_pkt_sum_list) if len(t_pkt_sum_list) > 0 else 0

        c_payload_avg = np.mean(c_sum_list) if len(c_sum_list) > 0 else 0
        c_payload_std = np.std(c_sum_list, ddof=1) if len(c_sum_list) > 0 else 0
        c_in_cnt = gen_in_list(c_sum_list, c_payload_avg - c_payload_std, c_payload_avg + c_payload_std)
        c_in_per = len(c_in_cnt) / len(c_sum_list) if len(c_sum_list) > 0 else 0

        s_payload_avg = np.mean(s_sum_list) if len(s_sum_list) > 0 else 0
        s_payload_std = np.std(s_sum_list, ddof=1) if len(s_sum_list) > 0 else 0
        s_in_cnt = gen_in_list(s_sum_list, s_payload_avg - s_payload_std, s_payload_avg + s_payload_std)
        s_in_per = len(s_in_cnt) / len(s_sum_list) if len(s_sum_list) > 0 else 0

        t_payload_avg = np.mean(t_sum_list) if len(t_sum_list) > 0 else 0
        t_payload_std = np.std(t_sum_list, ddof=1) if len(t_sum_list) > 0 else 0
        t_in_cnt = gen_in_list(t_sum_list, t_payload_avg - t_payload_std, t_payload_avg + t_payload_std)
        t_in_per = len(t_in_cnt) / len(t_sum_list) if len(t_sum_list) > 0 else 0

        new_line = [ip_src, ip_dst, port_dst, proto, period_avg, period_std,
                    c_duration_avg, c_duration_std, c_payload_sum, c_payload_avg, c_payload_std, c_pkt_sum, c_in_per,
                    s_duration_avg, s_duration_std, s_payload_sum, s_payload_avg, s_payload_std, s_pkt_sum, s_in_per,
                    t_duration_avg, t_duration_std, t_payload_sum, t_payload_avg, t_payload_std, t_pkt_sum, t_in_per]
        feature_list.append(new_line)
    column = ['ip_src', 'ip_dst', 'port_dst', 'proto', 'period_avg', 'period_std',
              'c_duration_avg', 'c_duration_std', 'c_payload_sum', 'c_payload_avg', 'c_payload_std', 'c_pkt_sum',
              'c_in_per',
              's_duration_avg', 's_duration_std', 's_payload_sum', 's_payload_avg', 's_payload_std', 's_pkt_sum',
              's_in_per',
              't_duration_avg', 't_duration_std', 't_payload_sum', 't_payload_avg', 't_payload_std', 't_pkt_sum',
              't_in_per']
    csvdata = pd.DataFrame(columns=column, data=feature_list)
    csvdata.to_csv("output_3.csv", encoding='utf-8')


if __name__ == '__main__':
    parse_features()
