## 环境

* ubuntu-16.04.7
* tshark-3.x
* python 3.10



## 结构

```shell
├── raw_data 			:pcap文件夹
├── fields				:中间文件文件夹
│   ├── certificates 	:证书数据文件夹
│   ├── pre_fields		:单值字段信息文件夹
│   └── sni_lists 		:SNI数据文件夹
├── five_tuples 		:单值、多值字段连接生成文件(初始字段)文件夹
├── session 			:流文件夹
├── ip-tshark.py 		:提取pcap初始字段
├── split-session.py 	:划分为五元组流
├── gen_features.py 	:从五元组流提取初始字段
├── gen_features_2.py 	:提取五元组特征
├── gen_features_3.py 	:提取四元组特征
├── output.csv 			:gen_features.py输出文件
├── output_2.csv 		:gen_features_2.py输出文件
├── output_3.csv 		:gen_features_3.py输出文件
└── README.md
```

