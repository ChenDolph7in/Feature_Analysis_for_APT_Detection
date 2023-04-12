import OpenSSL
import time
from dateutil import parser

def fields_test():
    for j in range(1):
        '''
                多值字段连接
        '''
        print("j: ", j);
        pre_field = open("./fields/pre_fields/" + str(j) + ".csv", 'r')
        certificate = open("./fields/certificates/" + str(j) + ".csv", 'r')
        sni_list = open("./fields/sni_lists/" + str(j) + ".csv", 'r')
        five_tuple = open("./five_tuples/" + str(j) + ".csv", 'w')
        while True:
            l1 = pre_field.readline()
            l2 = certificate.readline()
            l3 = sni_list.readline()
            print(l1)
            if not l1:
                pre_field.close()
                certificate.close()
                sni_list.close()
                five_tuple.close()
                break
            d1 = l1[:-1].split(',')
            d2 = l2[:-1].split(',')[9:]
            d3 = l3[:-1].split(',')[9:]
            print(d1)
            print(d2)
            print(d3)
            print(','.join(d1 + [';'.join(d2)] + [';'.join(d3)]))
            five_tuple.write(','.join(d1 + [';'.join(d2)] + [';'.join(d3)]) + "\n")


def openssl_test():
    # bin_x509 = open("./test1.cer", encoding='utf8', mode='r')
    # x509_data = bin_x509.read()
    x509_data = "3082064d30820535a003020102021100d562e1239af50f88ee4ab924a6f3a254300d06092a864886f70d01010b0500308190310b3009060355040613024742311b30190603550408131247726561746572204d616e636865737465723110300e0603550407130753616c666f7264311a3018060355040a1311434f4d4f444f204341204c696d69746564313630340603550403132d434f4d4f444f2052534120446f6d61696e2056616c69646174696f6e2053656375726520536572766572204341301e170d3137303530313030303030305a170d3139303530313233353935395a305a3121301f060355040b1318446f6d61696e20436f6e74726f6c2056616c696461746564311e301c060355040b1315457373656e7469616c53534c2057696c64636172643115301306035504030c0c2a2e6f6e696f6e2e6c696e6b30820222300d06092a864886f70d01010105000382020f003082020a0282020100b03731aa0e5ed01484d94079a89efc4d2b4bd3d0c9172ef1364e17532fedb159ddfc04636ea9b6a0db8fa3946bfcf0f94fbf6970ed5111997f94653e83d6eec96d794a71b7c7ff9cdbeb63610a42c77774433ac5399d9b60193934ee1fc0c76c9c377a4109e663f89027f887dc5cacb797b8136ba906a06817688d7faad413358d24c7fb8196f518d995294ce77c046c9c3e1576eb17e91572b6670d21238af2dde190f5b266700e513832d45be4d43a73c818430167ae8bef5d91d61c426c65e51f7651eb2c0dddcdea2a3d4d503ebb6ad51970dfc6655f375cc78694f4d23c68ee02b18071ae2643a5645cd1c792fba4376462e3eda295ffffe56c1c04abeede539b142e3c7d08be20b36304f268ae4fe91016b9f8a878fa86fe46564c27de054f8fcd8b660a67eca84d7d3c3c89593fa8bf4b6dd74ce58dbb71845a60e9eb4703abf9ee15f2f02c963c22e304d2565f62a15ba7b80c895853230d63582e2d508a887db3d2c02529491e4b2a99226f792ff7eeb1e5054f9041c4b9d237820724dd873f14e21e4052d5b686f3249b4a0b66acaca421d96efd72a9b80a0494d76a2ac1b0baa26bb81a94b13cd980a5c8f08ccd282e8c5c494f75e80bd794fb636e9277ff5dac5d38044af7113a333c3a3ea96341c5f345526362c43bd61431a3cdc7d185aba5a088a2614fc3dd663eef4b790aa3fadf366ccdca2d1e8461bc950203010001a38201d5308201d1301f0603551d2304183016801490af6a3a945a0bd890ea125673df43b43a28dae7301d0603551d0e041604140840eb965809cab9e8ceefefec4ebb9a2aa3ac89300e0603551d0f0101ff0404030205a0300c0603551d130101ff04023000301d0603551d250416301406082b0601050507030106082b06010505070302304f0603551d2004483046303a060b2b06010401b23101020207302b302906082b06010505070201161d68747470733a2f2f7365637572652e636f6d6f646f2e636f6d2f4350533008060667810c01020130540603551d1f044d304b3049a047a0458643687474703a2f2f63726c2e636f6d6f646f63612e636f6d2f434f4d4f444f525341446f6d61696e56616c69646174696f6e53656375726553657276657243412e63726c30818506082b0601050507010104793077304f06082b060105050730028643687474703a2f2f6372742e636f6d6f646f63612e636f6d2f434f4d4f444f525341446f6d61696e56616c69646174696f6e53656375726553657276657243412e637274302406082b060105050730018618687474703a2f2f6f6373702e636f6d6f646f63612e636f6d30230603551d11041c301a820c2a2e6f6e696f6e2e6c696e6b820a6f6e696f6e2e6c696e6b300d06092a864886f70d01010b050003820101008592c43a09c011bf721b7b22688913d43ce5f957880083122e9b46fd6e3a2ad4fc6295806051cb74a81de534bdc7a4fa3d9b916ebf559846784122e360460e1af5646666cbe71f83932f53e5656e468fbfc7d5159851de1130dac3dac928f803e1122cd5509e0bad328357cf30194af9c070433de267cbfbe70360c2361c55fadd3c500afd910e20267438f4d3998d82d8b7660a1502771ab2d3eea6e22186a53b040b55f344888feb2d5373e378be633aee57aaa805dd19c34c9198261085f1224685e5e320653202cef1565e2afc4ea5dbb2a863da4c8bd27e072d45509e54bc4a79ac6217a3a931892485bc14b3ad06e25b46b9cd680aabba3f08db9e6acd"
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes.fromhex(x509_data))
    certIssue = cert.get_issuer()

    print("cert_extention_count : ", cert.get_extension_count())

    for i in range(cert.get_extension_count()):
        ex = cert.get_extension(i)
        print("ex ",i,": ")
        print("shor_name: ",ex.get_short_name())
        # print(str(ex))
        print(ex.get_critical())
        print(ex.get_data())

    print(parser.parse(cert.get_notAfter().decode("utf-8")))
    print(parser.parse(cert.get_notBefore().decode("utf-8")))

    # print(certIssue.get_extention)

    print("证书版本:            ", cert.get_version() + 1)

    print("证书序列号:          ", hex(cert.get_serial_number()))

    print("证书中使用的签名算法: ", cert.get_signature_algorithm().decode("UTF-8"))

    print("颁发者:              ", certIssue.commonName)

    # datetime_struct = parser.parse(cert.get_notBefore().decode("UTF-8"))
    #
    # print("有效期从:             ", datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))
    #
    # datetime_struct = parser.parse(cert.get_notAfter().decode("UTF-8"))
    #
    # print("到:                   ", datetime_struct.strftime('%Y-%m-%d %H:%M:%S'))

    print("证书是否已经过期:      ", cert.has_expired())

    print("公钥长度", cert.get_pubkey().bits())

    # print("公钥:\n", OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8"))

    print("主体信息:")

    print("CN : 通用名称  OU : 机构单元名称")
    print("O  : 机构名    L  : 地理位置")
    print("S  : 州/省名   C  : 国名")

    for item in certIssue.get_components():
        print(item[0].decode("utf-8"), "  ——  ", item[1].decode("utf-8"))

    print(cert.get_extension_count())


def tcp_flags_test():
    a = '0x03'
    # b_flags = bytes.fromhex(flags[2:])
    # print(b_flags)
    # a = flags[2:]
    a = int(a, 16)  # 先把16进制转10进制
    a = bin(a)
    print(a)
    for i in range(len(a)-2):
        print(a[len(a)-1-i])
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # openssl_test()
    tcp_flags_test()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
