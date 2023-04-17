import os,sys
def read_file(file_name):
    dic_session={}
    with open('./five_tuples/'+file_name,'r') as f:
        for line in f:
            temp=line.split(',')
            pro=temp[2]
            src=temp[3]
            dst=temp[4]
            sport=temp[5]
            dport=temp[6]
            key1=str(pro)+"_"+str(src)+"_"+str(sport)+"_"+str(dst)+"_"+str(dport)
            key2=str(pro)+"_"+str(dst)+"_"+str(dport)+"_"+str(src)+"_"+str(sport)
            if key1 not in dic_session and key2 not in dic_session:
                dic_session[key1]=[]
                dic_session[key1].append(line)
            else:
                if key1 in dic_session:
                    dic_session[key1].append(line)
                else:
                    dic_session[key2].append(line)
        for key in dic_session:
            file=open("./session/"+file_name+"_"+key+".csv","w")
            for line in dic_session[key]:
                file.write(line)
            file.close()
filelist=os.listdir('./five_tuples/')
for file in filelist:
    if "csv" in file:
        read_file(file)


