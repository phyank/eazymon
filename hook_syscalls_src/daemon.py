import socket,struct,time,json

try:
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,25)
    sock.bind((0,-1))
except IOError:
    print("Kernel module not ready!")
    exit(-1)
#sock.send(<nlmsghdr>)
logf=open('syscalls.log','a')
while True:
        try:
            msg=sock.recv(8192000)
        except:
            continue
        msg=msg[16:]
        js=msg[48:]
        li=struct.unpack('<qqIiiiiiq',msg[:48])
        #o=''
        #for i in list:
        #    o+=("%x"%(256+i if i<0 else i))
        #    o+=" "
        info=""
        info+="#####################"
        info+="time:%s"%time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(li[0]))+"\n"
        info+="pid:%d"%li[3]+"\n"
        info+="tgid:%d"%li[4]+"\n"
        info+="uid:%d"%li[5]+"\n"
        info+="euid:%d"%li[6]+"\n"
        info+="syscallNumber:%d"%li[7]+"\n"
        info+="return:%d"%li[8]+"\n"
        js=js[:(li[2]-48-1)]
        #info+=js)
        #info+=len(js))
        try:
            d=json.loads(js)
        except:
            info+="invalid data."+"\n"
        else:
            if "process_name" in d:
                if d['process_name']=='systemd-journal':
                    continue
            info+="JSON message:"+"\n"
            for key in d:
                info+=key+":"+d[key]+"\n"
        
        logf.write(info)

