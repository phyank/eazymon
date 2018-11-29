from definition import *
import threading,socket,struct,json
from struct import *
from binascii import hexlify
from time import sleep
import traceback,os

class CapThread(threading.Thread):
    def __init__(self,outQueue,mainStatus):
        threading.Thread.__init__(self)
        self.outQueue=outQueue
        self.mainStatus=mainStatus

    def run(self):
        try:
            if os.system('insmod hook_syscalls.ko')==0:
                print("insmod success")
            else:
                print("insmod failed")
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 25)
            self.sock.bind((0, -1))
            self.sock.settimeout(1)
        except IOError:
            print("Kernel module not ready!")

        else:
            while True:
                if self.mainStatus.quit_signal:
                    self.sock.close()
                    r = os.system('rmmod hook_syscalls.ko')
                    print("rmmod result:%d." % r)
                    break
                try:
                    msg = self.sock.recv(8192000)
                except:
                    continue
                else:
                    self.outQueue.put(msg)
        print("CapThread Quit.")
        return


class RefreshThread(threading.Thread):
    def __init__(self,inQueue,mainStatus,db,slist,filter):
        threading.Thread.__init__(self)
        self.inQueue=inQueue
        self.mainStatus=mainStatus
        self.db=db
        self.slist=slist
        self.filter=filter

    def run(self):
        while True:
            if self.mainStatus.quit_signal:
                break
            try:
                msg=self.inQueue.get(timeout=0.5)
            except queue.Empty:
                continue
            else:
                msg = msg[16:]
                l = struct.unpack('<qqIiiiiiq', msg[:48])

                p = Record()

                p.syscall_index = int(l[7])
                p.pid = int(l[3])
                p.tgid = int(l[4])
                p.uid = int(l[5])
                p.euid = int(l[6])
                p.ret = int(l[8])

                jsonSrc = msg[48:][:(l[2] - 48 - 1)]
                try:
                    p.js = json.loads(jsonSrc)
                except:
                    p.js = {"Error": "Invalid JSON",
                            "Inv":jsonSrc.decode('ascii','ignore'),
                            "trb":traceback.format_exc(),
                            'process_name':"Process %d"%p.tgid,
                            'read_bytes':-1,
                            'from_fd':-1,
                            'full_name':'N/A',
                            'dir_name':'N/A'}



                if p.syscall_index == SYSCALL_INDEX_X64['read']:
                    p.pname = p.js['process_name']
                    p.bytes = int(p.js['read_bytes'])
                    p.fd=int(p.js['from_fd']) if p.js['from_fd']!='' else -1024
                elif p.syscall_index == SYSCALL_INDEX_X64['mkdir']:
                    p.path=str(p.js['full_name'])
                    p.dir=str(p.js['dir_name'])

                if self.filter.filter_pass(p):
                    eid=self.db.add(p)
                    self.slist.list_insert(eid,p)

        print("Refresh thread quit.")
        return
