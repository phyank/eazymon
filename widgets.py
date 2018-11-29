from definition import *
from tkinter import *
from tkinter import ttk
from tkinter.messagebox import *
from binascii import hexlify
import os,json,time,traceback
from threads import *



class ScrolledList(Frame):
    def __init__(self, db, stext, options, mutex, parent,fliter):
        Frame.__init__(self, parent)
        self.pack(side=LEFT, fill=BOTH)
        self.pos = 0
        self.db = db
        self.stext = stext
        # self.stext2 = stext2
        # self.stextph = stextph
        self.mutex = mutex
        self.fliter=fliter
        self.makeWidgets(options)



    def handlelist(self, e):
        index = self.listbox.curselection()
        # label=self.listbox.get(index)
        try:
            self.runCommand(index[0])
        except IndexError:
            pass

    def clean(self):
        self.listbox.delete(0,END)

    def makeWidgets(self, options):
        sbar = Scrollbar(self)
        list = Listbox(self, width=70, relief=SUNKEN)
        sbar.config(command=list.yview)
        list.config(yscrollcommand=sbar.set)
        sbar.pack(side=RIGHT, fill=Y)
        list.pack(side=LEFT, fill=BOTH)

        list.bind('<ButtonRelease-1>', self.handlelist)
        self.listbox = list

    def runCommand(self, selection):
        try:
            p=self.db.get(selection)
            self.stext.advancedsettext(1, p)
        except Exception as e:
            print(traceback.format_exc())
            print(e.args)
            print("Index Out of Range")

    def list_label(self,p):
        o=""
        if p.syscall_index==SYSCALL_INDEX_X64['read']:
            o+="SYSCALL read() by process:%s"%p.pname
            o+=", %d bytes from fd %d"%(p.bytes,p.fd)
        elif p.syscall_index==SYSCALL_INDEX_X64['mkdir']:
            o += "SYSCALL mkdir()"
            o += ", user:%d, path:%s" % (p.uid, p.path)

        return o

        # if p[PCAP_ETH_PROTO]==0x0800:
        #     if p[PCAP_PROTO]==PROTO_ICMP:
        #         return parseproto(p[PCAP_PROTO]) +" type"+interpret_icmp(p[PCAP_PROTO_OPT][0])+ " from " + str(p[PCAP_SRC_IP])  + " to " + str(p[PCAP_DST_IP])
        #     else:
        #         if p[PCAP_SRC_PORT]==UNDEFINED:
        #             return parseproto(p[PCAP_PROTO]) + " Damaged "+" from " + str(p[PCAP_SRC_IP])  + " to " + str(p[PCAP_DST_IP])
        #         else:
        #             return parseproto(p[PCAP_PROTO]) + " from " + str(p[PCAP_SRC_IP]) + ":" + str(p[PCAP_SRC_PORT]) + " to " + str(
        #                 p[PCAP_DST_IP]) + ":" + str(p[PCAP_DST_PORT])
        # elif p[PCAP_ETH_PROTO]==0x0806:
        #     if p[PCAP_PROTO_OPT]!=UNDEFINED:
        #         if p[PCAP_PROTO_OPT][8]==UNDEFINED:
        #             return 'ARP gratuitous from '+str(p[PCAP_PROTO_OPT][6])
        #         else:
        #             return 'ARP from '+str(p[PCAP_PROTO_OPT][6])+' '+('asking for' if p[PCAP_PROTO_OPT][4]==1 else 'response of')+' '+str(p[PCAP_PROTO_OPT][8])
        #     else:
        #         return 'ARP Damaged?'
        # elif p[PCAP_ETH_PROTO]==0x8035:
        #     if p[PCAP_PROTO_OPT]!=UNDEFINED:
        #         return 'RARP from '+mac_formater(p[PCAP_PROTO_OPT][5])+' '+('asking for' if p[PCAP_PROTO_OPT][4]==3 else 'response of')+' '+str(p[PCAP_PROTO_OPT][7])
        #     else:
        #         return 'RARP Damaged?'



    def list_insert(self, eid,p):
        self.listbox.insert(eid, self.list_label(p))

class ScrolledText(Frame):
    def __init__(self, parent=None, width=32, text='', file=None):
        Frame.__init__(self, parent)
        self.pack(side=LEFT, fill=BOTH)
        self.width = width
        self.makewidgets()
        self.settext(text, file)
        self.textbytes=b''

    def makewidgets(self):
        tsbar = Scrollbar(self)
        if self.width:
            text = Text(self, width=self.width, relief=SUNKEN)
        else:
            text = Text(self, relief=SUNKEN)
        tsbar.config(command=text.yview)
        text.config(yscrollcommand=tsbar.set)
        tsbar.pack(side=RIGHT, fill=Y)
        text.pack(side=LEFT, expand=YES, fill=BOTH)

        self.text = text

    def settext(self, text='', file=None):
        if file:
            text = open(file, 'r').read()
        self.text.delete('1.0', END)
        self.text.insert('1.0', text)

    def gettext(self):
        return self.text.get('1.0', END + '-1c')

    def advancedsettext(self,n,p):
        info = ""
        info += "time:%s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.time)) + "\n"
        info += "pid:%d" % p.pid + "\n"
        info += "tgid:%d" % p.tgid + "\n"
        info += "uid:%d" % p.uid + "\n"
        info += "euid:%d" % p.euid + "\n"
        info += "syscallNumber:%d" % p.syscall_index + "\n"
        info += "return:%d" % p.ret + "\n"
        js = p.js
        try:
            d = js
        except:
            info += "invalid data." + "\n"
        else:
            info += "JSON message:" + "\n"
            for key in d:
                info += str(key) + ":" + str(d[key]) + "\n"
        self.text.delete('1.0', END)
        self.text.insert('1.0', info)


class StartBox:
    def __init__(self, db, parent,mainStatus,mode=FIRST_START):

        self.mode=mode

        self.mainStatus=mainStatus

        self.parent = parent
        self.db = db
        self.top = Toplevel()

        self.top.title('Settings')
        self.top.resizable(0, 0)

        self.fuid = LabelFrame(self.top, text="用户黑名单")
        self.fpr = LabelFrame(self.top, text="进程黑名单")

        self.fn = LabelFrame(self.top, text="监控目标")

        self.f3 = Frame(self.top)

        self.fn.pack(side=TOP,fill=BOTH)

        self.fuid.pack(side=TOP, fill=BOTH)
        self.fpr.pack(side=TOP, fill=BOTH)
        self.f3.pack(side=BOTTOM, fill=BOTH)

        self.u_not_accepted=StringVar()
        self.pr_not_accepted=StringVar()

        Entry(self.fuid, textvariable=self.u_not_accepted).grid(columnspan=2,row=0)

        Entry(self.fpr, textvariable=self.pr_not_accepted).grid(columnspan=2,row=1)


        # devicelist.bind("<<ComboboxSelected>>", notdone)
        self.syscall_vars={0:IntVar(self.top),83:IntVar(self.top)}

        self.p0 = Checkbutton(self.fn, text='read()', variable=self.syscall_vars[0])
        self.p83 = Checkbutton(self.fn, text='mkdir()', variable=self.syscall_vars[83])


        self.p0.pack(side=LEFT)
        self.p83.pack(side=LEFT)


        Button(self.f3, text='OK', command=self.config_finish).pack(
            side=LEFT)
        Button(self.f3, text='Cancel', command=self.config_quit).pack(side=RIGHT)

    def config_quit(self):
        self.top.destroy()
        if self.mode==FIRST_START:
            self.parent.destroy()

    def config_finish(self):
        idPattern=r"(\d+;)*\d+(;)?"

        nacPr=self.pr_not_accepted.get()
        nacPid=""
        nacPn=""

        accSyscalls=""
        for s in nacPr.split(","):
            try:
                nacPid+=str(int(s))+";"
            except ValueError:
                nacPn+=s+";"

        nacUid=";".join(self.u_not_accepted.get().split(","))

        for i in self.syscall_vars:
            v=self.syscall_vars[i].get()
            if v:
                accSyscalls+=str(i)+";"

        if nacPid and not re.match(idPattern,nacPid):
            showerror("Error","无效的pid!")
            return

        if nacUid and not re.match(idPattern, nacUid):
            showerror("Error", "无效的uid!")
            return

        if not accSyscalls:
            showerror("Error", "至少选择一种syscall！")
            return

        self.mainStatus.accept_syscalls_config=accSyscalls
        self.mainStatus.ignore_process_names=nacPn
        self.mainStatus.ignore_uids=nacUid
        self.mainStatus.ignore_pids=nacPid

        self.mainStatus.init=True

        if self.mode==FIRST_START:
            self.parent.update()
            self.parent.deiconify()

        self.top.destroy()



