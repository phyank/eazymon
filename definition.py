from io import StringIO
import re,queue,threading,time

MAIN_TITLE='EazyMon syscall monitor'


SYSCALL_INDEX_X64={
    'read':0,
    'mkdir':83
}


FIRST_START=0
LOAD_FILE=1


UNDEFINED=-1



mutex = threading.Lock()


class Record:
    def __init__(self):
        self.syscall_index=None
        self.time=time.time()
        self.pid=None
        self.tgid=None
        self.uid=None
        self.euid=None
        self.ret=None
        self.js=None

class Database:
    def __init__(self):
        self.pcap = []
        self.counter = UNDEFINED

#
    def add(self, d):
        self.pcap.append(d)
        self.counter += 1
        return self.counter

    def get(self,eid):
        return self.pcap[eid]

    def clean(self):
        self.pcap = []
        self.counter = UNDEFINED


class Filter:
    def __init__(self):
        self.ignore_process_names=set()
        self.ignore_pids=set()
        self.ignore_uids=set()
        self.accept_syscalls=set()

    def filter_pass(self,p):
        if p.syscall_index not in self.accept_syscalls:
            return False
        else:
            try:
                if p.uid in self.ignore_uids:
                    return False
                else:
                    pass
            except AttributeError:
                pass

            try:
                if p.pname in self.ignore_process_names:
                    return False
                else:
                    pass
            except AttributeError:
                pass

            try:
                if p.pid in self.ignore_pids:
                    return False
                else:
                    pass
            except AttributeError:
                pass


            return True

