from tkinter import *
from tkinter import ttk
from tkinter.messagebox import *
from tkinter.filedialog import *
from pickle import *
from binascii import hexlify,b2a_hex
import threading
import socket, sys
from struct import *
import queue
from time import sleep
import os
import re
import json,time
from io import StringIO

from definition import *
from widgets import *
from threads import *

if os.name=='nt':
    print("This program can only be run on Linux with root priviledge")
    sys.exit(1)

def notdone():
    showinfo("Info","Under construction!")


def quit():
    db.quit = True
    sys.exit()


def startcapture(filter):
    db.clean()
    slist.clean()
    filter.ignore_pids=set(map(lambda x:int(x) if x else "N", mainStatus.ignore_pids.split(";")))
    filter.ignore_uids=set(map(lambda x:int(x) if x else "N", mainStatus.ignore_uids.split(";")))
    filter.ignore_process_names=set(map(lambda x:x if x else 0, mainStatus.ignore_process_names.split(";")))
    filter.accept_syscalls=set(map(lambda x:int(x) if x else "N", mainStatus.accept_syscalls_config.split(";")))

def stopcapture(filter):
    filter.accept_syscalls.clear()

def storepackage(db,slist):

    while True:
        src=asksaveasfilename(defaultextension='.mycap',filetypes =[('MyCap File','.mycap')],initialdir ='~\\')
        try:
            file=open(src,'wb')
            dump(db.pcap,file)
            file.close()
            break
        except:
            if askyesno('Saving Failed','Failed to save file,continue to save?'):
                pass
            else:
                break

def loadpackage(fliter,db,slist):
    if filter.accept_syscalls:
        answer = askyesno("info", "Stop current process without saving?")
        if answer:
            stopcapture(filter)
            db.clean()
            slist.clean()
        else:
            return


    while True:
        try:
            src=askopenfilename(defaultextension='.mycap',filetypes =[('MyCap File','.mycap')],initialdir ='~\\')
            file=open(src,'rb')
            obj=load(file)

            for p in obj:
                slist.list_insert(db.add(p),p)

            break
        except:
            r=askyesno('Loading Failed','Failed to load file,continue to load?')
            if r:
                continue
            else:
                break

def changefilter(db,parent,mainStatus):
     StartBox(db,parent,mainStatus,mode=LOAD_FILE)

def savecurrentraw(stext):
    notdone()

def full_quit(root,pcap):
    mainStatus.quit_signal=True
    root.destroy()

def on_closing():
    if askokcancel("Quit", "Do you want to quit?"):
        mainStatus.quit_signal=True
        root.destroy()


class MainStatus:
    def __init__(self):
        self.init=False
        self.quit_signal=False
        self.accept_syscalls_config=""
        self.ignore_process_names=""
        self.ignore_pids=""
        self.ignore_uids=""

# if "access control disabled" not in os.popen('xhost +').read():
#     print("Disable access control failed. Quit.")
#     exit(-1)

mainStatus=MainStatus()
filter=Filter()

root = Tk()
root.title(MAIN_TITLE)
root.protocol("WM_DELETE_WINDOW", on_closing)
options = []

db = Database()
topframe = Frame(root)
bottomframe = LabelFrame(root, text='Data')


topframe.pack(side=LEFT, fill=BOTH)
bottomframe.pack(side=RIGHT, fill=BOTH)

stext = ScrolledText(bottomframe)

slist = ScrolledList(db, stext, options, mutex, topframe,None)

tpMnu = Menu(root)
root.config(menu=tpMnu)
file = Menu(tpMnu)
file.add_command(label="Open mycap File", command=(lambda:loadpackage(filter,db,slist)), underline=0)
file.add_command(label="Save All Captured Packages", command=(lambda:storepackage(db,slist)), underline=0)
file.add_command(label="Save Current RAW Data", command=(lambda:savecurrentraw(stext)), underline=0)
#file.add_command(label="Interpret Current RAW Data", command=notdone, underline=0)
file.add_command(label="Quit", command=(lambda: full_quit(root,db)), underline=0)
tpMnu.add_cascade(label='File', menu=file, underline=0)

controller = Menu(tpMnu)
controller.add_command(label="Filter", command=(lambda: changefilter(db,root,mainStatus)), underline=0)
controller.add_command(label="Start Cap", command=(lambda: startcapture(filter)), underline=0)
controller.add_command(label="Stop Cap", command=(lambda: stopcapture(filter)), underline=0)
tpMnu.add_cascade(label='Control', menu=controller, underline=0)

about = Menu(tpMnu)
about.add_command(label="About",command=(lambda:showinfo('About',"EazyMon\nVersion : 0.1\nAuthor : phyank \nEmail : hbyyeah@qq.com\n")))
tpMnu.add_cascade(label='About', menu=about, underline=0)


cap2refresh=queue.Queue()


capThread=CapThread(cap2refresh,mainStatus)

reThread=RefreshThread(cap2refresh,mainStatus,db,slist,filter)


capThread.start()

reThread.start()

root.resizable(0, 0)
root.withdraw()

StartBox(db,root,mainStatus,mode=FIRST_START)

root.mainloop()
