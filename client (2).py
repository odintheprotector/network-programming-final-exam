#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Media-Chat – Tk GUI client (broadcast + private DM)
"""
import os, socket, threading, hashlib, queue, tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from subprocess import run

HOST, PORT = '127.0.0.1', 5000
CACHE_DIR  = 'client_downloads'; os.makedirs(CACHE_DIR, exist_ok=True)

# ---------- helpers ----------
def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for ch in iter(lambda:f.read(4096),b''): h.update(ch)
    return h.hexdigest()

def open_media(p):
    try: run(['xdg-open',p],check=False)
    except FileNotFoundError: pass

def recv_line(sock):
    buf=b''
    while True:
        ch=sock.recv(1)
        if not ch or ch==b'\n': break
        buf+=ch
    return buf.decode(errors='ignore')

# ---------- GUI ----------
class Client(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Media Chat"); self.minsize(600,450)
        self.sock=None
        self.q=queue.Queue()

        self.chat=scrolledtext.ScrolledText(self,wrap='word',state='disabled')
        self.chat.pack(fill=tk.BOTH,expand=True,padx=4,pady=4)

        bar=ttk.Frame(self); bar.pack(fill=tk.X,padx=4,pady=4)
        self.e=ttk.Entry(bar); self.e.pack(side=tk.LEFT,fill=tk.X,expand=True)
        self.e.bind('<Return>',lambda _ : self.send_text())

        ttk.Button(bar,text='Send',command=self.send_text).pack(side=tk.LEFT,padx=2)
        ttk.Button(bar,text='Send File',command=self.send_file).pack(side=tk.LEFT,padx=2)
        ttk.Button(bar,text='Get File',command=self.get_file).pack(side=tk.LEFT,padx=2)
        ttk.Button(bar,text='Clear',command=self.clear_cache).pack(side=tk.LEFT,padx=2)
        ttk.Button(bar,text='Exit',command=self.on_exit).pack(side=tk.LEFT,padx=2)

        self.after(100,self.prompt_login); self.after(100,self.poll_q)

    # ---------- login ----------
    def prompt_login(self):
        w=tk.Toplevel(self); w.title("Login"); w.transient(self); w.grab_set()
        ttk.Label(w,text="User").grid(row=0,column=0,sticky='e',padx=4,pady=4)
        usr=tk.StringVar(); ttk.Entry(w,textvariable=usr).grid(row=0,column=1,padx=4,pady=4)
        ttk.Label(w,text="Pass").grid(row=1,column=0,sticky='e',padx=4,pady=4)
        pwd=tk.StringVar(); ttk.Entry(w,textvariable=pwd,show='*').grid(row=1,column=1,padx=4,pady=4)

        def go():
            try:
                self.sock=socket.socket()
                self.sock.connect((HOST,PORT))
                self.sock.sendall(f"{usr.get()}|{pwd.get()}\n".encode())
                self._append(recv_line(self.sock))
                threading.Thread(target=self.recv_loop,daemon=True).start()
                w.destroy()
            except Exception as e: messagebox.showerror("Error",e)
        ttk.Button(w,text="Connect",command=go).grid(row=2,column=0,columnspan=2,pady=6)
        w.bind('<Return>',lambda _ : go())

    # ---------- receive ----------
    def recv_loop(self):
        try:
            while True:
                h=recv_line(self.sock)
                if not h: break
                if h.startswith("FILE_TRANSFER"):
                    _,fname,size=h.split('|'); size=int(size)
                    path=os.path.join(CACHE_DIR,fname)
                    with open(path,'wb') as f:
                        remain=size
                        while remain:
                            ch=self.sock.recv(min(4096,remain))
                            if not ch: break
                            f.write(ch); remain-=len(ch)
                    self.sock.recv(1)  # '\n'
                    self.q.put(f"[+] downloaded → {path}")
                    open_media(path)
                else:
                    self.q.put(h)
        except Exception as e:
            self.q.put(f"[!] disconnected ({e})")

    # ---------- send ----------
    def send_text(self):
        if not self.sock: return
        raw=self.e.get().strip()
        if not raw: return
        # ---- detect private ----
        if raw.startswith('@') or raw.lower().startswith('/dm '):
            if raw.startswith('@'): split=raw[1:].split(' ',1)
            else:                   split=raw[4:].split(' ',1)
            if len(split)<2:
                messagebox.showwarning("DM","Nhập dạng @user nội_dung"); return
            to,msg=split
            self.sock.sendall(f"DM|{to}|{msg}\n".encode())
            self._append(f"[PM → {to}] {msg}")
        else:
            self.sock.sendall(f"TEXT|{raw}\n".encode())
            self._append(f"[Me] {raw}")
        self.e.delete(0,tk.END)

    def send_file(self):
        if not self.sock: return
        p=filedialog.askopenfilename(); 0
        if not p: return
        fname=os.path.basename(p); size=os.path.getsize(p); h=sha256(p)
        try:
            self.sock.sendall(f"FILE|{fname}|{size}|{h}\n".encode())
            with open(p,'rb') as f:
                for ch in iter(lambda:f.read(4096),b''): self.sock.sendall(ch)
            self.sock.sendall(b'\n')
            self._append(f"[Me] sent {fname} ({size} B)")
        except Exception as e: messagebox.showerror("File",e)

    def get_file(self):
        if not self.sock: return
        fname=simple_input(self,"Filename","File:")
        if fname: self.sock.sendall(f"GET_FILE|{fname}\n".encode())

    # ---------- misc ----------
    def clear_cache(self):
        for f in os.listdir(CACHE_DIR):
            try: os.remove(os.path.join(CACHE_DIR,f))
            except: pass
        self._append("[*] cache cleared")

    def poll_q(self):
        while not self.q.empty():
            line=self.q.get()
            if line.startswith("DM|"):
                # hiển thị đẹp hơn
                self._append(f"[PM] {line[3:]}")
            else:
                self._append(line)
        self.after(100,self.poll_q)

    def _append(self,txt):
        self.chat.config(state='normal')
        self.chat.insert(tk.END,txt+'\n'); self.chat.see(tk.END)
        self.chat.config(state='disabled')

    def on_exit(self):
        try:
            if self.sock: self.sock.close()
        finally: self.destroy()

def simple_input(root,title,prompt):
    w=tk.Toplevel(root); w.title(title); w.transient(root); w.grab_set()
    ttk.Label(w,text=prompt).pack(padx=8,pady=8)
    v=tk.StringVar(); ttk.Entry(w,textvariable=v).pack(padx=8,pady=4); v.set("")
    r=[None]
    ttk.Button(w,text="OK",command=lambda:(r.__setitem__(0,v.get().strip()),w.destroy())).pack(pady=6)
    w.bind('<Return>',lambda _:(r.__setitem__(0,v.get().strip()),w.destroy()))
    root.wait_window(w); return r[0]

# ---------- main ----------
if __name__=='__main__':
    Client().mainloop()
