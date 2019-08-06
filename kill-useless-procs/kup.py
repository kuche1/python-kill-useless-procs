

import hashlib
from pathlib import Path
import psutil
from threading import Thread
from time import sleep



def thr(f,*a):
    Thread(target=f,args=a).start()

def readdata(d):
    f = open(d,'rb')
    data = f.read()
    f.close()
    data = data.split(b'\n')
    while b'' in data:
        data.remove(b'')
    return data


class Scan:
    def __init__(s):
        s.whitelist = readdata('whitelist.txt')
        s.blacklist = readdata('blacklist.txt')
        
        s.unknown = []
        s.unknown_data = []

    def start(s):
        s.running = True
        s.finished = False

        thr(s.scanning_thread)
    
    def stop(s):
        s.running = False
        while not s.finished:
            sleep(0.1)

    def scanning_thread(s):
        while s.running:
            for p in psutil.process_iter():
                
                try:
                    exe = p.exe()
                except (psutil.AccessDenied,OSError):
                    continue

                try:
                    f = open(exe,'rb')
                except FileNotFoundError:
                    continue
                data = f.read()
                f.close()
                
                h = hashlib.sha256()
                h.update(data)
                h = h.digest()

                if h in s.blacklist:
                    p.terminate()
                elif h in s.whitelist:
                    pass
                elif h not in s.unknown:
                    s.unknown.append(h)
                    s.unknown_data.append((p.name(),exe))

            sleep(1)

        s.finished = True
    

scan = Scan()





scan.start()


ind = 0
while True:

    try:
        while ind < len(scan.unknown):
            data = scan.unknown_data[ind]
            print(f'{ind}/{data}')
            ind += 1

        sleep(1)

    except KeyboardInterrupt:
        c = input('>')
        try:
            c = int(c)
        except ValueError:
            input('Invalid choice.')
        else:
            if c < 0 or c > ind:
                input('Invalid chouce.')
            else:
                m = input('(w)hitelist / (b)lacklist: ')
                if m == 'w':
                    f = open('whitelist.txt','ab')
                    f.write(scan.unknown[c])
                    f.write(b'\n')
                    f.close()

                    scan.whitelist.append(scan.unknown[c])
                    del scan.unknown_data[c]
                    del scan.unknown[c]

                elif m == 'b':
                    f = open('blacklist.txt','ab')
                    f.write(scan.unknown[c])
                    f.write(b'\n')
                    f.close()

                    scan.blacklist.append(scan.unknown[c])
                    del scan.unknown_data[c]
                    del scan.unknown[c]

                else:
                    input('Invalid mode.')

        ind = 0
                    
        

scan.stop()

