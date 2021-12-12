from scapy.all import *
from scapy.layers.inet import IP
import threading
import eel
from queue import Queue
from pathlib import Path

secret_TOS = 0xD  # flag marking this packet contains stego message
destination = '192.168.123.123'  # ip address where we send our packets

received_packages = Queue()


@eel.expose
def server_daemon():
    server_thread = threading.Thread(target=server)
    server_thread.start()


@eel.expose
def client_thread(message: str):
    thread = threading.Thread(target=client(message))
    thread.start()


@eel.expose
def queue_poper() -> str:
    """Pops all received data and transfers it to view"""
    text = ''
    while not received_packages.empty():
        text += received_packages.get() + '\n'
    return text


def client(text):
    """Handles sending packets with stego chars"""
    i = 0
    for char in text:
        payload = 256 * i + int.from_bytes(bytes(char, encoding='cp866'), 'big')
        send(IP(tos=secret_TOS, chksum=payload, dst=destination, flags='DF'))
        i += 1
    print('sent')


def server():
    """Sniffs send packets, retrieves message letters"""
    sniff(filter='ip[1]=0xD', prn=lambda x: received_packages.put(
        'i = %d, char = %s' % (x[IP].chksum / 256, (x[IP].chksum % 256).to_bytes(1, 'big').decode('cp866'))))


def main():
    eel.init(Path(__file__).parent / 'view')
    eel.start('view.html', port=8014)


if __name__ == '__main__':
    main()
