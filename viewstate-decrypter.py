#!/usr/bin/python3
import os
import signal
from queue import Queue
from urllib import parse
from threading import Thread
from binascii import hexlify
from base64 import b64decode
from hashlib import sha1, sha256
from argparse import ArgumentParser
from pyDes import des, ECB, PAD_PKCS5


class ViewStateCracker:
    def __init__(self, queue_size, algorithm, viewstate, wordlist, outfile) -> None:
        self.queue_size = queue_size
        self.queue = None
        self.algorithm = algorithm
        self.viewstate = viewstate
        self.wordlist = wordlist
        self.outfile = outfile
        self.enc_data = None
        self.hmac = None
        self.key_length_error = 0

    def slice_viewstate(self):
        offset = len(self.algorithm().digest())
        self.hmac = self.viewstate[-offset:]
        self.enc_data = self.viewstate[:-offset]

    def key_length_check(self, key):
        if len(key) != 8:
            self.key_length_error += 1
            if self.key_length_error % 100 == 0:
                print("Detecting a lot of keys that are not 8 bytes long")
            return False
        return True

    def decrypt(self, key):
        if len(key) != 8:
            self.key_length_error += 1
            if self.key_length_error % 100 == 0:
                print("Detecting a lot of keys that are not 8 bytes long")
            return

        cipher = des(key, ECB, IV=None, pad=None, padmode=PAD_PKCS5)
        decrypted = cipher.decrypt(self.enc_data)

        if decrypted[:4] in (b'\xca\xfe\xba\xbe', b'\xac\xed\x00\x05'):
            print(f"[+] Key found: {key.decode()}")
            if self.outfile:
                with open(self.outfile, 'wb') as f:
                    f.write(decrypted)
                print(f"[+] Viewstate written to {self.outfile}")
            os.kill(os.getpid(), signal.SIGINT)

    def do_work(self):
        while True:
            key = self.queue.get()
            self.decrypt(key.encode())
            self.queue.task_done()

    def read_wordlist(self):
        with open(self.wordlist, 'r') as f:
            while line := f.readline():
                key = line.strip()
                if self.key_length_check(key):
                    yield key

    def startup_data(self):
        print(f"{'[*] SHA256 of viewstate/HMAC:' : <30} {sha256(self.viewstate).hexdigest()}")
        print(f"{'[*] SHA256 of viewstate:' : <30} {sha256(self.enc_data).hexdigest()}")
        if self.algorithm == sha256:
            print(f"{'[*] Original HMAC SHA256 digest:' : <30} {hexlify(self.hmac).decode()}")
        else:
            print(f"{'[*] Original HMAC SHA1 digest:' : <30} {hexlify(self.hmac).decode()}")
        print("[*] Running...\n")

    def run(self):
        self.queue = Queue(self.queue_size)
        self.slice_viewstate()
        self.startup_data()

        for _ in range(self.queue_size):
            t = Thread(target=self.do_work)
            t.daemon = True
            t.start()

        try:
            for key in self.read_wordlist():
                self.queue.put(key.strip())
            self.queue.join()
        except KeyboardInterrupt:
            exit(1)
        print("[-] Key not found")


def parse_args():
    parser = ArgumentParser(description="Viewstate encryption key cracker by M. Cory Billington.")
    parser.add_argument("-q", "--queue-size", nargs='?', default=200, type=int, help="Size of queue. read the docs. idk...")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist.")
    parser.add_argument("-a", "--algorithm", required=False, default='sha1', help="HMAC algorithm (sha1 or sha256)")
    parser.add_argument("-o", "--outfile", required=False, default=None, help="File to write decrypted viewstate object")
    viewstate_group = parser.add_mutually_exclusive_group(required=True)
    viewstate_group.add_argument("-f", "--viewstate-file", help="Path to base64 encoded viewstate.")
    viewstate_group.add_argument("-V", "--viewstate", help="Viewstate as a base64 encoded string.")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.viewstate:
        unquoted = parse.unquote_plus(args.viewstate)
        viewstate_object = b64decode(unquoted)
    else:
        with open(args.viewstate_file, 'r') as f:
            unquoted = parse.unquote_plus(f.read())
            viewstate_object = b64decode(unquoted)

    if args.algorithm == 'sha256':
        algorithm = sha256
    else:
        algorithm = sha1

    viewstate_cracker = ViewStateCracker(queue_size=args.queue_size,
                                         algorithm=algorithm,
                                         viewstate=viewstate_object,
                                         wordlist=args.wordlist,
                                         outfile=args.outfile
                                         )
    viewstate_cracker.run()


if __name__ == "__main__":
    main()
