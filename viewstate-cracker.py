#!/usr/bin/python3
import os
import hmac
import signal
from queue import Queue
from urllib import parse
from threading import Thread
from binascii import hexlify
from base64 import b64decode
from hashlib import sha1, sha256
from argparse import ArgumentParser


class ViewStateCracker:
    def __init__(self, queue_size, viewstate, wordlist) -> None:
        self.queue_size = queue_size
        self.queue = None
        self.viewstate = viewstate
        self.wordlist = wordlist
        self.orig_enc_data = None
        self.orig_hmac = None

    def slice_viewstate(self):
        self.orig_hmac = self.viewstate[-20:]
        self.orig_enc_data = self.viewstate[:-20]

    def check_hmac(self, key):
        new_hmac = hmac.new(key, self.orig_enc_data, sha1)
        if hmac.compare_digest(new_hmac.digest(), self.orig_hmac):
            print(f"[+] Key found: {key.decode()}")
            os.kill(os.getpid(), signal.SIGINT)

    def do_work(self):
        while True:
            key = self.queue.get()
            self.check_hmac(key.encode())
            self.queue.task_done()

    def read_wordlist(self):
        with open(self.wordlist, 'r') as f:
            while line := f.readline():
                yield line.rstrip()

    def startup_data(self):
        print(f"{'[*] SHA256 of viewstate/HMAC:' : <30} {sha256(self.viewstate).hexdigest()}")
        print(f"{'[*] SHA256 of viewstate:' : <30} {sha256(self.orig_enc_data).hexdigest()}")
        print(f"{'[*] Original HMAC SHA1 digest:' : <30} {hexlify(self.orig_hmac).decode()}")
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
    parser = ArgumentParser(description="Multithreaded, queued viewstate encryption key cracker by M. Cory Billington.")
    parser.add_argument("-q", "--queue-size", nargs='?', default=200, type=int, help="Size of queue. read the docs. idk...")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist.")
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

    viewstate_cracker = ViewStateCracker(queue_size=args.queue_size,
                                         viewstate=viewstate_object,
                                         wordlist=args.wordlist)
    viewstate_cracker.run()


if __name__ == "__main__":
    main()
