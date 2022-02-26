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
    def __init__(self, queue_size, algorithm, viewstate, wordlist) -> None:
        self.queue_size = queue_size
        self.queue = None
        self.algorithm = algorithm
        self.viewstate = viewstate
        self.wordlist = wordlist
        self.orig_enc_data = None
        self.orig_hmac = None

    def slice_viewstate(self):
        offset = len(self.algorithm().digest())
        self.orig_hmac = self.viewstate[-offset:]
        self.orig_enc_data = self.viewstate[:-offset]

    def check_hmac(self, key):
        new_hmac = hmac.new(key, self.orig_enc_data, self.algorithm)
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
        if self.algorithm == sha256:
            print(f"{'[*] Original HMAC SHA256 digest:' : <30} {hexlify(self.orig_hmac).decode()}")
        else:
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
            print("[!] Detected keyboard interrupt. Exiting...")
            exit(1)
        print("[-] Key not found")


def parse_args():
    parser = ArgumentParser(description="Viewstate encryption key cracker by M. Cory Billington.")
    parser.add_argument("-q", "--queue-size", nargs='?', default=200, type=int, help="Size of queue. read the docs. idk...")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist.")
    parser.add_argument("-a", "--algorithm", required=False, default='sha1', help="HMAC algorithm (sha1 or sha256)")
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
                                         wordlist=args.wordlist)
    viewstate_cracker.run()


if __name__ == "__main__":
    main()
