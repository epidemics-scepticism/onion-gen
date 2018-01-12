#!/usr/bin/env python3

#    Copyright (C) 2016 cacahuatl < cacahuatl at autistici dot org >
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from base64 import b32encode
from time import time,sleep
from sys import stdout
from itertools import combinations
from multiprocessing import Process,Queue,Event

from Crypto.PublicKey import RSA
from Crypto.PublicKey.pubkey import getStrongPrime
from Crypto.Util import asn1
from Crypto.Util.number import inverse
from Crypto.Hash import SHA

ctr = 0
start_time = 0

class Search():
    """ Uses a list of words to efficiently iteratively search for a string
    which consists purely of words in the list.
    """
    def __init__(self, wordlists: list = [], full: bool = True):
        """ wordlists is a list of file paths, to files containing new-line
        separated words.
        full is a boolean flag to determine if a prefix or a full match is
        required.
        """
        self.root = {}
        self.charset = set("abcdefghijklmnopqrstuvwxyz234567")
        self.full = full
        self.populate(wordlists)

    def populate(self, wordlists: list = []):
        """ Populates the lookup table from the wordlist list.
        """
        print("[-] Populating from wordlists", end = '')
        stdout.flush()
        for wordlist in wordlists:
            for word in open(wordlist).read().split('\n'):
                word = word.lower()
                if len(word) < 1:
                    continue
                if set(word).issubset(self.charset) is False:
                    continue
                tree = self.root
                for letter in word[:-1]:
                    if not letter in tree:
                        tree[letter] = [{}, False]
                    tree = tree[letter][0]
                if word[-1] in tree:
                    tree[word[-1]][1] = True
                else:
                    tree[word[-1]] = [{}, True]
        self.populated = True
        print("[+] Populated from wordlists ")

    def match(self, test):
        """ Checks test against the wordlists, returns True on a match, else
        False.
        """
        if self.populated != True:
            return False
        tree = self.root
        for i in range(0, len(test)):
            if test[i] in tree:
                if tree[test[i]][1] is True:
                    if self.full is False:
                        return True
                    elif self.match(test[i+1:]) is True:
                        return True
                tree = tree[test[i]][0]
            else:
                return False
        return True

def generator(done: Event, primes: Queue, search: Search):
    while done.is_set():
        p, q = primes.get()
        if p > q:
            (p, q) = (q, p)
            u = inverse(p, q)
            n = p * q
            for e in range(3, 65538, 2):
                d = inverse(e, (p - 1) * (q - 1))
                r = RSA.construct((n, e, d, p, q, u))
                pub = r.publickey()
                der = asn1.DerSequence()
                der.append(pub.n)
                der.append(pub.e)
                b = der.encode()
                h = SHA.new(b).digest()[0:10]
                o = b32encode(h).lower().decode('utf-8')                
                if search.match(o):
                    sk = r.exportKey('PEM').decode('utf-8')
                    print("%s\n%s" % (o, sk))
                    open(o + ".onion", 'w').write(sk)

if __name__ == '__main__':
    import argparse
    from sys import stdout

    parser = argparse.ArgumentParser(description="Onion Searcher")
    parser.add_argument("--word-lists", "-w", type = str, default = "words",
        help = "Comma delimited list of wordlists")
    parser.add_argument("--full", "-f", action = "store_true",
        help = "Only match full, not just prefix")
    parser.add_argument("--processes", "-p", type = int, default = 4,
        help = "Number of worker processes")
    args = parser.parse_args()
    d = Event()
    d.set()
    q = Queue(args.processes)
    processes = []
    s = Search(wordlists = args.word_lists.split(','), full = args.full)
    for i in range(0, args.processes):
        print("[+] Starting worker {}".format(i+1))
        processes.append(Process(target = generator, args = (d, q, s)))
        processes[i].start()
    try:
        while True:
            q.put((getStrongPrime(512, 3, 1e-12),getStrongPrime(512, 3, 1e-12)))
    except KeyboardInterrupt:
        print("[-] Interrupt received, stopping...")
        stdout.flush()
        d.clear()
        for p in processes:
            p.terminate()
        i = args.processes
        for p in processes:
            p.join()
            print("[+] Worker {} stopped.".format(i))
            i = i-1
