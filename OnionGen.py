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

from Crypto.PublicKey import RSA
from Crypto.PublicKey.pubkey import getStrongPrime
from Crypto.Util import asn1
from Crypto.Util.number import inverse
from Crypto.Hash import SHA
from base64 import b32encode
from time import time,sleep
from sys import stdout
from itertools import combinations

ctr = 0
start_time = 0

class Search():

    def __init__(self, wordlists = [], full = False):
        self.root = {}
        self.charset = set("abcdefghijklmnopqrstuvwxyz234567")
        self.full = full
        self.populate(wordlists)

    def populate(self, wordlists = []):
        print("[-] Populating from wordlists\r", end = '')
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

class Generator():

    def __init__(self, count = 500, wordlists = [], die = None, auto_start = False, full = False):
        self.die = die
        self.primes = []
        self.onions = {}
        self.count = count
        self.searcher = Search(wordlists, full)
        self.spinner = ['|','/','-','\\']
        if auto_start:
            while die.is_set():
                self.populate_primes()
                self.search()

    def populate_primes(self):
        self.primes = []
        print("[-] Generating %d primes\r" % self.count, end = '')
        stdout.flush()
        for _ in range(0,self.count):
            self.primes.append(getStrongPrime(512, 3, 1e-12))
        print("[+] Generated %d primes \r" % self.count)

    def onion(self,pub):
        der = asn1.DerSequence()
        der.append(pub.n)
        der.append(pub.e)
        b = der.encode()
        h = SHA.new(b).digest()[0:10]
        return b32encode(h).lower().decode('utf-8')

    def gen_key(self,p,q,e):
        if p > q:
            (p, q)=(q, p)
        u = inverse(p,q)
        n = p*q
        d = inverse(e, (p-1) * (q-1))
        return RSA.construct((n, e, d, p, q, u))


    def search(self):
        global start_time
        global ctr
        if start_time == 0:
            start_time = time()
        for p,q in combinations(self.primes, 2):
            for e in range(3, 65538, 2):
                if not self.die.is_set():
                    return
                k = self.gen_key(p, q, e)
                o = self.onion(k.publickey())
                if self.searcher.match(o) is True:
                    pk = k.exportKey('PEM').decode('utf-8')
                    print("%s\n%s" % (o, pk))
                    open(o + ".onion", 'w').write(pk)
                ctr = ctr + 1
                print("[%s]\r" % self.spinner[ctr % len(self.spinner)], end = '')
                stdout.flush()

if __name__ == '__main__':
    import argparse,threading
    from sys import stdout
    die = threading.Event()
    die.set()
    parser = argparse.ArgumentParser(description="Onion Searcher")
    parser.add_argument("--count", "-c", type = int, default = 100,
        help = "Number of primes to generate")
    parser.add_argument("--word-lists", "-w", type = str, default = "words",
        help = "Comma delimited list of wordlists")
    parser.add_argument("--full", "-f", type = bool, default = False,
        help = "Only match full, not just prefix")
    args = parser.parse_args()
    t = threading.Thread(target = Generator, args = (args.count, args.word_lists.split(','), die, True, args.full))
    t.start()
    try:
        while True:
            sleep(30.0)
            if start_time > 0:
                elapsed = time() - start_time
                print("%d keys in %d seconds\t(%d k/s)" % (ctr, elapsed, ctr / elapsed))
    except KeyboardInterrupt:
        print("[-] Interrupt received, stopping...\r", end = '')
        stdout.flush()
        die.clear()
        t.join()
        print("[+] Interrupt received, stopped... ")
