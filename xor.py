#coding:utf-8

import os
import base64

def Readfile():
        filename = 'cipher.txt'
        cipherList = []
        f = open(filename,'r').readlines()
        cipher = base64.b64decode(f[0])
        cipherList.extend(map(lambda i:ord(cipher[i]), range(0,len(cipher),1)))
        return cipherList

def getKeyPool(cipher, plaintext, keyset, keylenlist):
        KeyPool = {}
        for step in keylenlist:
                res = [None]*step
                for pos in xrange(step):
                        res[pos] = []
                        for k in keyset:
                                flag = 1
                                for c in cipher[pos::step]:
                                        if c^k not in plaintext:
                                                flag = 0
                                if flag:
                                        res[pos].append(k)
                for i in res:
                        if len(i) == 0:
                                res=[]
                                break
                if len(res) > 0:
                        KeyPool[step] = res
        return KeyPool
        

def getFrequency(cipher, KeyPoolList):
        keylen = len(KeyPoolList)
        freqlist = []
        for i in xrange(keylen):
                charlist = {}
                for cell in KeyPoolList[i]:
                        charlist[cell] = {}
                        for c in cipher[i::keylen]:
                                char = chr(cell^c)
                                charlist[cell][char] = charlist[cell][char] + 1 if char in charlist[cell] else 1        
                freqlist.append(charlist)
        return freqlist

def calCorrelation(cpool):
        '''传入字典，形如{'e':2,'p':3}
        返回可能性，0~1,值越大可能性越大
        (correlation between the decrypted column letter frequencies and
        the relative letter frequencies for normal English text)
        '''
        frequencies = {"e": 0.12702, "t": 0.09056, "a": 0.08167, "o": 0.07507, "i": 0.06966,"n": 0.06749, "s": 0.06327, "h": 0.06094, "r": 0.05987, "d": 0.04253,"l": 0.04025, "c": 0.02782, "u": 0.02758, "m": 0.02406, "w": 0.02360,"f": 0.02228, "g": 0.02015, "y": 0.01974, "p": 0.01929, "b": 0.01492,"v": 0.00978, "k": 0.00772, "j": 0.00153, "x": 0.00150, "q": 0.00095, "z": 0.00074}
        charList = 'qwertyuiopasdfghjklzxcvbnm'
        total = sum(cpool.values())
        relative =0.0
        for i in cpool.keys():
                if i in charList:
                        relative += frequencies[i]*cpool[i]/total
        return relative        


def SelectFromFreq(freqlist):
        key = []
        for freq in freqlist:
                mostRelative = 0
                for char in freq.keys():
                        r = calCorrelation(freq[char])
                        if r > mostRelative:
                                mostRelative = r
                                keychar = char
                key.append(keychar)
        return key


def xorDecrypt(cipher,key):
        keylen = len(key)
        pos = 0
        plain = ''
        for c in cipher:
                plain += chr(c^key[pos])
                pos = (pos + 1) % keylen
        return plain 

def main():
        '''
        cipher 密钥 
        plaintext 明文
        keyset 密钥字符集
        keylen 密钥的可能长度
        '''

        cipher = Readfile()
        print len(cipher)
        plaintext = list(xrange(0xff))
        keyset = list(xrange(32,128))
        keylenlist = list(xrange(10,24))

        keyPool = getKeyPool(cipher=cipher, plaintext=plaintext, keyset=keyset, keylenlist=keylenlist)
        #print KeyPool
        for i in keyPool:
                freq = getFrequency(cipher, keyPool[i])
                key = SelectFromFreq(freq)
                print ''.join(map(chr,key))

if __name__ == '__main__':
        main()
