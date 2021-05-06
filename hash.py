import os
import shutil as shu
import hashlib as hl
from zlib import adler32,crc32
from base64 import b64encode as b64
from Crypto.Util.RFC1751 import key_to_english as rfc1751
from Crypto.Util.Padding import pad
from Crypto.Hash import MD2 as md2,RIPEMD160 as ripemd160,keccak
from crcmod.predefined import mkCrcFun as mkcrc
import hashlib_additional as hlext
from blake3 import blake3
from siphash import SipHash_2_4 as sip

j=lambda *x:os.path.join(*x)
fp=lambda *x:os.path.join(".",*x)
k2e=lambda b:rfc1751(pad(b,8))

nl=[5,10,15,25,50,100,250,500,1000,1024,2048,4096,8192,10000,15000,100000]
crcl=[
    "crc-8",
    "crc-8-darc",
    "crc-8-i-code",
    "crc-8-itu",
    "crc-8-maxim",
    "crc-8-rohc",
    "crc-8-wcdma",
    "crc-16",
    "crc-16-buypass",
    "crc-16-dds-110",
    "crc-16-dect",
    "crc-16-dnp",
    "crc-16-en-13757",
    "crc-16-genibus",
    "crc-16-maxim",
    "crc-16-mcrf4xx",
    "crc-16-riello",
    "crc-16-t10-dif",
    "crc-16-teledisk",
    "crc-16-usb",
    "x-25",
    "xmodem",
    "modbus",
    "kermit",
    "crc-ccitt-false",
    "crc-aug-ccitt",
    "crc-24",
    "crc-24-flexray-a",
    "crc-24-flexray-b",
    "crc-32-bzip2",
    "crc-32c",
    "crc-32d",
    "crc-32-mpeg",
    "posix",
    "crc-32q",
    "jamcrc",
    "xfer",
    "crc-64",
    "crc-64-we",
    "crc-64-jones"
]

def w(f,s):
    if type(s)==bytes:
        s=s.decode("utf-8")
    f=open(f,"w")
    res=f.write(s)
    f.close()
    return res

def wb(f,b):
    f=open(f,"wb")
    res=f.write(b)
    f.close()
    return res

def main():
    s="JustAytch"
    count=bc=0
    d={
        "sha1": hl.sha1(),
        "sha224": hl.sha224(),
        "sha256": hl.sha256(),
        "sha384": hl.sha384(),
        "sha512": hl.sha512(),
        "blake2b": hl.blake2b(),
        "blake2s": hl.blake2s(),
        "md5": hl.md5(),
        "sha3-224": hl.sha3_224(),
        "sha3-256": hl.sha3_256(),
        "sha3-384": hl.sha3_384(),
        "sha3-512": hl.sha3_512(),
        "shake128": hl.shake_128(),
        "shake256": hl.shake_256(),
        "md2": md2.new(),
        "ripemd160": ripemd160.new(),
        "blake3": blake3(),
        "SipHash-2-4": sip(pad(bytes(s,"utf-8"),16)[:16])
    }
    for i in ["fletcher16","fletcher32","fletcher64","cksum","sysv","bsd","udp","twoping"]:
        d[i]=hlext.new(i)
    for k in d:
        x=d[k]
        x.update(bytes(s,"utf-8"))
        try:
            bc+=wb(fp("hash",f"{k}_default.bin"),x.digest())
            bc+=w(fp("hash",f"{k}_default.hex"),x.hexdigest())
            bc+=wb(fp("hash",f"{k}_default.b64"),b64(x.digest()))
            bc+=w(fp("hash",f"{k}_default.rfc1751"),k2e(x.digest()))
            count+=4
        except TypeError:
            for n in nl:
                bc+=wb(fp("hash",f"{k}_{n}.bin"),x.digest(n))
                bc+=w(fp("hash",f"{k}_{n}.hex"),x.hexdigest(n))
                bc+=wb(fp("hash",f"{k}_{n}.b64"),b64(x.digest(n)))
                bc+=w(fp("hash",f"{k}_{n}.rfc1751"),k2e(x.digest(n)))
                count+=4
    for n in [224,256,384,512]:
        x=keccak.new(digest_bits=n)
        x.update(bytes(s,"utf-8"))
        bc+=wb(fp("hash",f"keccak_{n}.bin"),x.digest())
        bc+=w(fp("hash",f"keccak_{n}.hex"),x.hexdigest())
        bc+=wb(fp("hash",f"keccak_{n}.b64"),b64(x.digest()))
        bc+=w(fp("hash",f"keccak_{n}.rfc1751"),k2e(x.digest()))
        count+=4
    zl=[adler32(bytes(s,"utf-8")),crc32(bytes(s,"utf-8"))]
    kl=["adler32","crc32"]
    el=["int","hex","b64","rfc1751"]
    for i in crcl:
        zl.append(mkcrc(i)(bytes(s,"utf-8")))
        kl.append(i)
    for i in zl:
        tmp=[str(i),str(hex(i)).replace("0x","",1),b64(bytes(str(i),"utf-8")).decode("utf-8"),k2e(bytes(str(i),"utf-8"))]
        for ii in tmp:
            k=kl[zl.index(i)]+"_default."+el[tmp.index(ii)]
            bc+=w(fp("hash",k),ii)
            count+=1
    print(f"{count} Files Written.")
    print(f"{bc} Bytes Written.")

def init():
    try:
        shu.rmtree(fp("hash"))
    except:
        pass
    os.mkdir(fp("hash"))
    main()
    print("Done!!!")

if __name__=="__main__":
    init()