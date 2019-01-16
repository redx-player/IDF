#!/usr/bin/python
# Author: Mozzamil Eltayeeb (Red-x)
# Last Updated: 13/1/19
# v1.0

#~~~~~~~~~~~~~~~~~import libs~~~~~~~~~~~~~~~~~~~~~#
from progressbar import ProgressBar, Percentage, Bar
import commands
import os
import sys
import subprocess
import time
import string

#~~~~~~~~~~~~~~~~~print colors~~~~~~~~~~~~~~~~~~~~#
w="\033[1;37m"
red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
b="\033[1;34m"


#~~~~~~~~~~~~~~~~~~  banner  ~~~~~~~~~~~~~~~~~~~~~#
os.system("clear")
print w+"========================================="
print"||"+red+"                  __                 "+w+"||"
print"||"+red+"                 /  \                "+w+"||"
print"||"+red+"      __        //  \\\\            __ "+w+"||  Image Digital Forensic"
print"||"+red+"     /  \\"+w+"d888888b"+red+"    \\\\          /  \\"+w+"||  "
print"||"+red+"    // "+w+".88"+red+"    //"+w+"88."+red+"   \\\\        //   "+w+"||  Author: Red-x"
print"||"+red+"   //  "+w+"88"+red+"\\\\  //  "+w+"88"+red+"    \\\\      //    "+w+"||"
print"||"+red+"  //   "+w+"88"+red+" \\\\//   "+w+"88"+red+"     \\\\    //     "+w+"||  Twitter: @mozzamil_redx"
print"||"+red+" //    "+w+"88        88"+red+"      \\\\  //      "+w+"||"
print"||"+red+"//     "+w+"'88      88'"+red+"       \\\\//       "+w+"||  Version: 1.0"
print"||        "+b+"/0/"+w+"88888P                    "+w+"||"
print"||       "+b+"/0/                           "+w+"||  https://github.com/Red-x-player/IDF"
#print"||      "+b+"/0/                            "+w+"||"
print"========"+b+"/0/"+w+"=============================="
print b+"       /0/\n\n"




#~~~~~~~~~~~~~~~~~~check type~~~~~~~~~~~~~~~~~~~~~#
if len(sys.argv)==1:
    time.sleep(0.4)
    exit(red+"[+] No such file or directory")

fullPATH=sys.argv[1]
fullPATH=fullPATH.replace(" ","\ ")
imageName=fullPATH
if fullPATH.find("/")!=-1:
    PathArray=sys.argv[1].split("/")
    imageName=PathArray[len(PathArray)-1]

fileTypes=["ASCII text",
"RAR archive data",
"Zip archive data",
"7-zip archive data",
"gzip compressed data",
"ELF 32-bit LSB executable",
"ELF 64-bit LSB executable",
"PE32 executable (GUI)",
"DOS/MBR boot sector",
"Windows Recycle Bin",
"Composite Document",
"Android binary XML",
"Java archive data (JAR)",
"PNG image data",
"JPEG image data",
"Dalvik dex file",
"Visual Networks traffic",
"tcpdump capture file"
"data",
"directory",
"empty"]

output = subprocess.check_output("file "+fullPATH, shell=True)
fileType=False
for getType in fileTypes:
    if output.find(getType)!=-1:
        time.sleep(0.9)
        print green+"[+] "+yellow+"File Type: "+getType
        fileType=getType
        break
if fileType==False:
    print red+"[+] Unknown file type"
    
#~~~~~~~~~~~~~~~~~Bytes2Strings~~~~~~~~~~~~~~~~~#
os.system("mkdir _%s"%(imageName))
time.sleep(0.9)
print green+"[+] "+yellow+"Change bytes to strings > 2strings.txt"
min=4
o = open("_%s/2strings.txt"%(imageName),"wb")
f = open(sys.argv[1],"rb")
result = ""
for c in f.read():
    if c in string.printable:
       result += c
       continue
    if len(result) >= min:
        o.write(result+"\n")
    result = ""
if len(result) >= min:
    o.write(result+"\n")

#~~~~~~~~~~~~~~~~~meta data~~~~~~~~~~~~~~~~~~~~~#
os.system("exiftool %s > _%s/metaData.txt"%(fullPATH,imageName))
time.sleep(0.9)
print green+"[+] "+yellow+"Extract meta data to metaData.txt"


#~~~~~~~~~~~~~~~~~foremost~~~~~~~~~~~~~~~~~~~~~#
os.system("mkdir _%s/hiddenFiles;mkdir _%s/hiddenFiles/foremost"%(imageName,imageName))
output = subprocess.check_output("foremost -t all -v -i %s -o _%s/hiddenFiles/foremost"%(fullPATH,imageName), shell=True)
time.sleep(0.9)
print green+"[+] "+yellow+"Foremost extract hidden files"


#~~~~~~~~~~~~~~~~~ binwalk ~~~~~~~~~~~~~~~~~~~~#
output = subprocess.check_output("binwalk -e %s --directory _%s/hiddenFiles"%(fullPATH,imageName), shell=True)
time.sleep(0.9)
print green+"[+] "+yellow+"Binwalk extract hidden files"


#~~~~~~~~~~~~~~~~~stegsolve~~~~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
print green+"[+] "+yellow+"Try to open image in stegsolve"
os.system("java -jar stegsolve.jar")


#~~~~~~~~~~~~~~ reverse bytes ~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
print green+"[+] "+yellow+"Reverse image bytes"
file1 = open(sys.argv[1],'rb')
data = file1.read()
data2 = []
file2 = open("_%s/revImage"%(imageName.replace("\ "," ")),"wb")
file2.write(data[::-1])
file2.close()


#~~~~~~~~~~~~~~~~ and2bytes ~~~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
os.system("mkdir _%s/AND"%(imageName))
andRange=raw_input(green+"[+] "+yellow+"Enter the range in decimal to do AND opretion(default 1-100): ")
if andRange=="":
    andRange="1-100"
andRange=andRange.split("-")
for x in range(int(andRange[0]),int(andRange[1])+1):
    f=bytearray(open(sys.argv[1],'rb').read())
    for y in range(len(f)):
        f[y]&=x
    open('_%s/AND/andWith%s'%(imageName.replace("\ "," "),x),'wb').write(f)


#~~~~~~~~~~~~~~~~ xor2bytes ~~~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
os.system("mkdir _%s/XOR"%(imageName))
xorRange=raw_input(green+"[+] "+yellow+"Enter the range in decimal to do XOR opretion(default 1-100): ")
if xorRange=="":
    xorRange="1-100"
xorRange=xorRange.split("-")
for x in range(int(xorRange[0]),int(xorRange[1])+1):
    f=bytearray(open(sys.argv[1],'rb').read())
    for y in range(len(f)):
        f[y]^=x
    open('_%s/XOR/xorWith%s'%(imageName.replace("\ "," "),x),'wb').write(f)


#~~~~~~~~~~~~~~steghide crack~~~~~~~~~~~~~~~~~~#
if fileType=="JPEG image data":
    crack=raw_input(green+"[+] "+yellow+"Do you want to crack this image with steghide crack(take longe time)?[N/y] ")
    if crack.lower().startswith("y")!=False:
        os.system("mkdir _%s/steghideCrack"%(imageName))
        wordlist=raw_input(green+"[+] "+yellow+"Enter wordlist path (default rockyou): ")
        if wordlist=="" :
            if os.path.exists("/usr/share/wordlists/rockyou.txt")==True:
                wordlist="/usr/share/wordlists/rockyou.txt"
            else:
                exit(green+"[+] "+yellow+"You don't have rockyou in this path '/usr/share/wordlists/rockyou.txt'")
        print green+"[+] "+yellow+"Start cracking..."
        i = 0
        ofile = imageName.split('.')[0] + "_flag.txt"
        nlines = len(open(wordlist).readlines())
        with open(wordlist, 'r') as passFile:
            pbar = ProgressBar(widgets=[Percentage(), Bar()], maxval=nlines).start()
            for line in passFile.readlines():
                password = line.strip('\n')
                r = commands.getoutput("steghide extract -sf %s -p '%s' -xf _%s/steghideCrack/%s" % (fullPATH, password,imageName, ofile))
                if not "no pude extraer" in r and not "could not extract" in r:
                    print(green+"\n[+] "+yellow+"Information obtained with password: %s" % password)
                    break
                pbar.update(i + 1)
                i += 1

#~~~~~~~~~~~~~~~~~~Finsh scan~~~~~~~~~~~~~~~~#
time.sleep(0.9)
print green+"[+] "+yellow+"Done !!"
