#!/usr/bin/python
# Author: Mozzamil Eltayeeb (red-x)
# Last Updated: 29/03/20
# v2.0


#~~~~~~~~~~~~~~~~~import libs~~~~~~~~~~~~~~~~~~~~~#
import commands
import os
import sys
import subprocess
import time
import string


#~~~~~~~~~~~~~~~~~print colors~~~~~~~~~~~~~~~~~~~~#
w="\033[1;37m"
r="\033[1;31m"
g="\033[1;32m"
y="\033[1;33m"
yellow="\033[1;33m"
b="\033[1;34m"

#~~~~~~~~~~~~~~~~~~  banner  ~~~~~~~~~~~~~~~~~~~~~#
os.system("clear")
print w+"========================================="
print"||"+r+"                  __                 "+w+"||"
print"||"+r+"                 /  \                "+w+"||"
print"||"+r+"      __        //  \\\\            __ "+w+"||  Image Digital Forensic"
print"||"+r+"     /  \\"+w+"d888888b"+r+"    \\\\          /  \\"+w+"||  "
print"||"+r+"    // "+w+".88"+r+"    //"+w+"88."+r+"   \\\\        //   "+w+"||  Author: red-x"
print"||"+r+"   //  "+w+"88"+r+"\\\\  //  "+w+"88"+r+"    \\\\      //    "+w+"||"
print"||"+r+"  //   "+w+"88"+r+" \\\\//   "+w+"88"+r+"     \\\\    //     "+w+"||  Twitter: @mozzamil_redx"
print"||"+r+" //    "+w+"88        88"+r+"      \\\\  //      "+w+"||"
print"||"+r+"//     "+w+"'88      88'"+r+"       \\\\//       "+w+"||  Version: 2.0"
print"||        "+b+"/0/"+w+"88888P                    "+w+"||"
print"||       "+b+"/0/                           "+w+"||  https://github.com/red-x-player/IDF"
#print"||      "+b+"/0/                            "+w+"||"
print"========"+b+"/0/"+w+"=============================="
print b+"       /0/\n\n"

#~~~~~~~~~~~~~~~~~~Get file info~~~~~~~~~~~~~~~~~~~#
if len(sys.argv)>=2:
	#Full file Path with replace special chars 
	filePath = sys.argv[1].replace(" ","\ ").replace("(","\(").replace(")","\)")
	#Full file path with no replace
	filePath1= sys.argv[1]
	#Directory name with replace special chars to mkdir and rm
	dirName  = '%s' % (os.path.basename(filePath))
	#file name with out replace 
	fileName= '%s' % (os.path.basename(sys.argv[1]))
else:
	#Full file path with no replace
	filePath1= raw_input(g+"[+] "+y+"Enter your file path: "+w)
	#Full file Path with replace special chars 
	filePath = filePath1.replace(" ","\ ").replace("(","\(").replace(")","\)")
	#Directory name with replace special chars to mkdir and rm
	dirName  = '%s' % (os.path.basename(filePath))
	#file name with out replace
	fileName= '%s' % (os.path.basename(filePath1))

#~~~~~~~~~~~~~~~~~~check type~~~~~~~~~~~~~~~~~~~~~#
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

output = subprocess.check_output("file "+filePath, shell=True)
fileType=False
for getType in fileTypes:
    if output.find(getType)!=-1:
        time.sleep(0.9)
        print g+"[+] "+y+"File Type: "+getType
        fileType=getType
        break
if fileType==False:
    print r+"[+] Unknown file type"

#~~~~~~~~~~~~~~~~~stegsolve~~~~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
print g+"[+] "+y+"Try to open image in stegsolve"
os.system("java -jar stegsolve.jar")

#~~~~~~~~~~~~~~~~~Bytes2Strings~~~~~~~~~~~~~~~~~#
if os.path.exists("_%s"%(fileName)) == False:
	os.system("mkdir _%s"%(dirName))
time.sleep(0.9)
print(g+"[+] "+y+"Change bytes to strings into "+w+"strings.txt")
min=4
o = open("_%s/strings.txt"%(fileName),"wb")
f = open(filePath1,"rb")
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
os.system("exiftool %s > _%s/metaData.txt"%(filePath,dirName))
time.sleep(0.9)
print g+"[+] "+y+"Extract meta data into "+w+"metaData.txt"+y


#~~~~~~~~~~~~~~~~~foremost~~~~~~~~~~~~~~~~~~~~~#
if os.path.exists("_%s/hiddenFiles"%(fileName)) == False:
	os.system("mkdir _%s/hiddenFiles;mkdir _%s/hiddenFiles/foremost"%(dirName,dirName))
else:
	os.system("rm -r _%s/hiddenFiles/foremost/*"%(dirName))

output = subprocess.check_output("foremost -t all -v -i %s -o _%s/hiddenFiles/foremost"%(filePath,dirName), shell=True)
time.sleep(0.9)
print g+"[+] "+y+"Foremost extract hidden files"


#~~~~~~~~~~~~~~~~~ binwalk ~~~~~~~~~~~~~~~~~~~~#
output = subprocess.check_output("binwalk -e %s --directory _%s/hiddenFiles"%(filePath,dirName), shell=True)
time.sleep(0.9)
print g+"[+] "+y+"Binwalk extract hidden files"


#~~~~~~~~~~~~~~ reverse bytes ~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
print g+"[+] "+y+"Reverse image bytes and saved into "+w+"revImage"
file1 = open(filePath1,'rb')
data = file1.read()
data2 = []
file2 = open("_%s/revImage"%(fileName),"wb")
file2.write(data[::-1])
file2.close()

#~~~~~~~~~~~~~~~~ and operation ~~~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
if os.path.exists("_%s/AND"%(fileName)) == False:
	os.system("mkdir _%s/AND"%(dirName))
andRange=raw_input(g+"[+] "+yellow+"AND operation enter the range in decimal(default 1-100): "+w)
if andRange=="":
    andRange="1-100"
andRange=andRange.split("-")
for x in range(int(andRange[0]),int(andRange[1])+1):
    f=bytearray(open(filePath1,'rb').read())
    for z in range(len(f)):
        f[z]&=x
    open('_%s/AND/andWith%s'%(fileName,x),'wb').write(f)


#~~~~~~~~~~~~~~~~ xor operation ~~~~~~~~~~~~~~~~~~~#
time.sleep(0.9)
if os.path.exists("_%s/XOR"%(fileName)) == False:
	os.system("mkdir _%s/XOR"%(dirName))
xorRange=raw_input(g+"[+] "+yellow+"XOR operation enter the range in decimal(default 1-100): "+w)
if xorRange=="":
    xorRange="1-100"
xorRange=xorRange.split("-")
for x in range(int(xorRange[0]),int(xorRange[1])+1):
    f=bytearray(open(filePath1,'rb').read())
    for z in range(len(f)):
        f[z]^=x
    open('_%s/XOR/xorWith%s'%(fileName,x),'wb').write(f)

#~~~~~~~~~~~~~~steghide crack~~~~~~~~~~~~~~~~~~#
if fileType=="JPEG image data":
    crack=raw_input(g+"[+] "+y+"Do you want to crack this image with steghide crack(take long time)?[N/y] "+w)
    if crack.lower().startswith("y") != False:
    	if os.path.exists("_%s/steghideCrack"%(fileName)) == False:
        	os.system("mkdir _%s/steghideCrack"%(dirName))
        
        r = commands.getoutput("steghide extract -sf %s -p '' -xf _%s/steghideCrack/output.txt"%(filePath,dirName,))
        if not "no pude extraer" in r and not "could not extract" in r and not "can not uncompress data" in r:
                    print(g+"[+] "+y+"Information obtained with no password")
                    time.sleep(0.9)
                    exit(g+"[+] "+y+"Done !!")
                    
        wordlist=raw_input(g+"[+] "+y+"Enter wordlist path (default rockyou): "+w)
        if wordlist == "":
            if os.path.exists("/usr/share/wordlists/rockyou.txt")==True:
                wordlist="/usr/share/wordlists/rockyou.txt"
            else:
                exit(g+"[+] "+y+"You don't have rockyou in this path '/usr/share/wordlists/rockyou.txt'")
        if os.path.exists(wordlist) == False:
             print(g+"[+] "+y+"This wordlist path not exists '%s'"%(wordlist))
             time.sleep(0.9)
             exit(g+"[+] "+y+"Done !!")
             
        print g+"[+] "+y+"Start cracking..."
        
        max_lines = sum(1 for line in open(wordlist, 'r'))        
        i = 0
        with open(wordlist, 'r') as passFile:
            passes = passFile.readlines()
            for password in passes:
                password = password.split("\n")[0]
                output = "%*d / %d | %6.2f%% -> %s\r" % (len(str(max_lines)),i,max_lines,100 * i / max_lines,password)
                sys.stdout.write(w+output)
                sys.stdout.flush()
                if password.find("'") != -1:
                    r = commands.getoutput("steghide extract -sf %s -p \"%s\" -xf _%s/steghideCrack/output.txt" % (filePath,password,dirName))
                else:
                    r = commands.getoutput("steghide extract -sf %s -p '%s' -xf _%s/steghideCrack/output.txt" % (filePath, password,dirName))
                if not "no pude extraer" in r and not "could not extract" in r and not "can not uncompress data" in r:
                    print(g+"\n[+] "+y+"Information obtained with password:"+w+" %s" % password)
                    break
                i += 1

#~~~~~~~~~~~~~~~~~~Finsh scan~~~~~~~~~~~~~~~~#
time.sleep(0.9)
print(g+"[+] "+y+"Result saved into "+w+"_%s"%(fileName))
time.sleep(0.9)
print g+"[+] "+y+"Done !!"
