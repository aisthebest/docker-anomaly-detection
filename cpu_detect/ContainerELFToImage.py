#!/usr/bin/python
#coding=utf-8

# python getelf.py -c 容器id/容器name/镜像id（以逗号分割多个） -d 指定目录（以逗号分割）

# python getelf.py -c 68b4a7cdaf58 -d /home/,/home/jin
# container list: 68b4a7cdaf58
# directory list: /home/,/home/jin
# tmp directory: 92
# container:68b4a7cdaf58, elflist:['./92/merged/home/jin/huha', './92/merged/home/huha1', './92/merged/home/huha', './92/merged/home/jin/huha']

# python getelf.py -c f5b668f50b6e,68b4a7cdaf58 -d /home/,/home/jin
# container list: f5b668f50b6e,68b4a7cdaf58
# directory list: /home/,/home/jin
# tmp directory: 70
# ------ERROR: directory "/home/jin" does not exists in container "f5b668f50b6e"
# container:f5b668f50b6e, elflist:[]
# tmp directory: 98
# container:68b4a7cdaf58, elflist:['./98/merged/home/jin/huha', './98/merged/home/huha1', './98/merged/home/huha', './98/merged/home/jin/huha']

import sys
import getopt 
import os
import signal
import subprocess
import commands
import random

import re
import commands
import angr
import numpy as np
from PIL import Image

class CodeToImage:
	pattern = re.compile(r"\[\s*[0-9]+\]\s+(\S+)\s+[A-Z]+\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+(AX)\s+[0-9 ]+\n")
	entryp = re.compile(r"\s*Entry point address\:\s+0x([0-9a-f]+)\n");
	READELF = "readelf -S "
	GETENTRYP = "readelf -h "
	argv = []
	list = []
	binCon = None
	MAX_LENGTH = 50000 * 1024
	IMAGE_WIDTH = [
		[10 * 1024, 32], 	[30 * 1024, 64], 	[60 * 1024, 128],
		[100 * 1024, 256], 	[200 * 1024, 384], 	[500 * 1024, 512],
		[1000 * 1024, 768],	[MAX_LENGTH, 1024]
	]
	image = None
	image_array = None
	im = None
	
	def __init__(self, argv):
		self.argv = argv
	
	def help(self):
		print "usage: python ",self.argv[0]," program imageFilePath(store created image)."

	def GetElfInfo(self):
		fp = None
		try:
			if(len(self.argv) < 3):
				self.help()
				return -1
			proj = angr.Project(self.argv[1], auto_load_libs = False)
			obj = proj.loader.main_object
			sort_list = obj.sections.__dict__["_sorted_list"]
			self.list = []
			for i in sort_list:
				if i.is_executable is True:
					self.list.append((i.__dict__["name"], str(hex(i.__dict__["offset"])), str(hex(i.__dict__["filesize"]))));
			if(len(self.list) < 1):
				self.list = str(hex(proj.entry))
				if(len(self.list) < 1):
					print "ERROR: No entry point found!"
					return -1
				stat = os.stat(self.argv[1])
				entrypoint = int(self.list[len(self.list) - 1], 16)
				print "Not section found! Convert the whole binary from entry point(0x%x) to the end(0x%x)." %(entrypoint, stat.st_size + 0x8048000)
				self.list = []
				self.list.append(("entry_to_end", str(hex(entrypoint - 0x8048000)), str(hex(stat.st_size + 0x8048000 - entrypoint))))
				
			for l in self.list:
				print "%s,%s,%s" %(l[0], l[1], l[2])
			return self.list
		except Exception as e:
			print "ERROR: file not exist or something else happend!"
			return -1
		finally:
			if(fp != None):
				fp.close()
		return 0
			
	def readBin(self, start, off):
		self.binCon = []
		fp = None
		try:
			if(start < 0):
				print "start is smaller than 0!"
				start = 0
			size = os.stat(self.argv[1]).st_size
			if(size < start + off):
				print "0x%x+0x%x is bigger than file.size(0x%x)!" %(start, off, size)
				off = size - start
			fp = open(self.argv[1], 'rb')
			fp.seek(start, 0)
			st = fp.read(off)
			for i in st:
				self.binCon.append(ord(i))
			#	print"%x" %(ord(self.binCon[i])),
		except Exception as e:
			print "something else happend!"
			return -1
		finally:
			if(fp != None):
				fp.close()
		return 0
		
	def run(self):
		if(self.GetElfInfo() < 0):
			print "GetElfInfo error!"
			return -1
		sum = 0x0;
		for l in self.list:
			sum += int(l[2], 16)
		print "sum = 0x%x" %(sum)
		w_size = 1024
		for w in self.IMAGE_WIDTH:
			if(sum <= w[0]):
				w_size = w[1]
				break
		print "width = %d" %(w_size)
		self.image = []
		for l in self.list:
			if(self.readBin(int(l[1], 16), int(l[2], 16)) < 0):
				print "readBin erro!"
				return -1
			
			length = len(self.binCon)
			if(length <= 0):
				continue
			for i in range(length / w_size + 1):
				tl = ['0'] * ((i + 1) * w_size - length)
				self.image.append(self.binCon[i * w_size : (i + 1) * w_size] + tl)
				#print len(self.image[i])
				#self.image.append(self.binCon[i * w_size : (i + 1) * w_size] + '\0' * ((i + 1) * w_size - length))
		print "total columns is %d" %(len(self.image))
		print "image is creating!"
		self.image_array = np.uint8(self.image)
		self.im = Image.fromarray(self.image_array)
		print "done!"
		# print("self.argv[2]",self.argv[2])
		self.im.save(self.argv[2])
		#self.im.show()
		
def overlay2_dir2elf(icid, dirnamearg):
	print 'tmp directory:',icid
	command = "docker inspect -f '{{.GraphDriver.Data.LowerDir}},{{.GraphDriver.Data.UpperDir}}' %s" % (icid) 
	fp = os.popen(command, "r")
	dirret = fp.read()
	mountdirlist = []##lowerdir,upperdir
	for mountnum, mountdir in enumerate(dirret.split(","), 1):
		mountdirlist.append(mountdir.strip('\n'))

	if mountdirlist[0] == '<no value>':##镜像id，没有lowerdir
		mountc = "mkdir ./%s && mkdir ./%s/upper ./%s/work ./%s/merged \
		&& mount -t overlay overlay -o lowerdir=%s,upperdir=./%s/upper,workdir=./%s/work ./%s/merged" \
		% (icid, icid, icid, icid, mountdirlist[1], icid, icid, icid)
		os.popen(mountc)
	else:##容器id/name
		lowerdirs = "%s:%s" % (mountdirlist[1], mountdirlist[0])##将lowerdir和upperdir拼接为mount时的lowerdir，只读，不破坏原有容器
		mountc = "mkdir ./%s && mkdir ./%s/upper ./%s/work ./%s/merged \
		&& mount -t overlay overlay -o lowerdir=%s,upperdir=./%s/upper,workdir=./%s/work ./%s/merged" \
		% (icid, icid, icid, icid, lowerdirs, icid, icid, icid,)
		os.popen(mountc)

	elflist = []
	for dirnum, dirname in enumerate(dirnamearg.split(","), 1):
		path="./%s/merged%s" % (icid, dirname)
		isExists = os.path.exists(path)
		if not isExists:
			print '------ERROR: directory "%s" does not exists in container "%s"' % (dirname, icid)
			continue
		else:
			mergeddir = "./%s/merged%s" % (icid, dirname)##provide path like: ['./tmpdir/merged/$dirname/elfname',xxxxx]
			findelfc = "find %s -type f -exec file {} \; | grep '\<ELF\>' |awk -F ':' '{print $1}'" % (mergeddir)
			findelfret = os.popen(findelfc, "r")
			for elfnum, elf in enumerate(findelfret, 1):
				elflist.append(elf.strip('\n'))
	print 'container:%s, elflist:%s' % (icid, elflist)
	try:
		result = "./result"
		isExists = os.path.exists(result)
		if not isExists:
			os.makedirs(result)
		else:
			for root, dirs, files in os.walk(result, topdown=False):
				for item in files:
					os.remove(root + "/" + item)
		for item in elflist:
			_argv = [sys.argv[0], item]
			loc = result + "/"
			for i in item:
				if i == '.' or i == '/':
					loc += "_"
				else:
					loc += i
			loc += ".png"
			_argv.append(loc)
			cti = CodeToImage(_argv)
			cti.run()
	except Exception as e:
		print "something wrong happend!"
	finally:
		##分析完elf后，需要取消临时目录的挂载并删除该临时目录
		cleanc = "umount ./%s/merged && rm -fr %s" % (icid, icid)
		os.popen(cleanc)
	return

def overlay_dir2elf(icid, dirnamearg):
	command = "docker inspect -f '{{.GraphDriver.Data.RootDir}}' %s" % (icid) 
	fp = os.popen(command, "r")
	rootdir = fp.read().strip('\n')
	if rootdir!="<no value>":##输入的是镜像id，只有rootdir一层
		elflist = []
		for dirnum, dirname in enumerate(dirnamearg.split(","), 1):
			path=rootdir+dirname
			isExists = os.path.exists(path)
			if not isExists:
				print '------ERROR: directory "%s" does not exists in container "%s"' % (dirname, icid)
				continue
			else:
				findelfc = "find %s -type f -exec file {} \; | grep '\<ELF\>' |awk -F ':' '{print $1}'" % (path)
				findelfret = os.popen(findelfc, "r")
				for elfnum, elf in enumerate(findelfret, 1):
					elflist.append(elf.strip('\n'))
		print 'container:%s, elflist:%s' % (icid, elflist)
	else:##输入的是容器id/name
		command = "docker inspect -f '{{.GraphDriver.Data.MergedDir}}' %s" % (icid) 
		fp = os.popen(command, "r")
		mergeddir = fp.read().strip('\n')
		elflist = []
		for dirnum, dirname in enumerate(dirnamearg.split(","), 1):
			path=mergeddir+dirname
			isExists = os.path.exists(path)
			if not isExists:
				print '------ERROR: directory "%s" does not exists in container "%s"' % (dirname, icid)
				continue
			else:
				findelfc = "find %s -type f -exec file {} \; | grep '\<ELF\>' |awk -F ':' '{print $1}'" % (path)
				findelfret = os.popen(findelfc, "r")
				for elfnum, elf in enumerate(findelfret, 1):
					elflist.append(elf.strip('\n'))
		print 'container:%s, elflist:%s' % (icid, elflist)
	##开始分析
	try:
		result = "./result"
		isExists = os.path.exists(result)
		if not isExists:
			os.makedirs(result)
		else:
			for root, dirs, files in os.walk(result, topdown=False):
				for item in files:
					os.remove(root + "/" + item)
		for item in elflist:
			picnames=item.split('/')[item.split('/').index('overlay')+2:]
			picname=""
			picname+="__"+icid
			for i in picnames:
				picname+="/"+i
			_argv = [sys.argv[0], item]
			loc = result + "/"
			for i in picname:
				if i == '.' or i == '/':
					loc += "_"
				else:
					loc += i
			loc += ".png"
			_argv.append(loc)
			cti = CodeToImage(_argv)
			cti.run()
	except Exception as e:
		print "something wrong happend!"
	# finally:
	# 	##分析完elf后，需要取消临时目录的挂载并删除该临时目录
	# 	cleanc = "umount ./%s/merged && rm -fr %s" % (icid, icid)
	# 	os.popen(cleanc)
	return

def main(argv):
	contlist = ''
	dirname = ''
	dirnamearg = ''
	try:
		opts, args = getopt.getopt(argv,"hc:d:")
	except getopt.GetoptError:
		print 'usage: getelf.py -c <container id> -d <container dirname>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'usage: getelf.py -c <container id> -d <container dirname>'
			sys.exit()
		elif opt == '-c':
			contlist = arg
		elif opt == '-d':
			dirnamearg = arg
	print 'container list:', contlist 
	print 'directory list:', dirnamearg

	##获取主机上所有容器id/name/镜像id
	lcontlist = []
	command = os.popen("docker ps -a| awk 'NR==2,NR==0 {print $1,$NF}'", "r") #所有容器id/name 
	for lcontnum, lcont in enumerate(command, 1):#lcont:68b4a7cdaf58 mysql
		lcontlist.append(lcont.split(" ")[0])
		lcontlist.append(lcont.split(" ")[1].strip('\n'))

	#print '\n', lcontlist
	command = os.popen("docker images | awk 'NR==1 {for(i=1;i<=NF;i++)if($i~/IMAGE/)n=i} NR>1 {print $n}'", "r") #容器镜像id
	for lcontnum, lcont in enumerate(command, 1):
		lcontlist.append(lcont.strip('\n'))
	#print '\n', lcontlist

	##获取主机docker存储驱动
	fp=os.popen("docker info |grep Storage","r")
	driver=fp.read().split(' ')[-1].strip('\n')
	# print driver

	for contnum, icid in enumerate(contlist.split(","), 1):
		if icid in lcontlist: #如果容器id/name/镜像id存在，则查看相应目录下elf
			if driver=="overlay":
				overlay_dir2elf(icid,dirnamearg)
			elif driver=="overlay2":
				overlay2_dir2elf(icid, dirnamearg)
		else:
			print '------ERROR : The image or container : %s does not exists' % (icid)
			continue
		
if __name__ == "__main__":
	main(sys.argv[1:])