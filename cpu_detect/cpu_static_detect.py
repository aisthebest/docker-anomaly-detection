# -*- coding: utf-8 -*-
import sys
import os
import getopt 
import subprocess

def main(argv):
	subout = None
	contlist = ''
	dirname = ''
	dirnamearg = ''
	command = ''
	try:
		opts, args = getopt.getopt(argv,"hc:d:")
	except getopt.GetoptError:
		print 'usage: cpu_static_detect.py -c <container id> -d <container dirname>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'usage: cpu_static_detect.py -c <container id> -d <container dirname>'
			sys.exit()
		elif opt == '-c':
			contlist = arg
		elif opt == '-d':
			dirnamearg = arg
	print 'container:', contlist 
	print 'directory:', dirnamearg
	command = "python ContainerELFToImage.py -c %s -d %s"%(contlist,dirnamearg) #构造命令
	try:
		subp = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell=True) #运行ContainerELFToImage.py
		subout = subp.communicate()
		#print 'program ContainerELFToImage.py output:',subout
		if(subp == None):
			print 'execute ContainerELFToImage.py error'
			sys.exit()
	except Exception as e:
		print "execute ContainerELFToImage.py error!"                                       

	command = "python test.py"
	try:
		subp = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell=True) #运行test.py
		subout = subp.communicate()
		#print 'program ContainerELFToImage.py output:',subout
		if(subp == None):
			print 'execute test.py error'
			sys.exit() 
	except Exception as e:
		print "execute test.py error!"                                            

if __name__ == "__main__":
	if(len(sys.argv) < 5):
		print 'usage: cpu_static_detect.py -c <container id> -d <container dirname>'
		sys.exit()
	else:
		main(sys.argv[1:])