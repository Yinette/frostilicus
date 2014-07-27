#!/usr/bin/env python

import os
import sys
import datetime as dt
import mmap
import time
import re
import argparse
import hashlib
from time import sleep
from butter.fanotify import *

parser = argparse.ArgumentParser()
parser.add_argument("directory", help="The directory to Scan.")
parser.add_argument('-p','--passive', help="Enables Passive mode, waits for file changes/creations before scanning. Uses the FNOTIFY syscall", action="store_true") 
parser.add_argument('-v','--verbose', help="Will run frostilicus verbosely.", action="store_true")
parser.add_argument('-f','--freeze', help="Will chmod 000 files with a score of 10 or above", action="store_true")
parser.add_argument('-d','--days', help="How many days to search for activity from, defaults to 1", default="1")
args = parser.parse_args()

def scan_files():
	"""
		Looks for files modified in the last 24 hours in a directory passed as an argument
	"""
	now=dt.datetime.now()
	ago=now-dt.timedelta(days=int(args.days))

	matches = []
	for root,dirs,files in os.walk(args.directory, followlinks=False, onerror=None):
		for fname in files:
			path=os.path.join(root,fname)
			if not empty(path) and os.path.exists(path):
					st=os.lstat(path)
					mtime=dt.datetime.fromtimestamp(st.st_mtime)
					if mtime>ago:
						matches.append(path)
						if args.verbose:
							print path
	return matches

def find_mount(mount):
	"""
		Finds the mountpoint of a given directory.
	"""
	mount = os.path.abspath(mount)
	while not os.path.ismount(mount):
		mount = os.path.dirname(mount)
	return mount


def scan_pasv():
	"""
		Scans files passively using the FANOTIFY syscall available in Linux Kernel 2.6.38 and above.
	"""
	mntpoint = find_mount(args.directory)
	notifier = Fanotify(FAN_CLASS_NOTIF)
	flags = FAN_CLOSE_WRITE
	notifier.watch(FAN_MARK_MOUNT, flags, mntpoint)
	
	for event in notifier:
		if event.filename.startswith(args.directory):
			yield event.filename
			#TODO: check compat with changing file descriptors


def empty(fname):
	"""
		Return True if file has something in it, returns false if empty
	"""
	st=os.lstat(fname)
	if st.st_size == 0:
		return True
	else:
		return False

def line_length(fname, l):
	"""
		Find the first line longer than (or equal to) defined variable
	"""
	f = open(fname, 'r')
	for line in f:
		if len(line) >= l:
			return True
	return False

def SCAN_b64withlen(fname):
	"""
		This takes a file, looks for the string "base64_decode" and reports back if there is a line in this file over 700 characters long.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if s.find('base64_decode') >= 0 and line_length(fname, 700):
		f.close()
		return True
	f.close()
	return False

def SCAN_b64hexwithlen(fname):
	"""
		This takes a file, looks for the string "base64_decode" in escaped Hexadecimal ASCII and reports back if there is a line in this file over 700 characters long.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if s.find('x62\x61\x73\x65\x36\x34\x5F\x64\x65\x63\x6F\x64\x65') >= 0 and line_length(fname, 700):
		f.close()
		return True
	f.close()
	return False

def SCAN_gifwithphp(fname):
	"""
		This looks for a .gif header (GIF89a) and a PHP header (<?php) in the same file.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if s.find('GIF89a') >= 0 and s.find('<?php') >=0:
		f.close()
		return True
	f.close()
	return False
	
def SCAN_RodecapBot(fname):
	"""
		This looks for a string common to Rodecap Trojan's PHP files used to propagate Spam.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if s.find('die(PHP_OS.chr(49).chr(48).chr(43).md5(0987654321));') >= 0:
		f.close()
		return True
	f.close()
	return False
	
def SCAN_c99injector(fname):
	"""
		This looks for the c99 family of PHP shells, a fairly common type encountered on the internet.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if s.find('/* c99 injector') >= 0 or s.find('$c99sh_updateurl') >= 0 or s.find('$c99sh_sourcesurl') >=0:
		f.close()
		return True
	f.close()
	return False

def SCAN_backdoors(fname):
	"""
		This looks for values commonly attributed to perl backdoors built into web shells like c99, r57 and WSO.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if s.find('$back_connect') >= 0 or s.find('$datapipe_') >= 0 or s.find('port_bind_bd_pl') >=0:
		f.close()
		return True
	f.close()
	return False

def SCAN_longlinephp(fname):
	"""
		This looks for .php files that are 1~6 lines long with a line that is longer than 700 Characters.
	"""
	if not empty(fname):
		if fname.endswith(".php"):
			line_greater_700 = line_length(fname, 700)
			f = open(fname, 'r')
			for i, line in enumerate(f):
				pass
			if i <= 6 and line_greater_700:
				f.close()
				return True
			f.close()
	return False

def SCAN_nestedelf(fname):
	"""
		Looks for nested ELF binaries in .php files...  pretty good indicator of something amiss. Known as "Linux/Mayhem" July 2014.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if fname.endswith(".php"):
		if s.find("\\x7f\\x45\\x4c\\x46\\x02\\x01\\x01\\x00\\x00\\x00\\x00") >= 0:
			f.close()
			return True
		f.close()
		return False
	return False

def SCAN_phpinj(fname):
	"""
		Looks for eval(base64_decode($_POST['<STRING>'])); at the top of files, used in nested PHP attacks on otherwise legit pages.
	"""
	f = open(fname, 'r')
	s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
	if fname.endswith(".php"):
		if s.find("eval(base64_decode($_POST") >= 0:
			f.close()
			return True
		f.close
		return False
	return False

def SCAN_i59spambot(fname):
	"""
		Looks for the i59 spambots
	"""
	if not empty(fname):
		f = open(fname, 'r')
		s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
		if fname.endswith(".php"):
			if s.find('<?$i59="Euc<v#`5R1s?') >=0:
				f.close()
				return True
			f.close()
			return False
	return False


#Regex is severely broken!
def SCAN_taintedfile(fname):
	"""
		This looks for .php files that are longer than 12 lines, and contain some known exploit keywords on a line exeeding 1000 Chr.
		Basically this is searching for 'tainted' legitimate files.
	"""
	if fname.endswith(".php") and line_length(fname, 1000):
			f = open(fname, 'r')
			reg = re.compile(r'eval\(base64_decode|\\x65\\x76\\x61\\x6C\\x28|x62\\x61\\x73\\x65\\x36\\x34\\x5F\\x64\\x65\\x63\\x6F\\x64\\x65')
			for i, line in enumerate(f):
				pass
			if i >=12:
				match = reg.findall(line)
				if match:
					f.close()
					return True
			f.close()
	return False


def main():
	while True:
		if args.passive:
			files = scan_pasv()
		else:
			files = scan_files()

		for fname in files:
			hash_get = hashlib.md5(open(fname).read()).hexdigest()
			if not os.path.isfile(fname):
				continue
			if "/cache/" in fname:
				continue
			if os.path.islink(fname):
				continue
			if hash_get == 'd1c8a277f0cc128b5610db721c70eabd': #simplepie.php has some strings that frostilicus finds.
				continue
			st=os.lstat(fname)
			if st.st_size / 1024 / 1024 >= 3:
				continue
			if empty(fname):
				continue
			test_taken = False
			score = 0

			if SCAN_b64withlen(fname) == True:
				print fname, 'has a line containing base64_decode as well as a line over 700 characters! +5'
				test_taken = True
				score += 5

			if SCAN_gifwithphp(fname) == True:
				print fname, 'has both gif and PHP file headers! +10'
				test_taken = True
				score += 10

			if SCAN_RodecapBot(fname) == True:
				print fname, 'is most likely a Rodecap spambot! +10'
				test_taken = True
				score += 10

			if SCAN_c99injector(fname) == True:
				print fname, 'is most likely a c99-type PHP shell! +20'
				test_taken = True
				score += 20

			if SCAN_backdoors(fname) == True:
				print fname, 'has variables commonly used by backdoors in PHP shells! +5'
				test_taken = True
				score += 5

			if SCAN_longlinephp(fname) == True:
				print fname, 'is a 1-6 lined php file with a really huge line! +10'
				test_taken = True
				score += 10

			if SCAN_taintedfile(fname) == True:
				print fname, 'is most likely a maliciously tainted file! -15'
				test_taken = True
				score +=-15

			if SCAN_nestedelf(fname) == True:
				print fname, 'Linux/Mayhem Detected! Nested ELF library in .php script, INVESTIGATE! +15'
				test_taken = True
				score += 15

			if SCAN_phpinj(fname) == True:
				print fname, 'is a .php file with an injected eval(base64_decode($_POST string, TAINTED!'
				test_taken = True
				score += 5

			if SCAN_i59spambot(fname) == True:
				print fname, 'i59 spambot detected!'
				test_taken = True
				score +=15


			if test_taken:
				if args.freeze and score >=10:
					print "!!!!"
					print "%s has high malicious confidence - frozen!" % (fname)
					print "!!!!"
					os.chmod(fname, 0000)
				print "%s has score %d" % (fname, score)
				print '==='
		sleep(0.2)
		if not args.passive:
			break

if __name__ == '__main__':
	sys.exit(main())
