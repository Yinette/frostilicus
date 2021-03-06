# NOTE
Hi, Yin here. I wrote this a while ago now, and it is absolutely no where near perfect, unfortunately I was not able to continue work on this project beyond minor fixes or tweaks when I had a moment of time to spare and I had the spoons to commit to it.

A lot of stuff has changed in the 5 or so years this thing has been around. PHP Malware on the upper-end of scale has become far more difficult to detect using what frostilicus does. Most of the time you cannot even find "base64_decode" anywhere but in legit places these days, or just really old or primitive webshells.

Really the whole landscape has changed in a lot of ways.

If you've come across this tool, thanks for taking a look! I would strongly recommend you take a peek at some alternatives I have come across since writing this ol' thing.

  - Clamd now does FANOTIFY! (And not just mountpoint patrolling)
  - Maldet, Linux Malware Detect - https://www.rfxn.com/projects/linux-malware-detect/
    - Based on ClamAV, but has its own ruleset and detection databases, a little more hosting friendly than ClamAV for large deployments. (i.e. Shared Hosting, cPanel)

Thanks for your interest and I wish you best of luck keeping your servers safe!

---------------------------------------

FROSTILICUS
---------------------------------------

Written by: Yinette of Anchor Systems

HUGE THANKS TO: Da_Blitz for the massive help with the basic teaching of how to write Python and for the awesome
library which is used by this script.

Frostilicus is no where near what i would call "complete" please be patient as I add more features and fix bugs.
Please let me know of any issues you do find!

Frostilicus is released under BSD License, so go nuts! (but tell me about what you're working on too)

#### Requirements:

 - Linux kernel version 2.6.38+ or 3.x+ (for fanotify support)
 - Python 2.7+
 - cffi python library (and libffi-dev/libffi-devel package)

covered in depth in installation

#### Intro

Frostilicus is a python based program that can either passively or actively look for
web-based malware based on signatures found common in malicious files/malicious modifications.

It will then set chmod 0000 on files that it has 'high confidence' of being malicious.


Frostilicus will run in one of two modes:

##### ACTIVE

Will recursively find files modified in the last 24 hours and then run them through a bunch of score tests.

##### PASSIVE

On supported systems will plug into the fanotify syscall and test files as they are modified. Requires butter.

#### What Frostilicus looks for

Frostilicus operates on a scoring system based on confidence of a file being compromised.

It takes several things into account when tallying this score:

 - The inclusion of `base64_decode` on a line longer than 700 Characters.

 - The inclusion of `base64_decode` and a line that exceeds 700 Characters

 - If `GIF89a` and `<?php` exist in the same file, DEAD GIVE AWAY.

 - Common variables defined in popular PHP shells.

 - Looks for a string found in the Rodecap spam Trojan.

 - Other stuff that has not been added yet!

#### INSTALL:

Frostilicus runs best in a virtualenv, however it's perfectly fine to run this on a system as is.

The prerequisites you will require on the system are:

 - libcffi-dev
 - python-virtualenv
 - python-pip
 - build-essential
 - libpython2.7

Some of these may already be installed.

Install all these fun things first:
`apt-get install libffi-dev build-essential python-virtualenv python-pip libpython2.7`


(packages might be named different on non-debian based systems)


now, goto where you cloned frostilicus and start the virtualenv.

<pre>
$ virtualenv env  #"env" can be whatever you want to call it.
$ . env/bin/activate
</pre>
Now, inside the virtualenv:
<pre>
pip install argparse #this one might already be installed
pip install cffi
pip install butter
</pre>

Now once that's all done, you're ready to go.

`./frostilicus.py`

##### Stand Alone

Frostilicus can run stand alone without butter, however you'll need to modify the source a little.
For stand alone, just remove the `import * from butter` in the top.

I will eventually introduce a branch that will work by itself.

#### USE:

##### ACTIVE MODE

`frostilicus.py [-v,--verbose] [-f,--freeze] <DIR>`

Frostilicus will recursively search and scan files in the given directory.
Files modified in the last 24 hours will be scanned for malware.

Freeze mode will chmod 000 files that gain a score of 10+

##### PASSIVE MODE

`sudo frostilicus.py -p / --passive [-v,--verbose], [-f,--freeze] <DIR>`

NOTE: Passive mode needs to be run as root for fanotify!

Frostilicus will generate a watch on the mounted filesystem where the supplied directory lives,
and will scan files in the directory if they are Created or Modified.

