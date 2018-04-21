#!/bin/bash

SSH_HOST="bandit.labs.overthewire.org"
SSH_PORT="2220"
SSH_PASS="bandit0"

set_password(){
    user=${1}
    pass=${2}
    cmd=${3}
    SSH_PASS=$(./remote.ssh.sh ${SSH_HOST} ${SSH_PORT} ${user} ${pass} "${cmd}" | tr -d '\n' | tr -d '\r')
    echo "Retrieved password from ${user} :" ${SSH_PASS}
}

# The password for the next level is stored in a file called readme located in the home directory. 
set_password "bandit0" ${SSH_PASS} "cat readme"

# The password for the next level is stored in a file called - located in the home directory
set_password "bandit1" ${SSH_PASS} "cat ./-"

# The password for the next level is stored in a file called spaces in this filename located in the home directory
set_password "bandit2" ${SSH_PASS} "cat spaces\ in\ this\ filename"

# The password for the next level is stored in a hidden file in the inhere directory.
set_password "bandit3" ${SSH_PASS} "cat ./inhere/.hidden"

# The password for the next level is stored in the only human-readable file in the inhere directory.
set_password "bandit4" ${SSH_PASS} "find . | grep '\-file' | xargs file | grep 'ASCII' | awk -F ':' '{print \$1}' | xargs cat"

# The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:
    # human-readable
    # 1033 bytes in size
    # not executable
set_password "bandit5" ${SSH_PASS} "find . -type f -size 1033c -name '[[:print:]]*' ! -executable | xargs cat"

# The password for the next level is stored somewhere on the server and has all of the following properties:
    # owned by user bandit7
    # owned by group bandit6
    # 33 bytes in size
set_password "bandit6" ${SSH_PASS} "find / -type f -size 33c -user bandit7 -group bandit6 2>&1 | grep -v 'Permission denied' | grep -v 'No such file or directory' | xargs cat"

# The password for the next level is stored in the file data.txt next to the word millionth
set_password "bandit7" ${SSH_PASS} "cat ./data.txt | grep 'millionth' | awk '{print \$2}'"

# The password for the next level is stored in the file data.txt and is the only line of text that occurs only once
set_password "bandit8" ${SSH_PASS} "cat data.txt | sort | uniq -u"

# The password for the next level is stored in the file data.txt in one of the few human-readable strings, beginning with several ‘=’ characters.
set_password "bandit9" ${SSH_PASS} "tr -cd '[:print:]\n' < data.txt | grep '========== ' | awk -F '========== ' '{print \$2}' | tail -1"

# The password for the next level is stored in the file data.txt, which contains base64 encoded data
set_password "bandit10" ${SSH_PASS} "cat data.txt | base64 --decode | awk -F 'The password is ' '{print \$2}'"

# The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions
set_password "bandit11" ${SSH_PASS} "cat data.txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]' | awk -F 'The password is ' '{print \$2}'"

# The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. 
set_password "bandit12" ${SSH_PASS} "rm -rf /tmp/krashid \
&& mkdir /tmp/krashid \
&& xxd -r data.txt > /tmp/krashid/bandit.gz \
&& cd /tmp/krashid/ \
&& gzip -d bandit.gz && mv bandit bandit.bz2\
&& bzip2 -d bandit.bz2 && mv bandit bandit.gz \
&& gzip -d bandit.gz \
&& tar -xvf bandit > /dev/null 2>&1 && rm -rf bandit \
&& tar -xvf data5.bin > /dev/null 2>&1 && rm -rf data5.bin \
&& bzip2 -d data6.bin > /dev/null 2>&1 \
&& tar -xvf data6.bin.out > /dev/null 2>&1 && rm -rf data6.bin.out \
&& mv data8.bin data8.gz \
&& gzip -d data8.gz > /dev/null 2>&1 \
&& cd ~ \
&& cat /tmp/krashid/data8 | awk -F 'The password is ' '{print \$2}'
"
# The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on
set_password "bandit13" ${SSH_PASS} "ssh -o StrictHostKeyChecking=no -i ./sshkey.private bandit14@localhost 2>/dev/null cat /etc/bandit_pass/bandit14"

# The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.
set_password "bandit14" ${SSH_PASS} "echo ${SSH_PASS} | nc localhost 30000 | sed -n 2p"

# The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption.
set_password "bandit15" ${SSH_PASS} "echo ${SSH_PASS} | openssl s_client -connect localhost:30001 -ign_eof 2>/dev/null | sed -n '/Correct!/{n;p}'"
