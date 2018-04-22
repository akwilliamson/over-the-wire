#!/usr/bin/expect -f
log_user 0
set prompt "$ "
set SSH_HOST [lindex $argv 0];
set SSH_PORT [lindex $argv 1];
set SSH_USER [lindex $argv 2];
set SSH_PASS [lindex $argv 3];
set SSH_CMD  [lindex $argv 4];

spawn ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=keyboard-interactive,password -o PubkeyAuthentication=no ${SSH_USER}@${SSH_HOST} -p ${SSH_PORT}
expect "password:"
send "${SSH_PASS}\r"
expect $prompt
send "clear\r"
send "${SSH_CMD}\r"
expect $prompt
expect "\n"
expect "\n"
set line $expect_out(buffer)
puts $line
expect $prompt
send "exit\r"
return 0