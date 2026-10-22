#!/bin/bash -l
cd /home/vmuser/LME
date -u +%FT%TZ > /home/vmuser/install.start
NON_INTERACTIVE=true AUTO_CREATE_ENV=true ./install.sh --offline -g /opt/lme-storage
echo $? > /home/vmuser/install.rc
date -u +%FT%TZ > /home/vmuser/install.end
