#!/bin/bash
umask 0000

sipp -m 1 -sf /test/UAC.xml -base_cseq 1 -i 10.5.3.34 -t u1 -s 9912344321 10.5.3.35 -p 5060 -trace_stat -trace_screen -trace_msg 
