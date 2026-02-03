#!/bin/bash

./build/skeleton -l 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30 -n 4 --master-lcore=0 -w 4b:00.1,rxq_cqe_comp_en=1,mprq_en=1,rxqs_min_mprq=1,mprq_max_memcpy_len=128,txq_inline_max=64,txq_inline_mpw=64,mprq_log_stride_num=8 --socket-mem=8192,0
