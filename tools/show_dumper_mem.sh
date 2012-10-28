#!/bin/sh
dumper_pid=`ps -ef|fgrep /dist/bin/trace_dumper|fgrep /mnt/logs|awk '{print $2}'`
file_info=`grep -nP 'dump$' /proc/"$dumper_pid"/smaps|fgrep -v warn`
echo "Output file:" `echo $file_info|awk '{print $6}'`
nlines=`echo $file_info|cut -d':' -f 1|xargs expr 9 + |cut -d' ' -f2`
head -"$nlines" "/proc/"$dumper_pid"/smaps" |tail|fgrep Dirty
