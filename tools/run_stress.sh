#!/bin/sh

echo Running dumper stress
../../../build/common/traces/tools/dumper_stress "$@" &
stress_pid=$!
echo dumper_stress started, pid= $stress_pid

out_file="/mnt/logs/stress_"$stress_pid".dump"
warnings_file="/mnt/logs/stress_"$stress_pid"_warnings.dump"
echo trace_dumper -p $stress_pid -w$out_file
trace_dumper -p $stress_pid -w$out_file -N$warnings_file &
dumper_pid=$!
echo dumper started, pid= $dumper_pid
wait "$stress_pid"
echo Stress process ended
wait "$dumper_pid"
dumper_ret=$?
echo Dumper process ended with status $dumper_ret, running stats ...

xn-trace-reader -s $out_file
