#!/bin/sh
# set n to 1
n=1

# continue until $n equals 5
while [ $n -le 2000 ]
do
	./pfexec id 
	n=$(( n+1 ))	 # increments $n
done
