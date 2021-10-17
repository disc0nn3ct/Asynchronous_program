#!/bin/bash
# time for i in {1..3}
# do echo "$i"
# build/./socks5_client &
# done
# wait
############################################
# build/./socks5_client & build/./socks5_client && fg


function make_it_parallel {
for i in {$(seq 1 $1)
do 
echo $i
# ls &
build/./socks5_client &
done 
wait

}

 

rm log.txt
for k in 1 2 3 4 5 6 7 8 15 30 50 
do 
echo $k >> log.txt
{ time make_it_parallel $k ; } 2>> log.txt

done

