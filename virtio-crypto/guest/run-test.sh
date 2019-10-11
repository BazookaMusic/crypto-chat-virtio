#!/bin/bash

SUCC=0

for i in `seq 100`; do 
	ret=$(./test_crypto $1 | grep "Success" | wc -l)
	SUCC=$((SUCC+ret))
done

echo "SUCC = $SUCC"
