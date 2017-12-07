#!/bin/bash

for file in $(ls raw/z4); do
	lz4 -d -f raw/z4/${file} raw/new/${file%.*}.xdr
done
