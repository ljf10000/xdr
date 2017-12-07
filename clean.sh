#!/bin/bash

dirs="tlvs xdrs bad file/file file/cert file/http /tmp/coredump"
for dir in ${dirs}; do
	[[ -d "${dir}" ]] && {
		rmall ${dir} && echo ${dir} clean
	}
done

