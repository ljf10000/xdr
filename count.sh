#!/bin/bash

dirs="tlvs xdrs bad file/file file/http file/cert"

main() {
	for dir in ${dirs}; do
		echo -n "${dir}: "; ls ${dir} | wc -l
	done
}

main "$@"
