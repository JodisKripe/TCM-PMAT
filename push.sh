#!/bin/bash
#
if [ $# -lt 1 ]
then
	echo "Commit message missing"
else
	cp ~/Desktop/PMAT/PMATNotes.ctb .
	git add *
	git commit -am "$1"
	git push
fi
