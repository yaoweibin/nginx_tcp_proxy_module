#!/bin/sh

perl util/wiki2pod.pl doc/README.wiki > /tmp/a.pod && pod2text /tmp/a.pod > doc/README.txt

perl util/wiki2pod.pl doc/README.wiki > /tmp/a.pod && pod2html /tmp/a.pod > doc/README.html

cp doc/README.txt README
