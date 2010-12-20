#!/bin/sh

perl util/wiki2pod.pl README.wiki > /tmp/a.pod && pod2text /tmp/a.pod > README

perl util/wiki2pod.pl README.wiki > /tmp/a.pod && pod2html /tmp/a.pod > README.html
