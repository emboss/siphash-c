#!/bin/bash
case `uname` in
    *[Ll]inux*) ldpath=LD_LIBRARY_PATH;;
    *[Dd]arwin*) ldpath=DYLD_LIBRARY_PATH;;
    *) ldpath=;;
esac
eval ${ldpath:+$ldpath=../src:\$$ldpath} ./test
