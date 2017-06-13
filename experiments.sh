#!/bin/bash

for i in {1..20}; do bin/runtests -N -i 100000 -n 3 >> results; done
for i in {1..20}; do bin/runtests -N -i 100000 -n 5 >> results; done
for i in {1..20}; do bin/runtests -N -i 100000 -n 7 >> results; done
for i in {1..20}; do bin/runtests -S -i 100000 -k 3 >> results; done
for i in {1..20}; do bin/runtests -S -i 100000 -k 5 >> results; done
for i in {1..20}; do bin/runtests -S -i 100000 -k 7 >> results; done
for i in {1..20}; do bin/runtests -P -p key.pub >> results; done
