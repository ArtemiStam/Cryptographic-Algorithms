###################################################
#
# file: Makefile
#
# @Author:   Artemisia Stamataki
# @Version:  21-03-2024
# @email:    csd4742@csd.uoc.gr
#
# Makefile
#
####################################################

CC = gcc
CFLAGS = -Wall -pedantic

all: tests

tests: tests.o cs457_crypto.o
	$(CC) $(CFLAGS) $^ -o a.out

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm -f *.out *.o