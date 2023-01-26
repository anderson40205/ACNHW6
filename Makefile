all:prog
prog:traceroute.o
	gcc traceroute.o -o prog
traceroute.o:traceroute.c
	gcc -c traceroute.c -o traceroute.o
clean:
	rm *.o prog