#Compile the launch.c by linking it with the lib_simpleloader.so
all:
	gcc -m32 -c launch.c -o ../bin/launch.o
	gcc -m32 -o ../bin/launch ../bin/launch.o -L../bin -l_simpleloader

#Provide the command for cleanup
clean:
	-@rm -f ../bin/launch.o
	-@rm -f ../bin/launch