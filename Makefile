#invoke make inside following directories and in this order: loader, launch, fib
#move the lib_simpleloader.so and launch binaries inside bin directory
#Provide the command for cleanup

all:
	make -C loader
	make -C launcher
	make -C test

clean:
	make -C loader clean
	make -C launcher clean
	make -C test clean