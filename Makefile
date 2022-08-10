EXTRA_CFLAGS+= -I$(src)/includes
#CFLAGS_fake.o:= -m32 -Wa,-32
EXTRA_LDFLAGS+= -s
intercept-y += main.o fake.o misc.o procfs.o syscalls.o hash.o cdev.o fifo.o
obj-m += intercept.o
