obj-m += otp_lkm_module.o
otp_lkm_module-objs := base_otp.o time_otp.o otp_lkm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean