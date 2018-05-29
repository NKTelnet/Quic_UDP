obj-m += crystal.o

KDIR := /root/rpmbuild/SOURCES/linux-3.10.0-327.36.3.el7/

PWD := $(shell pwd)

all:
	$(RM) -rf $(PWD)/scripts
	ln -s $(KDIR)/scripts $(PWD)/scripts
	$(MAKE) -C $(KDIR) M=$(PWD) $(KDIR).config modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
