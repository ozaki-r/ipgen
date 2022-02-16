
SUBDIRS := libpkt libaddrlist gen script htdocs

.PHONY: all $(SUBDIRS)

all clean cleandir depend install: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
