include rust.mk

all: lib iptrap

$(eval $(call RUST_CRATE,LIB,src/lib.rs))
$(eval $(call RUST_CRATE,IPTRAP,src/iptrap.rs))

$(IPTRAP_OUT): $(LIB_OUT)

lib: $(LIB_OUT)

iptrap: $(IPTRAP_OUT)

clean: $(LIB_CLEAN) $(IPTRAP_CLEAN)

.PHONY: all lib iptrap clean
