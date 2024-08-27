include ../Variables.mak


all: libopenssl_tools.a libboringssl_tools.a

TOOLS_SRC=TLSutils.cc CertDB.cc
COMMON_SRC=TlsDebug.cc

COMMON_OBJS=$(COMMON_SRC:%.cc=%.o)
$(COMMON_OBJS): %.o: %.cc
	$(CXX) -c $(CXXFLAGS) $< -o $@

OPENSSL_TOOLS_OBJS=$(TOOLS_SRC:%.cc=%.openssl.o)
$(OPENSSL_TOOLS_OBJS): %.openssl.o: %.cc
	$(CXX) -c $(CXXFLAGS) $(LIBOPENSSL_CFLAGS) $< -o $@

libopenssl_tools.a: $(OPENSSL_TOOLS_OBJS) $(COMMON_OBJS)
	ar -crs $@ $(OPENSSL_TOOLS_OBJS) $(COMMON_OBJS)

BORINGSSL_TOOLS_OBJS=$(TOOLS_SRC:%.cc=%.boringssl.o)
$(BORINGSSL_TOOLS_OBJS): %.boringssl.o: %.cc
	$(CXX) -c $(CXXFLAGS) $(BORINGSSL_CFLAGS) $< -o $@

libboringssl_tools.a: $(BORINGSSL_TOOLS_OBJS) $(COMMON_OBJS)
	ar -crs $@ $(BORINGSSL_TOOLS_OBJS) $(COMMON_OBJS)

ALL_SRC=$(TOOLS_SRC) $(COMMON_SRC)
ALL_DS=$(ALL_SRC:%.cc=%.d)
include $(ALL_DS)
$(ALL_DS): %.d : %.cc
	$(CXX) $(CXXFLAGS) $(SSL_CXXFLAGS) -MM $< > $@

clean:
	rm $(COMMON_OBJS) $(OPENSSL_TOOLS_OBJS) $(BORINGSSL_TOOLS_OBJS) libboringssl_tools.a libopenssl_tools.a
