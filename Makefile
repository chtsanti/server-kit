include Variables.mak

SSL_CXXFLAGS=$(LIBOPENSSL_CFLAGS)
SSL_LIBS=$(LIBOPENSSL_LIBS)
# SSL_OBJS=../tlsclient/openssl.o ../openssl/libopenssl_tools.a
SSL_OBJS=
SSL_SRC=openssl/TlsAcceptor.cc openssl/TLSutils.cc

all: server

SERVER_SRC= Connection.cc DnsResolver.cc ConnectionOpener.cc EventLoop.cc Bio.cc server.cc proc_utils.cc Config.cc Debug.cc mem.cc utils.cc $(SSL_SRC) AccessLog.cc


SERVER_OBJS=$(SERVER_SRC:%.cc=%.o)
$(SERVER_OBJS): %.o: %.cc
	$(CXX) -c -I . $(CXXFLAGS) $(SSL_CXXFLAGS) $< -o $@

server: $(SERVER_OBJS) $(SSL_OBJS)
	$(LINK) -o $@ $(SERVER_OBJS) $(SSL_OBJS) -levent -lpthread $(SSL_LIBS)

ALL_SRC=$(SERVER_SRC)

ALL_DS=$(ALL_SRC:%.cc=%.d)
include $(ALL_DS)
$(ALL_DS): %.d : %.cc
	$(CXX) -I. $(CXXFLAGS) $(SSL_CXXFLAGS) -MM $< > $@

clean:
	rm $(ALL_DS) $(SERVER_OBJS) server
