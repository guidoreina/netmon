CC=g++
CXXFLAGS=-O3 -std=c++11 -Wall -pedantic -D_GNU_SOURCE -I.

# Is packet mmap version 3 available?
CXXFLAGS+=-DHAVE_TPACKET_V3

LDFLAGS=-lpthread

MAKEDEPEND=${CC} -MM
PROGRAM=netmon

OBJS = string/buffer.o util/hash.o util/parser/number.o util/parser/size.o \
       fs/file.o pcap/reader.o \
       net/parser.o net/mon/event/base.o net/mon/event/icmp.o \
       net/mon/event/udp.o net/mon/event/dns.o net/mon/event/tcp_begin.o \
       net/mon/event/tcp_data.o net/mon/event/tcp_end.o net/mon/event/writer.o \
       net/mon/dns/message.o net/mon/tcp/connection.o net/mon/worker.o \
       net/mon/workers.o net/capture/ring_buffer.o net/capture/socket.o \
       net/mon/configuration.o \
       netmon.o

DEPS:= ${OBJS:%.o=%.d}

all: $(PROGRAM)

${PROGRAM}: ${OBJS}
	${CC} ${OBJS} ${LIBS} -o $@ ${LDFLAGS}

clean:
	rm -f ${PROGRAM} ${OBJS} ${DEPS}

${OBJS} ${DEPS} ${PROGRAM} : Makefile

.PHONY : all clean

%.d : %.cpp
	${MAKEDEPEND} ${CXXFLAGS} $< -MT ${@:%.d=%.o} > $@

%.o : %.cpp
	${CC} ${CXXFLAGS} -c -o $@ $<

-include ${DEPS}
