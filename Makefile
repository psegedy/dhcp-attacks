CXX=g++
CXXFLAGS=-g -pedantic -Wall -Wextra -std=c++11
SOURCES_ROGUE=rogue.cpp rogue.h
SOURCES_STARVE=starve.cpp starve.h
SOURCES_COMMON=dhcp.h checksum.cpp checksum.h
EXECUTABLES=pds-dhcprogue pds-dhcpstarve

all:$(EXECUTABLES)

pds-dhcpstarve: $(SOURCES_STARVE) $(SOURCES_COMMON)
	$(CXX) $(CXXFLAGS) $(SOURCES_STARVE) $(SOURCES_COMMON) -o $@

pds-dhcprogue: $(SOURCES_ROGUE)
	$(CXX) $(CXXFLAGS) $(SOURCES_ROGUE) $(SOURCES_COMMON) -o $@

clean:
	rm -f $(EXECUTABLES) xseged00.zip

pack:
	zip xseged00.zip $(SOURCES_STARVE) $(SOURCES_ROGUE) $(SOURCES_COMMON) \
					 dokumentace.pdf readme