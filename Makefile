PLUGIN=wtmp
CPPFLAGS=-I
CC=gcc
CFLAGS=-O2 -Wall -g -m32 -lutil

all: $(PLUGIN).so

$(PLUGIN).so: $(PLUGIN).o
	@$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) -Wl,-soname,$(PLUGIN).so -o $(PLUGIN).so $(PLUGIN).o -lc -lutil

$(PLUGIN).o: $(PLUGIN).c
	@$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c $(PLUGIN).c

clean:
	-rm $(PLUGIN).so $(PLUGIN).o
