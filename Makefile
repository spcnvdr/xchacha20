# A simple Makefile, to build run: make all 
TARGET	= redact

CC	= gcc
#compiler flags here
CFLAGS = -O3 -Wall -Wextra

#linker flags here
LFLAGS = -Wall

SRCDIR	= src

SOURCES	:= $(wildcard $(SRCDIR)/*.c)
INCLUDES	:= $(wildcard $(SRCDIR)/*.h))
OBJECTS	:= $(SOURCES:$(SRCDIR)/%.c=$(SRCDIR)/%.o)

.PHONY: all clean remove
all: ${TARGET}

$(TARGET): $(OBJECTS)
	@$(CC) -o $@ $(LFLAGS) $(OBJECTS)

$(OBJECTS): $(SRCDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@$ rm -f $(OBJECTS)

remove: clean
	@$ rm -f $(TARGET)
