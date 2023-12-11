CC     	= g++
FLAGS 	= -std=c++14 -Wall -DNDEBUG
CFLAGS  = -lcryptopp
SOURCE  = main.cpp
EXEC    = crypt

all: $(EXEC)

$(EXEC): $(SOURCE)
	$(CC) $(FLAGS) $(SOURCE) -o $(EXEC) $(CFLAGS)

clean:
	rm -f $(EXEC)
