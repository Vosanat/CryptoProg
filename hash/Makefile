CC     = g++
CFLAGS = -lcryptopp
SOURCE = main.cpp
EXEC   = hash

all: $(EXEC)

$(EXEC): $(SOURCE)
	$(CC) $(SOURCE) -o $(EXEC) $(CFLAGS)

clean:
	rm -f $(EXEC)
