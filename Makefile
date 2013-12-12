LIBS=
CC=g++
CFLAGS=-c
SOURCES=main.cpp des.cpp
ODIR=Debug
OBJECTS=$(SOURCES:%.cpp=$(ODIR)/%.o)
EXECUTABLE=des

all: $(SOURCES) $(EXECUTABLE)

$(ODIR)/%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) -o $(EXECUTABLE) $(LIBS)

clean:
	-rm -rf $(ODIR)/*.o $(EXECUTABLE)

