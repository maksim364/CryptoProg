CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lcryptopp

TARGET = hash_program
SRC = hash_program.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
