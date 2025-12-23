CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lcryptopp

TARGET = cipher_program
SRC = cipher_program.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
