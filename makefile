SRC = src
INC = inc
BUILD = build
BIN = bin

CC = gcc
CXX = g++
CFLAGS = -std=c++17 -I $(INC)/ -lbfd -lcapstone

_TARGET = loader_demo basic_capstone_liner basic_capstone_recursive
TARGET = $(patsubst %, $(BIN)/%, $(_TARGET))

$(shell if [ ! -d $(BUILD) ]; then mkdir -p $(BUILD); fi)
$(shell if [ ! -d $(BIN) ]; then mkdir -p $(BIN); fi)

.PHONY: all clean

all: $(TARGET)

$(BUILD)/%.o: $(SRC)/%.cc
	$(CXX) -c -o $@ $< $(CFLAGS)

$(BIN)/loader_demo: $(BUILD)/Loader.o $(BUILD)/loader_demo.o
	$(CXX) -o $@ $^ $(CFLAGS)

$(BIN)/basic_capstone_liner: $(BUILD)/Loader.o $(BUILD)/basic_capstone_liner.o
	$(CXX) -o $@ $^ $(CFLAGS)

$(BIN)/basic_capstone_recursive: $(BUILD)/Loader.o $(BUILD)/basic_capstone_recursive.o
	$(CXX) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(BUILD)/*.o
	rm -f $(BIN)/*