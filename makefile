SRC = src
INC = inc
BUILD = build
BIN = bin

CC = g++
CFLAGS = -std=c++17 -I $(INC)/ -lbfd

_OBJ = loader_demo.o Loader.o
OBJ = $(patsubst %, $(BUILD)/%, $(_OBJ))
TARGET = loader_demo

$(BUILD)/%.o: $(SRC)/%.cc
	$(CC) -c -o $@ $< $(CFLAGS)

$(BIN)/$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(BUILD)/*.o
	rm -f $(BIN)/$(TARGET)