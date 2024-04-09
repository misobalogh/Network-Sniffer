APP_NAME = NetworkSniffer
SRC_DIR = ./src/$(APP_NAME)
TEST_DIR = ./src/$(APP_NAME).Tests
BIN = bin
OBJ = obj

.PHONY: clean build test

all: build

build: 
	dotnet publish -c Release /p:DebugType=None -o .

help: build
	./$(APP_NAME) -h

restore:
	dotnet nuget locals all --clear
	dotnet restore --verbosity diagnostic

clear:
	dotnet nuget locals all --clear

clean:
	dotnet clean
