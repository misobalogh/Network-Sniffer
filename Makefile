APP_NAME = NetworkSniffer
EXE = ipk-sniffer
SRC_DIR = ./src/$(APP_NAME)
TEST_DIR = ./src/$(APP_NAME).Tests
BIN = bin
OBJ = obj

.PHONY: clean build test

all: build

run: build
	./$(APP_NAME)

build: 
	dotnet publish $(SRC_DIR)/$(APP_NAME).csproj  -c Release /p:DebugType=None -o .

utest: buildTests
	dotnet test $(TEST_DIR)/$(APP_NAME).Tests.csproj

buildTests:
	dotnet build -c Debug /p:DebugType=None $(TEST_DIR)/$(APP_NAME).Tests.csproj

help: build
	./$(APP_NAME) -h

restore:
	dotnet nuget locals all --clear
	dotnet restore $(SRC_DIR).sln  --verbosity diagnostic


clear:
	dotnet nuget locals all --clear

clean:
	dotnet clean $(SRC_DIR).sln
	rm -rf $(EXE)
