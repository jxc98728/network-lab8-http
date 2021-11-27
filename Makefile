ifeq ($(OS), Windows_NT)
	CXX = clang++
else
	CXX = g++
endif

ifeq ($(OS), Windows_NT)
	CXXLIBS = -lws2_32
else
	CXXLIBS = -lpthread
endif

ifeq ($(OS), Windows_NT)
	EXE = server.exe
else
	EXE = server
endif

CXXFLAGS = -Wall -std=c++11

all: $(EXE)

$(EXE): src/main.cpp
	$(CXX) $(CXXFLAGS) src/main.cpp -o $(EXE) $(CXXLIBS)

.PHONY: clean
clean:
ifeq ($(OS), Windows_NT)
	del /f /q $(EXE)
else
	rm -rf $(EXE)
endif
