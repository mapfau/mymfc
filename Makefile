CXX = g++
HEADERS = system.h main.h xbmcstubs.h LinuxC1Codec.h Log.h BitstreamConverter.h DVDVideoCodecC1.h
OBJ = main.o LinuxC1Codec.o Log.o BitstreamConverter.o DVDVideoCodecC1.o
CXXFLAGS = -g -Wall -std=c++11
LIBS = -lavformat -lavcodec -lavutil -lpthread -lswresample -lz -llzma -lbz2 -lopus  -L/usr/lib/aml_libs -lamcodec -lamadec -lasound -lamavutils

%.o: %.cpp $(HEADERS)
	$(CXX) -o $@ -c $< $(CXXFLAGS)

mymfc: $(OBJ)
	$(CXX) -o $@ $^ $(LIBS)

clean:
	-rm -f $(OBJ)
	-rm -f mymfc
