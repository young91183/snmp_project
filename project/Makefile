CC = g++
CFLAGS = -c -std=c++17
LFLAGS = -lpthread -lmysqlclient -lnetsnmp
OBJECTS = main.o Interface_Info.o Traffic_Info.o EQPT_Info.o 

net_info: $(OBJECTS)
	$(CC) $(OBJECTS) -g -o net_info $(LFLAGS)

Interface_Info.o: Interface_Info/Interface_Info.cpp
	$(CC) $(CFLAGS) Interface_Info/Interface_Info.cpp

Traffic_Info.o: Traffic_Info/Traffic_Info.cpp
	$(CC) $(CFLAGS) Traffic_Info/Traffic_Info.cpp

EQPT_Info.o: EQPT_Info/EQPT_Info.cpp
	$(CC) $(CFLAGS) EQPT_Info/EQPT_Info.cpp

main.o: main.cpp
	$(CC) $(CFLAGS) main.cpp

clean:
	rm -rf *o
