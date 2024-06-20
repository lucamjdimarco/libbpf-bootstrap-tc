# Define the compiler to use
CPP = g++
CC = gcc

FLAGS = -Wall

# -lstdc++ is a linker option in the GCC compiler that links the C++ standard
# library (libstdc++) with the compiled executable. This option tells the linker
# to include the necessary C++ standard library functions and classes in the
# final binary file.
LFLAGS = -lstdc++ -lInfluxDB

C_SRC = mainc.c
CPP_SRCS = influxdb_wrapper.cpp influxdb_wrapper_int.cpp

# Remove leading "../" from elements in $(CPP_SRCS)
CPP_OBJS = $(CPP_SRCS:.cpp=.o)

TARGET = example-influx-c

%.o: ../%.cpp
	$(CPP) -c $< -o $@ $(FLAGS) $(FLAGS)

$(TARGET): $(CPP_OBJS) ../$(C_SRC)
	$(CC) -o $@ ../$(C_SRC) $(CPP_OBJS) $(FLAGS) $(LFLAGS)

all: $(TARGET)

clean:
	rm -f $(CPP_OBJS) $(TARGET)
