An example in C of how to connect to InfluxDB by wrapping C++ classes inside of
C functions.

How to use C++ classes and libraries in C is explained in the repository:
	https://github.com/netgroup/cpp_to_c_adapter_example

In this example, we provide two ways to compile the executable: using cmake and
a simple makefile.  Both ways lead to the same result, which is an executable
that is able to connect to a local InfluxDB instance and create a sample
database.
