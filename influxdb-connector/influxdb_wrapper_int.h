
#ifndef INFLUXDB_WRAPPER_INT
#define INFLUXDB_WRAPPER_INT

#ifdef __cplusplus
extern "C" {
#endif
	/* The purpose of declaring a struct in a header file without
	 * defining it is to allow other source files that include the header
	 * to use pointers to the struct without needing to know the full
	 * definition of the struct. This technique is commonly used in C and
	 * C++ to create a "opaque" type, where the details of the struct are
	 * hidden from external code. This can be useful for encapsulating
	 * data and behavior within a library or module, and only exposing a
	 * limited interface to the outside world.
	 */
	struct MHandler;

	typedef struct MHandler MHandler_t;

	MHandler_t *create_influxdb(const char *);
	void show_databases_influxdb(MHandler_t *);
	int write_temp_influxdb(MHandler_t *, const char *, double);
	void destroy_influxdb(MHandler_t *);
	int write_data_influxdb(MHandler_t *h, __u64, __u64, __u64);
	void show_data_influxdb(MHandler_t *h, const char *measurement);
#ifdef __cplusplus
}
#endif

#endif /* INFLUXDB_WRAPPER_INT */
