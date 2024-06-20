
#include "influxdb_wrapper.hpp"

int main(int argc,char *argv[]) {
	const char *uri = "http://localhost:8086?db=tc_db";
	InfluxDBWrapper *wr = new InfluxDBWrapper(uri);

	wr->showDatabases();

	return 0;
}
