
#ifndef INFLUXDB_WRAPPER_HPP
#define INFLUXDB_WRAPPER_HPP

#include <iostream>
#include <InfluxDBFactory.h>

class InfluxDBWrapper {
public:
	InfluxDBWrapper(const char *uri);
	~InfluxDBWrapper();
	void showDatabases();
	int writeTemperature(const char *city, double temp);
	int writeData(__u64 flow_id, double counter, std::chrono::system_clock::time_point timestamp);
private:
	std::unique_ptr<influxdb::InfluxDB> db;
};

#endif
