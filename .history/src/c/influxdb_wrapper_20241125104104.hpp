
#ifndef INFLUXDB_WRAPPER_HPP
#define INFLUXDB_WRAPPER_HPP

#include <iostream>
#include <string>
#include <InfluxDB/InfluxDBFactory.h>

class InfluxDBWrapper {
public:
	InfluxDBWrapper(const char *uri);
	~InfluxDBWrapper();
	void showDatabases();
	int writeTemperature(const char *city, double temp);
	//int writeData(uint64_t ts, uint64_t flowid, uint64_t counter);
	// int writeDataBatch(const std::vector<uint64_t>& timestamps,
	// 					const std::vector<uint64_t>& flowids,
	// 					const std::vector<uint64_t>& counters);
	int writeData(uint64_t ts, const std::string& machine_id, const std::string& interface,
				 uint64_t flowid, uint64_t counter);
	int writeDataBatch(const std::vector<uint64_t>& timestamps,
                                    const std::vector<std::string>& machine_ids,
									const std::vector<std::string>& interfaces,
									const std::vector<uint64_t>& flowids,
                                    const std::vector<uint64_t>& counters);
	//void showData(const std::string& measurement);
private:
	std::unique_ptr<influxdb::InfluxDB> db;
};

#endif
