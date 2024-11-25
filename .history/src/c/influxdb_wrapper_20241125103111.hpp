
#ifndef INFLUXDB_WRAPPER_HPP
#define INFLUXDB_WRAPPER_HPP

#include <iostream>
#include <string>
#include <InfluxDB/InfluxDBFactory.h>

struct TagInfluxDB {
    std::string machine_id;
    std::string interface;
    uint64_t flowid;
};

class InfluxDBWrapper {
public:
	InfluxDBWrapper(const char *uri);
	~InfluxDBWrapper();
	void showDatabases();
	int writeTemperature(const char *city, double temp);
	int writeData(uint64_t ts, const TagInfluxDB& tags, uint64_t counter);
	int writeDataBatch(const std::vector<uint64_t>& timestamps,
                       const std::vector<TagInfluxDB>& tags_batch,
                       const std::vector<uint64_t>& counters);
	//void showData(const std::string& measurement);
private:
	std::unique_ptr<influxdb::InfluxDB> db;
};

#endif
