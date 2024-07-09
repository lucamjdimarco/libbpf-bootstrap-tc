
#include "influxdb_wrapper.hpp"
#include <sstream> 
#include <stdint.h>

/* con l'URI viene creato il DB se non esiste */
InfluxDBWrapper::InfluxDBWrapper(const char *uri) {
	std::string cppString = uri;

	/* throws an exception if we cannot connect to influxdb and/or
	 * create the db.
	 */
	db = influxdb::InfluxDBFactory::Get(cppString);
	db->createDatabaseIfNotExists();
}

InfluxDBWrapper::~InfluxDBWrapper() {
	db.reset();
}

void InfluxDBWrapper::showDatabases() {
	try {
		for (auto i: db->query("SHOW DATABASES"))
			std::cout << i.getTags() <<std::endl;
	} catch (...) { /* do nothing */ }
}

int InfluxDBWrapper::writeTemperature(const char *c, double t) {
	double temp = static_cast<double>(t);
	influxdb::Point point("temperature");
	std::string city = c;

	point.addTag("city", city);
	point.addField("value", temp);
	point.setTimestamp(std::chrono::system_clock::now());

	try {
		db->write(std::move(point));
		return 0;
	} catch (...) { /* do nothing */ }

	return -EINVAL;
}

int InfluxDBWrapper::writeData(uint64_t ts, uint64_t flowid, uint64_t counter) {
    influxdb::Point point("rate");
	double ccnt = 1.0D * counter;
	std::string flowid_str;
	std::ostringstream oss;

	oss << flowid;
	flowid_str = oss.str();
	point.addTag("flowid", flowid_str);

	point.addField("value", ccnt);

	//FIXME: use ts instead of now()
	point.setTimestamp(std::chrono::system_clock::now());

	if (db == nullptr) {
		std::cerr << "Error: db pointer is null." << std::endl;
		return -EINVAL;
	}


	try {
		db->write(std::move(point));
		return 0;
	} catch (...) { /* do nothing */ }

	return -EINVAL;
}

/*void InfluxDBWrapper::showData(const std::string& measurement) {
	try {
		auto results = db->query("SELECT * FROM " + measurement);
		for (const auto& point : results) {
			std::cout << "Time: " << point.getTimestamp().time_since_epoch().count() << ", ";
			for (const auto& tag : point.getTags()) {
				std::cout << tag.first << ": " << tag.second << ", ";
			}
			for (const auto& field : point.getFields()) {
				std::cout << field.first << ": " << field.second << ", ";
			}
			std::cout << std::endl;
		}
	} catch (...) {
		std::cerr << "Failed to query data from InfluxDB" << std::endl;
	}
}*/
