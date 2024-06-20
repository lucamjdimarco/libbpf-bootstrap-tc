
#include "influxdb_wrapper.hpp"

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
