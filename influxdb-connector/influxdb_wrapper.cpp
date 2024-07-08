
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

int InfluxDBWrapper::writeData(__u64 flow_id, double counter, std::chrono::system_clock::time_point timestamp) {
    std::string flow_id_str = std::to_string(flow_id);

    influxdb::Point point("flow_data");

    point.addTag("flow_id", flow_id_str);
    point.addField("counter", counter);
    point.setTimestamp(timestamp);

    try {
        db->write(std::move(point));
        return 0;
    } catch (...) {
        /* do nothing */
    }

    return -EINVAL;
}
