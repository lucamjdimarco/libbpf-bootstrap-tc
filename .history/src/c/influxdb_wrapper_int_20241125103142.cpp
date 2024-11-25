
#include "influxdb_wrapper.hpp"
#include "influxdb_wrapper_int.h"
#include <vector>
#include <string>

/* declared in magic_interface.h but defined here */
struct MHandler {
	void *obj;
};

// typedef struct {
//     char *machine_id;
//     char *interface;
//     uint64_t flowid;
// } TagInfluxDB;

MHandler_t *create_influxdb(const char *uri)
{
	InfluxDBWrapper *obj;
	MHandler_t *h;

	h = (typeof(h))malloc(sizeof(*h));
	if (!h)
		return NULL;

	try {
		obj = new InfluxDBWrapper(uri);
	} catch(...) {
		/* an exception occurred during wrapper creation */
		free(h);
		return NULL;
	}

	h->obj = obj;
	return h;
}

void show_databases_influxdb(MHandler_t *h)
{
	InfluxDBWrapper *obj;

	obj = static_cast<InfluxDBWrapper *>(h->obj);
	obj->showDatabases();
}

void destroy_influxdb(MHandler_t *h)
{
	InfluxDBWrapper *obj;

	obj = static_cast<InfluxDBWrapper *>(h->obj);
	/* Delete the obj instance */
	delete obj;

	/* destroy the opaque handler */
	free(h);
}

int write_temp_influxdb(MHandler_t *h, const char *city, double temp)
{
	InfluxDBWrapper *obj;

	obj = static_cast<InfluxDBWrapper *>(h->obj);
	return obj->writeTemperature(city, temp);
}

// int write_data_influxdb(MHandler_t *h,
// 			    uint64_t ts, uint64_t flowid, uint64_t counter)
int write_data_influxdb(MHandler_t *h,
			    uint64_t ts, TagInfluxDBC *tags, uint64_t counter)
{
	InfluxDBWrapper *obj;

    if (h == nullptr || tags == nullptr) {
        std::cerr << "Error: null pointer passed to write_data_influxdb." << std::endl;
        return -EINVAL;
    }

    if (h->obj == nullptr) {
        std::cerr << "Error: h->obj is null." << std::endl;
        return -EINVAL;
    }

    obj = static_cast<InfluxDBWrapper *>(h->obj);
    return obj->writeData(ts, *tags, counter);
}


// int write_data_influxdb_batch(MHandler_t *h, uint64_t *ts, uint64_t *flowid, uint64_t *counter, size_t count) {
int write_data_influxdb_batch(MHandler_t *h, uint64_t *ts, TagInfluxDBC **tags, uint64_t *counter, size_t count) {
    InfluxDBWrapper *obj;

    if (h == nullptr || ts == nullptr || tags == nullptr || counter == nullptr) {
        std::cerr << "Error: null pointer passed to write_data_influxdb_batch." << std::endl;
        return -EINVAL;
    }

    if (h->obj == nullptr) {
        std::cerr << "Error: h->obj is null." << std::endl;
        return -EINVAL;
    }

    std::vector<uint64_t> ts_vec(ts, ts + count);
    std::vector<TagInfluxDB> tags_vec;
    std::vector<uint64_t> counter_vec(counter, counter + count);

    for (size_t i = 0; i < count; ++i) {
        if (tags[i] == nullptr) {
            std::cerr << "Error: null tag in tags array at index " << i << "." << std::endl;
            return -EINVAL;
        }
        tags_vec.emplace_back(*tags[i]);
    }

    obj = static_cast<InfluxDBWrapper *>(h->obj);
    return obj->writeDataBatch(ts_vec, tags_vec, counter_vec);
}


/*void show_data_influxdb(MHandler_t *h, const char *measurement)
{
	InfluxDBWrapper *obj;

	obj = static_cast<InfluxDBWrapper *>(h->obj);
	obj->showData(measurement);
}*/
