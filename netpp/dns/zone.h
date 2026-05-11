#pragma once

#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "netpp.h"
#include "netpp/dns/record.h"

namespace netpp {

class DNS_ZoneFileParser {
    std::unique_ptr<DNS_Zone> parse_zone_file(const std::string& file_path);
    std::unique_ptr<DNS_Zone> parse_zone_string(const std::string& zone_data);
};

class DNS_Zone {
public:
    DNS_Zone(const std::string& origin, uint32_t ttl);
    ~DNS_Zone();

    const std::string& origin() const { return m_origin; }
    uint32_t ttl() const { return m_ttl; }

    void add_record(const DNS_Record& record) { m_records.push_back(record); }
    void add_record(DNS_Record&& record) { m_records.push_back(std::move(record)); }

    void clear_records() { m_records.clear(); }

    const std::vector<DNS_Record>& records() const { return m_records; }

private:
    std::string m_origin;
    uint32_t m_ttl;

    std::vector<DNS_Record> m_records;
};

}