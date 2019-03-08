#include <time.h>
#include <memory>
#include <QVariant>
#include "event.h"

namespace event {

void Events::clear()
{
  // Delete events.
  for (Base* event : m_events) {
    delete event;
  }

  m_events.clear();

  m_ipAddresses.clear();
  m_hosts.clear();
}

void Events::load(const QJsonArray& events, Connections& connections)
{
  // Get number of events.
  int nevents = events.count();

  // Allocate events.
  m_events.reserve(nevents);

  // For each event...
  for (int i = 0; i < nevents; i++) {
    // Get event at position 'i'.
    const QJsonValue& ev = events[i];

    // If it is an object...
    if (ev.isObject()) {
      // Convert QJsonValue to a QJsonObject.
      QJsonObject event = ev.toObject();

      // Get key "event-type".
      QJsonValue value = event.value("event-type");

      // If the key "event-type" is a string...
      if (value.isString()) {
        QString type = value.toString();

        if (type == "ICMP") {
          parseIcmpEvent(event);
        } else if (type == "UDP") {
          parseUdpEvent(event);
        } else if ((type == "dns-query") || (type == "dns-response")) {
          parseDnsEvent(event);
        } else if (type == "begin-tcp-connection") {
          parseTcpBeginEvent(event, connections);
        } else if (type == "tcp-data") {
          parseTcpDataEvent(event, connections);
        } else if (type == "end-tcp-connection") {
          parseTcpEndEvent(event, connections);
        }
      }
    }
  }
}

void Events::parseIcmpEvent(const QJsonObject& ev)
{
  uint64_t eventNumber;
  uint64_t timestamp;
  QString sourceAddress;
  QString sourceHostname;
  QString destinationAddress;
  QString destinationHostname;

  // Parse base event.
  if (parseBaseEvent(ev,
                     eventNumber,
                     timestamp,
                     sourceAddress,
                     sourceHostname,
                     destinationAddress,
                     destinationHostname)) {
    uint8_t icmpType;
    uint8_t icmpCode;
    uint16_t transferred;

    // Extract "icmp-type, "icmp-code" and "transferred".
    if ((getValue(ev, "icmp-type", icmpType)) &&
        (getValue(ev, "icmp-code", icmpCode)) &&
        (getValue(ev, "transferred", transferred))) {
      // Create 'ICMP' event.
      Icmp* icmp = new (std::nothrow) Icmp(eventNumber,
                                           timestamp,
                                           std::move(sourceAddress),
                                           std::move(sourceHostname),
                                           std::move(destinationAddress),
                                           std::move(destinationHostname),
                                           icmpType,
                                           icmpCode,
                                           transferred);

      if (icmp) {
        // Add event.
        m_events.push_back(icmp);

        // Add IP addresses.
        m_ipAddresses.insert(icmp->sourceAddress);
        m_ipAddresses.insert(icmp->destinationAddress);
      }
    }
  }
}

void Events::parseUdpEvent(const QJsonObject& ev)
{
  uint64_t eventNumber;
  uint64_t timestamp;
  QString sourceAddress;
  QString sourceHostname;
  QString destinationAddress;
  QString destinationHostname;

  // Parse base event.
  if (parseBaseEvent(ev,
                     eventNumber,
                     timestamp,
                     sourceAddress,
                     sourceHostname,
                     destinationAddress,
                     destinationHostname)) {
    in_port_t sourcePort;
    in_port_t destinationPort;

    // Extract ports.
    if (extractPorts(ev, sourcePort, destinationPort)) {
      uint16_t transferred;

      // Extract "transferred".
      if (getValue(ev, "transferred", transferred)) {
        // Create 'UDP' event.
        Udp* udp = new (std::nothrow) Udp(eventNumber,
                                          timestamp,
                                          std::move(sourceAddress),
                                          std::move(sourceHostname),
                                          std::move(destinationAddress),
                                          std::move(destinationHostname),
                                          sourcePort,
                                          destinationPort,
                                          transferred);

        if (udp) {
          // Add event.
          m_events.push_back(udp);

          // Add IP addresses.
          m_ipAddresses.insert(udp->sourceAddress);
          m_ipAddresses.insert(udp->destinationAddress);
        }
      }
    }
  }
}

void Events::parseDnsEvent(const QJsonObject& ev)
{
  uint64_t eventNumber;
  uint64_t timestamp;
  QString sourceAddress;
  QString sourceHostname;
  QString destinationAddress;
  QString destinationHostname;

  // Parse base event.
  if (parseBaseEvent(ev,
                     eventNumber,
                     timestamp,
                     sourceAddress,
                     sourceHostname,
                     destinationAddress,
                     destinationHostname)) {
    in_port_t sourcePort;
    in_port_t destinationPort;

    // Extract ports.
    if (extractPorts(ev, sourcePort, destinationPort)) {
      uint16_t transferred;
      uint8_t queryType;
      QString domain;

      // Extract "transferred", "query-type" and "domain".
      if ((getValue(ev, "transferred", transferred)) &&
          (getValue(ev, "query-type", queryType)) &&
          (getValue(ev, "domain", domain))) {
        std::vector<QString> responses;

        // Extract responses (if any).
        QJsonValue v = ev.value("responses");
        if (v.isArray()) {
          QJsonArray array = v.toArray();
          for (QJsonArray::ConstIterator it = array.constBegin();
               it != array.constEnd();
               ++it) {
            const QJsonValue& v = *it;
            if (v.isString()) {
              responses.emplace_back(v.toString());
            }
          }
        }

        // Create 'DNS' event.
        Dns* dns = new (std::nothrow) Dns(eventNumber,
                                          timestamp,
                                          std::move(sourceAddress),
                                          std::move(sourceHostname),
                                          std::move(destinationAddress),
                                          std::move(destinationHostname),
                                          sourcePort,
                                          destinationPort,
                                          transferred,
                                          queryType,
                                          std::move(domain),
                                          std::move(responses));

        if (dns) {
          // Add event.
          m_events.push_back(dns);

          // Add IP addresses.
          m_ipAddresses.insert(dns->sourceAddress);
          m_ipAddresses.insert(dns->destinationAddress);

          // Add hostname.
          m_hosts.insert(dns->domain);
        }
      }
    }
  }
}

void Events::parseTcpBeginEvent(const QJsonObject& ev, Connections& connections)
{
  uint64_t eventNumber;
  uint64_t timestamp;
  QString sourceAddress;
  QString sourceHostname;
  QString destinationAddress;
  QString destinationHostname;

  // Parse base event.
  if (parseBaseEvent(ev,
                     eventNumber,
                     timestamp,
                     sourceAddress,
                     sourceHostname,
                     destinationAddress,
                     destinationHostname)) {
    in_port_t sourcePort;
    in_port_t destinationPort;

    // Extract ports.
    if (extractPorts(ev, sourcePort, destinationPort)) {
      // Create 'Begin TCP connection' event.
      TcpBegin* tcpBegin = new (std::nothrow)
                           TcpBegin(eventNumber,
                                    timestamp,
                                    std::move(sourceAddress),
                                    std::move(sourceHostname),
                                    std::move(destinationAddress),
                                    std::move(destinationHostname),
                                    sourcePort,
                                    destinationPort);

      if (tcpBegin) {
        // Add event.
        m_events.push_back(tcpBegin);

        // Add IP addresses.
        m_ipAddresses.insert(tcpBegin->sourceAddress);
        m_ipAddresses.insert(tcpBegin->destinationAddress);

        connections.beginTcpConnection(tcpBegin->sourceAddress,
                                       tcpBegin->sourceHostname,
                                       tcpBegin->sourcePort,
                                       tcpBegin->destinationAddress,
                                       tcpBegin->destinationHostname,
                                       tcpBegin->destinationPort,
                                       tcpBegin->timestamp);
      }
    }
  }
}

void Events::parseTcpDataEvent(const QJsonObject& ev, Connections& connections)
{
  uint64_t eventNumber;
  uint64_t timestamp;
  QString sourceAddress;
  QString sourceHostname;
  QString destinationAddress;
  QString destinationHostname;

  // Parse base event.
  if (parseBaseEvent(ev,
                     eventNumber,
                     timestamp,
                     sourceAddress,
                     sourceHostname,
                     destinationAddress,
                     destinationHostname)) {
    in_port_t sourcePort;
    in_port_t destinationPort;

    // Extract ports.
    if (extractPorts(ev, sourcePort, destinationPort)) {
      uint16_t payload;

      // Extract "payload".
      if (getValue(ev, "payload", payload)) {
        // Create 'TCP data' event.
        TcpData* tcpData = new (std::nothrow)
                           TcpData(eventNumber,
                                   timestamp,
                                   std::move(sourceAddress),
                                   std::move(sourceHostname),
                                   std::move(destinationAddress),
                                   std::move(destinationHostname),
                                   sourcePort,
                                   destinationPort,
                                   payload);

        if (tcpData) {
          // Add event.
          m_events.push_back(tcpData);

          // Add IP addresses.
          m_ipAddresses.insert(tcpData->sourceAddress);
          m_ipAddresses.insert(tcpData->destinationAddress);

          connections.tcpData(tcpData->sourceAddress,
                              tcpData->sourcePort,
                              tcpData->destinationAddress,
                              tcpData->destinationPort,
                              tcpData->timestamp,
                              tcpData->payload);
        }
      }
    }
  }
}

void Events::parseTcpEndEvent(const QJsonObject& ev, Connections& connections)
{
  uint64_t eventNumber;
  uint64_t timestamp;
  QString sourceAddress;
  QString sourceHostname;
  QString destinationAddress;
  QString destinationHostname;

  // Parse base event.
  if (parseBaseEvent(ev,
                     eventNumber,
                     timestamp,
                     sourceAddress,
                     sourceHostname,
                     destinationAddress,
                     destinationHostname)) {
    in_port_t sourcePort;
    in_port_t destinationPort;

    // Extract ports.
    if (extractPorts(ev, sourcePort, destinationPort)) {
      QString creationStr;
      uint64_t creation;
      uint64_t transferredClient;
      uint64_t transferredServer;

      // Extract "creation", "transferred-client" and "transferred-server".
      if ((getValue(ev, "creation", creationStr)) &&
          (parseTimestamp(creationStr, creation)) &&
          (getValue(ev, "transferred-client", transferredClient)) &&
          (getValue(ev, "transferred-server", transferredServer))) {
        // Create 'End TCP connection' event.
        TcpEnd* tcpEnd = new (std::nothrow)
                         TcpEnd(eventNumber,
                                timestamp,
                                std::move(sourceAddress),
                                std::move(sourceHostname),
                                std::move(destinationAddress),
                                std::move(destinationHostname),
                                sourcePort,
                                destinationPort,
                                creation,
                                transferredClient,
                                transferredServer);

        if (tcpEnd) {
          // Add event.
          m_events.push_back(tcpEnd);

          // Add IP addresses.
          m_ipAddresses.insert(tcpEnd->sourceAddress);
          m_ipAddresses.insert(tcpEnd->destinationAddress);

          connections.endTcpConnection(tcpEnd->sourceAddress,
                                       tcpEnd->sourcePort,
                                       tcpEnd->destinationAddress,
                                       tcpEnd->destinationPort,
                                       tcpEnd->timestamp,
                                       tcpEnd->transferredClient,
                                       tcpEnd->transferredServer);
        }
      }
    }
  }
}

bool Events::parseBaseEvent(const QJsonObject& ev,
                            uint64_t& eventNumber,
                            uint64_t& timestamp,
                            QString& sourceAddress,
                            QString& sourceHostname,
                            QString& destinationAddress,
                            QString& destinationHostname)
{
  QString date;

  if ((getValue(ev, "event-number", eventNumber)) &&
      (getValue(ev, "date", date)) &&
      (parseTimestamp(date, timestamp)) &&
      (getValue(ev, "source-ip", sourceAddress)) &&
      (getValue(ev, "destination-ip", destinationAddress))) {
    // Get source hostname (if available).
    getValue(ev, "source-hostname", sourceHostname);

    // Get destination hostname (if available).
    getValue(ev, "destination-hostname", destinationHostname);

    return true;
  }

  return false;
}

bool Events::extractPorts(const QJsonObject& ev,
                          in_port_t& sourcePort,
                          in_port_t& destinationPort)
{
  return ((getValue(ev, "source-port", sourcePort)) &&
          (getValue(ev, "destination-port", destinationPort)));
}

bool Events::getValue(const QJsonObject& obj, const char* name, QString& value)
{
  // Get value.
  QJsonValue v = obj.value(name);

  // If the value is a string...
  if (v.isString()) {
    // Save value.
    value = v.toString();

    return true;
  }

  return false;
}

bool Events::getValue(const QJsonObject& obj, const char* name, uint8_t& value)
{
  // Get value.
  QJsonValue v = obj.value(name);

  // If the value exists...
  if (!v.isUndefined()) {
    // Convert value to a QVariant.
    QVariant n = v.toVariant();

    // Convert to unsigned.
    bool ok;
    unsigned number = n.toUInt(&ok);
    if ((ok) && (number < 256)) {
      // Save value.
      value = static_cast<uint8_t>(number);

      return true;
    }
  }

  return false;
}

bool Events::getValue(const QJsonObject& obj,
                     const char* name,
                     uint16_t& value)
{
  // Get value.
  QJsonValue v = obj.value(name);

  // If the value exists...
  if (!v.isUndefined()) {
    // Convert value to a QVariant.
    QVariant n = v.toVariant();

    // Convert to unsigned.
    bool ok;
    unsigned number = n.toUInt(&ok);
    if ((ok) && (number < 65536)) {
      // Save value.
      value = static_cast<uint16_t>(number);

      return true;
    }
  }

  return false;
}

bool Events::getValue(const QJsonObject& obj,
                     const char* name,
                     uint32_t& value)
{
  // Get value.
  QJsonValue v = obj.value(name);

  // If the value exists...
  if (!v.isUndefined()) {
    // Convert value to a QVariant.
    QVariant n = v.toVariant();

    // Convert to unsigned.
    bool ok;
    value = n.toUInt(&ok);
    return ok;
  }

  return false;
}

bool Events::getValue(const QJsonObject& obj,
                     const char* name,
                     uint64_t& value)
{
  // Get value.
  QJsonValue v = obj.value(name);

  // If the value exists...
  if (!v.isUndefined()) {
    // Convert value to a QVariant.
    QVariant n = v.toVariant();

    // Convert to unsigned long long.
    bool ok;
    value = n.toULongLong(&ok);
    return ok;
  }

  return false;
}

bool Events::parseTimestamp(const QString& s, uint64_t& timestamp)
{
  if ((s.length() != 26)  ||
      (!s[0].isDigit())   || // Y
      (!s[1].isDigit())   || // Y
      (!s[2].isDigit())   || // Y
      (!s[3].isDigit())   || // Y
      (s[4] != '/')       ||
      (!s[5].isDigit())   || // M
      (!s[6].isDigit())   || // M
      (s[7] != '/')       ||
      (!s[8].isDigit())   || // D
      (!s[9].isDigit())   || // D
      (s[10] != ' ')      ||
      (!s[11].isDigit())  || // h
      (!s[12].isDigit())  || // h
      (s[13] != ':')      ||
      (!s[14].isDigit())  || // m
      (!s[15].isDigit())  || // m
      (s[16] != ':')      ||
      (!s[17].isDigit())  || // s
      (!s[18].isDigit())  || // s
      (s[19] != '.')      ||
      (!s[20].isDigit())  || // u
      (!s[21].isDigit())  || // u
      (!s[22].isDigit())  || // u
      (!s[23].isDigit())  || // u
      (!s[24].isDigit())  || // u
      (!s[25].isDigit())) {  // u
    return false;
  }

  // Extract year.
  unsigned year = (s[0].digitValue() * 1000) +
                  (s[1].digitValue() * 100) +
                  (s[2].digitValue() * 10) +
                   s[3].digitValue();

  if ((year < 2000) || (year > 2100)) {
    return false;
  }

  // Extract month.
  unsigned mon = (s[5].digitValue() * 10) + s[6].digitValue();
  if ((mon < 1) || (mon > 12)) {
    return false;
  }

  // Extract day.
  unsigned mday = (s[8].digitValue() * 10) + s[9].digitValue();
  if ((mday < 1) || (mday > 31)) {
    return false;
  }

  // Extract hour.
  unsigned hour = (s[11].digitValue() * 10) + s[12].digitValue();
  if (hour > 23) {
    return false;
  }

  // Extract minutes.
  unsigned min = (s[14].digitValue() * 10) + s[15].digitValue();
  if (min > 59) {
    return false;
  }

  // Extract seconds.
  unsigned sec = (s[17].digitValue() * 10) + s[18].digitValue();
  if (sec > 59) {
    return false;
  }

  // Extract microseconds.
  unsigned us = (s[20].digitValue() * 100000) +
                (s[21].digitValue() * 10000) +
                (s[22].digitValue() * 1000) +
                (s[23].digitValue() * 100) +
                (s[24].digitValue() * 10) +
                 s[25].digitValue();

  struct tm tm;
  tm.tm_year = year - 1900;
  tm.tm_mon = mon - 1;
  tm.tm_mday = mday;
  tm.tm_hour = hour;
  tm.tm_min = min;
  tm.tm_sec = sec;
  tm.tm_isdst = -1;
  time_t time = mktime(&tm);

  timestamp = (static_cast<uint64_t>(time) * 1000000ull) + us;

  return true;
}

} // namespace event
