#ifndef EVENT_H
#define EVENT_H

#include <stdint.h>
#include <netinet/in.h>
#include <vector>
#include <set>
#include <QString>
#include <QJsonArray>
#include <QJsonObject>
#include "connection.h"

namespace event {
  // Base event.
  struct Base {
    // Event number.
    const uint64_t eventNumber;

    // Number of microseconds since the Epoch,
    // 1970-01-01 00:00:00 +0000 (UTC).
    const uint64_t timestamp;

    // Source address.
    const QString sourceAddress;

    // Source hostname.
    const QString sourceHostname;

    // Destination address.
    const QString destinationAddress;

    // Destination hostname.
    const QString destinationHostname;

    // Constructor.
    Base(uint64_t eventNumber,
         uint64_t timestamp,
         QString sourceAddress,
         QString sourceHostname,
         QString destinationAddress,
         QString destinationHostname);
  };

  // 'ICMP' event.
  struct Icmp : public Base {
    // ICMP type.
    const uint8_t icmpType;

    // ICMP code.
    const uint8_t icmpCode;

    // # of bytes transferred.
    const uint16_t transferred;

    // Constructor.
    Icmp(uint64_t eventNumber,
         uint64_t timestamp,
         QString sourceAddress,
         QString sourceHostname,
         QString destinationAddress,
         QString destinationHostname,
         uint8_t icmpType,
         uint8_t icmpCode,
         uint16_t transferred);
  };

  // 'UDP' event.
  struct Udp : public Base {
    // Source port.
    const in_port_t sourcePort;

    // Destination port.
    const in_port_t destinationPort;

    // # of bytes transferred.
    const uint16_t transferred;

    // Constructor.
    Udp(uint64_t eventNumber,
        uint64_t timestamp,
        QString sourceAddress,
        QString sourceHostname,
        QString destinationAddress,
        QString destinationHostname,
        uint16_t sourcePort,
        uint16_t destinationPort,
        uint16_t transferred);
  };

  // 'DNS' event.
  struct Dns : public Base {
    // Source port.
    const in_port_t sourcePort;

    // Destination port.
    const in_port_t destinationPort;

    // # of bytes transferred.
    const uint16_t transferred;

    // Query type.
    const uint8_t queryType;

    // Domain.
    const QString domain;

    // DNS responses.
    const std::vector<QString> responses;

    // Constructor.
    Dns(uint64_t eventNumber,
        uint64_t timestamp,
        QString sourceAddress,
        QString sourceHostname,
        QString destinationAddress,
        QString destinationHostname,
        uint16_t sourcePort,
        uint16_t destinationPort,
        uint16_t transferred,
        uint8_t queryType,
        QString domain,
        std::vector<QString> responses);
  };

  // 'Begin TCP connection' event.
  struct TcpBegin : public Base {
    // Source port.
    const in_port_t sourcePort;

    // Destination port.
    const in_port_t destinationPort;

    // Constructor.
    TcpBegin(uint64_t eventNumber,
             uint64_t timestamp,
             QString sourceAddress,
             QString sourceHostname,
             QString destinationAddress,
             QString destinationHostname,
             uint16_t sourcePort,
             uint16_t destinationPort);
  };

  // 'TCP data' event.
  struct TcpData : public Base {
    // Source port.
    const in_port_t sourcePort;

    // Destination port.
    const in_port_t destinationPort;

    // # of bytes of payload.
    const uint16_t payload;

    // Constructor.
    TcpData(uint64_t eventNumber,
            uint64_t timestamp,
            QString sourceAddress,
            QString sourceHostname,
            QString destinationAddress,
            QString destinationHostname,
            uint16_t sourcePort,
            uint16_t destinationPort,
            uint16_t payload);
  };

  // 'End TCP connection' event.
  struct TcpEnd : public Base {
    // Source port.
    const in_port_t sourcePort;

    // Destination port.
    const in_port_t destinationPort;

    // Creation timestamp.
    const uint64_t creation;

    // # of bytes sent by the client.
    const uint64_t transferredClient;

    // # of bytes sent by the server.
    const uint64_t transferredServer;

    // Constructor.
    TcpEnd(uint64_t eventNumber,
           uint64_t timestamp,
           QString sourceAddress,
           QString sourceHostname,
           QString destinationAddress,
           QString destinationHostname,
           uint16_t sourcePort,
           uint16_t destinationPort,
           uint64_t creation,
           uint64_t transferredClient,
           uint64_t transferredServer);
  };

  // Events.
  class Events {
    public:
      // Constructor.
      Events() = default;

      // Destructor.
      ~Events();

      // Clear events.
      void clear();

      // Load.
      void load(const QJsonArray& events, Connections& connections);

      // Get events.
      const std::vector<Base*>& get() const;

      // Get IP addresses.
      const std::set<QString>& ipAddresses() const;

      // Get hosts.
      const std::set<QString>& hosts() const;

    private:
      // Events.
      std::vector<Base*> m_events;

      // IP addresses.
      std::set<QString> m_ipAddresses;

      // Hosts.
      std::set<QString> m_hosts;

      // Parse 'ICMP' event.
      void parseIcmpEvent(const QJsonObject& ev);

      // Parse 'UDP' event.
      void parseUdpEvent(const QJsonObject& ev);

      // Parse 'DNS' event.
      void parseDnsEvent(const QJsonObject& ev);

      // Parse 'Begin TCP connection' event.
      void parseTcpBeginEvent(const QJsonObject& ev, Connections& connections);

      // Parse 'TCP data' event.
      void parseTcpDataEvent(const QJsonObject& ev, Connections& connections);

      // Parse 'End TCP connection' event.
      void parseTcpEndEvent(const QJsonObject& ev, Connections& connections);

      // Parse base event.
      static bool parseBaseEvent(const QJsonObject& ev,
                                 uint64_t& eventNumber,
                                 uint64_t& timestamp,
                                 QString& sourceAddress,
                                 QString& sourceHostname,
                                 QString& destinationAddress,
                                 QString& destinationHostname);

      // Extract ports.
      static bool extractPorts(const QJsonObject& ev,
                               in_port_t& sourcePort,
                               in_port_t& destinationPort);

      // Get value as string.
      static bool getValue(const QJsonObject& obj,
                           const char* name,
                           QString& value);

      // Get value as uint8_t.
      static bool getValue(const QJsonObject& obj,
                           const char* name,
                           uint8_t& value);

      // Get value as uint16_t.
      static bool getValue(const QJsonObject& obj,
                           const char* name,
                           uint16_t& value);

      // Get value as uint32_t.
      static bool getValue(const QJsonObject& obj,
                           const char* name,
                           uint32_t& value);

      // Get value as uint64_t.
      static bool getValue(const QJsonObject& obj,
                           const char* name,
                           uint64_t& value);

      // Parse timestamp.
      static bool parseTimestamp(const QString& s, uint64_t& timestamp);
  };

  inline Base::Base(uint64_t eventNumber,
                    uint64_t timestamp,
                    QString sourceAddress,
                    QString sourceHostname,
                    QString destinationAddress,
                    QString destinationHostname)
    : eventNumber(eventNumber),
      timestamp(timestamp),
      sourceAddress(std::move(sourceAddress)),
      sourceHostname(std::move(sourceHostname)),
      destinationAddress(std::move(destinationAddress)),
      destinationHostname(std::move(destinationHostname))
  {
  }

  inline Icmp::Icmp(uint64_t eventNumber,
                    uint64_t timestamp,
                    QString sourceAddress,
                    QString sourceHostname,
                    QString destinationAddress,
                    QString destinationHostname,
                    uint8_t icmpType,
                    uint8_t icmpCode,
                    uint16_t transferred)
    : Base(eventNumber,
           timestamp,
           std::move(sourceAddress),
           std::move(sourceHostname),
           std::move(destinationAddress),
           std::move(destinationHostname)),
      icmpType(icmpType),
      icmpCode(icmpCode),
      transferred(transferred)
  {
  }

  inline Udp::Udp(uint64_t eventNumber,
                  uint64_t timestamp,
                  QString sourceAddress,
                  QString sourceHostname,
                  QString destinationAddress,
                  QString destinationHostname,
                  uint16_t sourcePort,
                  uint16_t destinationPort,
                  uint16_t transferred)
  : Base(eventNumber,
         timestamp,
         std::move(sourceAddress),
         std::move(sourceHostname),
         std::move(destinationAddress),
         std::move(destinationHostname)),
    sourcePort(sourcePort),
    destinationPort(destinationPort),
    transferred(transferred)
  {
  }

  inline Dns::Dns(uint64_t eventNumber,
                  uint64_t timestamp,
                  QString sourceAddress,
                  QString sourceHostname,
                  QString destinationAddress,
                  QString destinationHostname,
                  uint16_t sourcePort,
                  uint16_t destinationPort,
                  uint16_t transferred,
                  uint8_t queryType,
                  QString domain,
                  std::vector<QString> responses)
  : Base(eventNumber,
         timestamp,
         std::move(sourceAddress),
         std::move(sourceHostname),
         std::move(destinationAddress),
         std::move(destinationHostname)),
    sourcePort(sourcePort),
    destinationPort(destinationPort),
    transferred(transferred),
    queryType(queryType),
    domain(std::move(domain)),
    responses(std::move(responses))
  {
  }

  inline TcpBegin::TcpBegin(uint64_t eventNumber,
                            uint64_t timestamp,
                            QString sourceAddress,
                            QString sourceHostname,
                            QString destinationAddress,
                            QString destinationHostname,
                            uint16_t sourcePort,
                            uint16_t destinationPort)
  : Base(eventNumber,
         timestamp,
         std::move(sourceAddress),
         std::move(sourceHostname),
         std::move(destinationAddress),
         std::move(destinationHostname)),
    sourcePort(sourcePort),
    destinationPort(destinationPort)
  {
  }

  inline TcpData::TcpData(uint64_t eventNumber,
                          uint64_t timestamp,
                          QString sourceAddress,
                          QString sourceHostname,
                          QString destinationAddress,
                          QString destinationHostname,
                          uint16_t sourcePort,
                          uint16_t destinationPort,
                          uint16_t payload)
  : Base(eventNumber,
         timestamp,
         std::move(sourceAddress),
         std::move(sourceHostname),
         std::move(destinationAddress),
         std::move(destinationHostname)),
    sourcePort(sourcePort),
    destinationPort(destinationPort),
    payload(payload)
  {
  }

  inline TcpEnd::TcpEnd(uint64_t eventNumber,
                        uint64_t timestamp,
                        QString sourceAddress,
                        QString sourceHostname,
                        QString destinationAddress,
                        QString destinationHostname,
                        uint16_t sourcePort,
                        uint16_t destinationPort,
                        uint64_t creation,
                        uint64_t transferredClient,
                        uint64_t transferredServer)
  : Base(eventNumber,
         timestamp,
         std::move(sourceAddress),
         std::move(sourceHostname),
         std::move(destinationAddress),
         std::move(destinationHostname)),
    sourcePort(sourcePort),
    destinationPort(destinationPort),
    creation(creation),
    transferredClient(transferredClient),
    transferredServer(transferredServer)
  {
  }

  inline Events::~Events()
  {
    clear();
  }

  inline const std::vector<Base*>& Events::get() const
  {
    return m_events;
  }

  inline const std::set<QString>& Events::ipAddresses() const
  {
    return m_ipAddresses;
  }

  inline const std::set<QString>& Events::hosts() const
  {
    return m_hosts;
  }
}

#endif // EVENT_H
