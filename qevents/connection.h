#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include <netinet/in.h>
#include <vector>
#include <map>
#include <QString>

namespace event {
  // Connection.
  class Connection {
    public:
      // Connection key.
      class Key {
        public:
          // Constructor.
          Key(const QString& addr1,
              in_port_t port1,
              const QString& addr2,
              in_port_t port2);

          // Destructor.
          ~Key() = default;

          // Build connection key.
          static Key build(const QString& sourceAddress,
                           in_port_t sourcePort,
                           const QString& destinationAddress,
                           in_port_t destinationPort);

          // Operator "less than".
          bool operator<(const Key& other) const;

        private:
          const QString m_addr1;
          const in_port_t m_port1;

          const QString m_addr2;
          const in_port_t m_port2;
      };

      // Payload.
      class Payload {
        public:
          enum class Direction {
            from_client,
            from_server
          };

          // Constructor.
          Payload(Direction direction, uint64_t timestamp, uint16_t size);

          // Destructor.
          ~Payload() = default;

          // Get direction.
          Direction direction() const;

          // Get timestamp.
          uint64_t timestamp() const;

          // Get payload size.
          uint16_t size() const;

        private:
          // Direction of the payload.
          Direction m_direction;

          // Timestamp.
          uint64_t m_timestamp;

          // Payload size.
          uint16_t m_size;
      };

      // Constructor.
      Connection(const QString& clientIp,
                 const QString& clientHostname,
                 in_port_t clientPort,
                 const QString& serverIp,
                 const QString& serverHostname,
                 in_port_t serverPort,
                 uint64_t begin);

      // Destructor.
      ~Connection() = default;

      // Get client IP.
      const QString& clientIp() const;

      // Get client hostname.
      const QString& clientHostname() const;

      // Get client port.
      in_port_t clientPort() const;

      // Get client.
      const QString& client() const;

      // Get server IP.
      const QString& serverIp() const;

      // Get server hostname.
      const QString& serverHostname() const;

      // Get server port.
      in_port_t serverPort() const;

      // Get server.
      const QString& server() const;

      // Get the timestamp when the connection was created.
      uint64_t begin() const;

      // Get the timestamp when the connection was terminated.
      uint64_t end() const;

      // Set the timestamp when the connection was terminated.
      void end(uint64_t end);

      // Get client payload.
      uint64_t clientPayload() const;

      // Add client payload.
      void addClientPayload(uint64_t timestamp, uint16_t payload);

      // Get server payload.
      uint64_t serverPayload() const;

      // Add server payload.
      void addServerPayload(uint64_t timestamp, uint16_t payload);

      // Get the number of bytes transferred by the client.
      uint64_t transferredClient() const;

      // Set the number of bytes transferred by the client.
      void transferredClient(uint64_t transferred);

      // Get the number of bytes transferred by the server.
      uint64_t transferredServer() const;

      // Set the number of bytes transferred by the server.
      void transferredServer(uint64_t transferred);

      // Get payloads.
      const std::vector<Payload>& payloads() const;

    private:
      // Client IP.
      const QString m_clientIp;

      // Client hostname.
      const QString m_clientHostname;

      // Client port.
      const in_port_t m_clientPort;

      // Client.
      const QString m_client;

      // Server IP.
      const QString m_serverIp;

      // Server hostname.
      const QString m_serverHostname;

      // Server port.
      const in_port_t m_serverPort;

      // Server.
      const QString m_server;

      // Timestamp when the connection was created.
      const uint64_t m_begin;

      // Timestamp when the connection was terminated.
      uint64_t m_end = 0;

      // Client payload.
      uint64_t m_clientPayload = 0;

      // Server payload.
      uint64_t m_serverPayload = 0;

      // Number of bytes transferred by the client.
      uint64_t m_transferredClient = 0;

      // Number of bytes transferred by the server.
      uint64_t m_transferredServer = 0;

      // Payloads.
      std::vector<Payload> m_payloads;
  };

  // Connections.
  class Connections {
    public:
      // Constructor.
      Connections() = default;

      // Destructor.
      ~Connections() = default;

      // Clear.
      void clear();

      // Get open connections.
      const std::map<Connection::Key, Connection>& openConnections() const;

      // Get closed connections.
      const std::vector<Connection>& closedConnections() const;

      // Process 'Begin TCP connection'.
      void beginTcpConnection(const QString& sourceAddress,
                              const QString& sourceHostname,
                              in_port_t sourcePort,
                              const QString& destinationAddress,
                              const QString& destinationHostname,
                              in_port_t destinationPort,
                              uint64_t timestamp);

      // Process 'TCP data'.
      void tcpData(const QString& sourceAddress,
                   in_port_t sourcePort,
                   const QString& destinationAddress,
                   in_port_t destinationPort,
                   uint64_t timestamp,
                   uint16_t payload);

      // Process 'End TCP connection'.
      void endTcpConnection(const QString& sourceAddress,
                            in_port_t sourcePort,
                            const QString& destinationAddress,
                            in_port_t destinationPort,
                            uint64_t timestamp,
                            uint64_t transferredClient,
                            uint64_t transferredServer);

  private:
      // Open connections.
      std::map<Connection::Key, Connection> m_openConnections;

      // Closed connections.
      std::vector<Connection> m_closedConnections;
  };

  inline Connection::Key::Key(const QString& addr1,
                              in_port_t port1,
                              const QString& addr2,
                              in_port_t port2)
    : m_addr1(addr1),
      m_port1(port1),
      m_addr2(addr2),
      m_port2(port2)
  {
  }

  inline
  Connection::Key Connection::Key::build(const QString& sourceAddress,
                                         in_port_t sourcePort,
                                         const QString& destinationAddress,
                                         in_port_t destinationPort)
  {
    if (sourcePort < destinationPort) {
      return Key{sourceAddress,
                 sourcePort,
                 destinationAddress,
                 destinationPort};
    } else if (sourcePort > destinationPort) {
      return Key{destinationAddress,
                 destinationPort,
                 sourceAddress,
                 sourcePort};
    } else if (sourceAddress <= destinationAddress) {
      return Key{sourceAddress,
                 sourcePort,
                 destinationAddress,
                 destinationPort};
    } else {
      return Key{destinationAddress,
                 destinationPort,
                 sourceAddress,
                 sourcePort};
    }
  }

  inline bool Connection::Key::operator<(const Key& other) const
  {
    if (m_port1 < other.m_port1) {
      return true;
    } else if (m_port1 == other.m_port1) {
      if (m_port2 < other.m_port2) {
        return true;
      } else if (m_port2 == other.m_port2) {
        int cmp = m_addr1.compare(other.m_addr1);
        if (cmp < 0) {
          return true;
        } else if (cmp == 0) {
          return (m_addr2.compare(other.m_addr2) < 0);
        }
      }
    }

    return false;
  }

  inline Connection::Payload::Payload(Direction direction,
                                      uint64_t timestamp,
                                      uint16_t size)
    : m_direction(direction),
      m_timestamp(timestamp),
      m_size(size)
  {
  }

  inline Connection::Payload::Direction Connection::Payload::direction() const
  {
    return m_direction;
  }

  inline uint64_t Connection::Payload::timestamp() const
  {
    return m_timestamp;
  }

  inline uint16_t Connection::Payload::size() const
  {
    return m_size;
  }

  inline Connection::Connection(const QString& clientIp,
                                const QString& clientHostname,
                                in_port_t clientPort,
                                const QString& serverIp,
                                const QString& serverHostname,
                                in_port_t serverPort,
                                uint64_t begin)
    : m_clientIp(clientIp),
      m_clientHostname(clientHostname),
      m_clientPort(clientPort),
      m_client(QString("%1:%2")
               .arg(m_clientHostname.isEmpty() ? m_clientIp : m_clientHostname)
               .arg(m_clientPort)),
      m_serverIp(serverIp),
      m_serverHostname(serverHostname),
      m_serverPort(serverPort),
      m_server(QString("%1:%2")
               .arg(m_serverHostname.isEmpty() ? m_serverIp : m_serverHostname)
               .arg(m_serverPort)),
      m_begin(begin)
  {
  }

  inline const QString& Connection::clientIp() const
  {
    return m_clientIp;
  }

  inline const QString& Connection::clientHostname() const
  {
    return m_clientHostname;
  }

  inline in_port_t Connection::clientPort() const
  {
    return m_clientPort;
  }

  inline const QString& Connection::client() const
  {
    return m_client;
  }

  inline const QString& Connection::serverIp() const
  {
    return m_serverIp;
  }

  inline const QString& Connection::serverHostname() const
  {
    return m_serverHostname;
  }

  inline in_port_t Connection::serverPort() const
  {
    return m_serverPort;
  }

  inline const QString& Connection::server() const
  {
    return m_server;
  }

  inline uint64_t Connection::begin() const
  {
    return m_begin;
  }

  inline uint64_t Connection::end() const
  {
    return m_end;
  }

  inline void Connection::end(uint64_t end)
  {
    m_end = end;
  }

  inline uint64_t Connection::clientPayload() const
  {
    return m_clientPayload;
  }

  inline void Connection::addClientPayload(uint64_t timestamp, uint16_t payload)
  {
    m_clientPayload += payload;

    m_payloads.emplace_back(Payload::Direction::from_client,
                            timestamp,
                            payload);
  }

  inline uint64_t Connection::serverPayload() const
  {
    return m_serverPayload;
  }

  inline void Connection::addServerPayload(uint64_t timestamp, uint16_t payload)
  {
    m_serverPayload += payload;

    m_payloads.emplace_back(Payload::Direction::from_server,
                            timestamp,
                            payload);
  }

  inline uint64_t Connection::transferredClient() const
  {
    return m_transferredClient;
  }

  inline void Connection::transferredClient(uint64_t transferred)
  {
    m_transferredClient = transferred;
  }

  inline uint64_t Connection::transferredServer() const
  {
    return m_transferredServer;
  }

  inline void Connection::transferredServer(uint64_t transferred)
  {
    m_transferredServer = transferred;
  }

  inline const std::vector<Connection::Payload>& Connection::payloads() const
  {
    return m_payloads;
  }

  inline void Connections::clear()
  {
    m_openConnections.clear();
    m_closedConnections.clear();
  }

  inline const std::map<Connection::Key, Connection>&
  Connections::openConnections() const
  {
    return m_openConnections;
  }

  inline const std::vector<Connection>& Connections::closedConnections() const
  {
    return m_closedConnections;
  }
} // namespace event

#endif // CONNECTION_H
