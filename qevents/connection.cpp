#include "connection.h"

namespace event {

void Connections::beginTcpConnection(const QString& sourceAddress,
                                     const QString& sourceHostname,
                                     in_port_t sourcePort,
                                     const QString& destinationAddress,
                                     const QString& destinationHostname,
                                     in_port_t destinationPort,
                                     uint64_t timestamp)
{
  // Build connection key.
  Connection::Key key = Connection::Key::build(sourceAddress,
                                               sourcePort,
                                               destinationAddress,
                                               destinationPort);

  // Search connection.
  std::map<Connection::Key, Connection>::iterator
    it = m_openConnections.find(key);

  // If the connection has been found...
  if (it != m_openConnections.end()) {
    // Add connection to the list of closed connections.
    m_closedConnections.emplace_back(std::move(it->second));

    // Remove open connection.
    m_openConnections.erase(it);
  }

  Connection conn(sourceAddress,
                  sourceHostname,
                  sourcePort,
                  destinationAddress,
                  destinationHostname,
                  destinationPort,
                  timestamp);

  // Add connection.
  m_openConnections.emplace(std::piecewise_construct,
                            std::forward_as_tuple(key),
                            std::forward_as_tuple(conn));
}

void Connections::tcpData(const QString& sourceAddress,
                          in_port_t sourcePort,
                          const QString& destinationAddress,
                          in_port_t destinationPort,
                          uint64_t timestamp,
                          uint16_t payload)
{
  // Build connection key.
  Connection::Key key = Connection::Key::build(sourceAddress,
                                               sourcePort,
                                               destinationAddress,
                                               destinationPort);

  // Search connection.
  std::map<Connection::Key, Connection>::iterator
    it = m_openConnections.find(key);

  // If the connection has been found...
  if (it != m_openConnections.end()) {
    // Client payload?
    if ((sourcePort == it->second.clientPort()) &&
        (sourceAddress == it->second.clientIp())) {
      it->second.addClientPayload(timestamp, payload);
    } else {
      it->second.addServerPayload(timestamp, payload);
    }
  }
}

void Connections::endTcpConnection(const QString& sourceAddress,
                                   in_port_t sourcePort,
                                   const QString& destinationAddress,
                                   in_port_t destinationPort,
                                   uint64_t timestamp,
                                   uint64_t transferredClient,
                                   uint64_t transferredServer)
{
  // Build connection key.
  Connection::Key key = Connection::Key::build(sourceAddress,
                                               sourcePort,
                                               destinationAddress,
                                               destinationPort);

  // Search connection.
  std::map<Connection::Key, Connection>::iterator
    it = m_openConnections.find(key);

  // If the connection has been found...
  if (it != m_openConnections.end()) {
    it->second.end(timestamp);

    it->second.transferredClient(transferredClient);
    it->second.transferredServer(transferredServer);

    // Add connection to the list of closed connections.
    m_closedConnections.emplace_back(std::move(it->second));

    // Remove open connection.
    m_openConnections.erase(it);
  }
}

} // namespace event
