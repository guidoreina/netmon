#include <QFile>
#include <QFileDialog>
#include <QJsonDocument>
#include <QMessageBox>
#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
  : QMainWindow(parent),
    m_ui(new Ui::MainWindow)
{
  m_ui->setupUi(this);

  // Make tables read-only.
  m_ui->connections->setEditTriggers(QTableView::NoEditTriggers);
  m_ui->payloads->setEditTriggers(QTableView::NoEditTriggers);

  // Select rows.
  m_ui->connections->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->payloads->setSelectionBehavior(QAbstractItemView::SelectRows);

  // Connect menu item "Open" to method onOpen().
  connect(m_ui->actionOpen, &QAction::triggered, this, &MainWindow::onOpen);

  connect(m_ui->ipAddresses,
          &QListWidget::currentItemChanged,
          this,
          &MainWindow::onIpAddress);

  connect(m_ui->hosts,
          &QListWidget::currentItemChanged,
          this,
          &MainWindow::onHost);

  connect(m_ui->connections,
          &QTableWidget::currentItemChanged,
          this,
          &MainWindow::onConnection);

  // Add headers to the connection table.
  static const QStringList connectionColumns = {"Begin",
                                                "End",
                                                "Client",
                                                "Server",
                                                "Transferred client",
                                                "Transferred server"};

  // Set number of columns.
  m_ui->connections->setColumnCount(connectionColumns.size());

  m_ui->connections->setHorizontalHeaderLabels(connectionColumns);

  // Add headers to the payload table.
  static const QStringList payloadColumns = {"Timestamp", "From", "Size"};

  // Set number of columns.
  m_ui->payloads->setColumnCount(payloadColumns.size());

  m_ui->payloads->setHorizontalHeaderLabels(payloadColumns);
}

MainWindow::~MainWindow()
{
  delete m_ui;
}

void MainWindow::onOpen()
{
  // Get filename from the user.
  QString filename = QFileDialog::getOpenFileName(this,
                                                  "Open file",
                                                  ".",
                                                  "JSON (*.json)");

  // If no file has been selected...
  if (filename.isEmpty()) {
    return;
  }

  // Open file for reading.
  QFile file(filename);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    QMessageBox msgBox(QMessageBox::Warning,
                       "Error",
                       "Error opening file '" + filename + "' for reading.");

    msgBox.exec();

    return;
  }

  // Read file content.
  QByteArray data = file.readAll();

  // Close file.
  file.close();

  // Parse JSON file.
  QJsonDocument doc = QJsonDocument::fromJson(data);

  // If the document is invalid...
  if (doc.isNull()) {
    QMessageBox msgBox(QMessageBox::Warning,
                       "Error",
                       "Invalid JSON document '" + filename + "'.");

    msgBox.exec();

    return;
  }

  // Clear events.
  m_events.clear();

  // Clear connections.
  m_connections.clear();

  // Load events.
  m_events.load(doc.array(), m_connections);

  // Add IP addresses.
  const std::set<QString>& ipAddresses = m_events.ipAddresses();
  for (const QString& ipAddress : ipAddresses) {
    m_ui->ipAddresses->addItem(ipAddress);
  }

  // Add hosts.
  const std::set<QString>& hosts = m_events.hosts();
  for (const QString& host : hosts) {
    m_ui->hosts->addItem(host);
  }
}

void MainWindow::onIpAddress(QListWidgetItem* item, QListWidgetItem* previous)
{
  std::ignore = previous;

  m_ui->labelConnections->setText("Connections from/to " + item->text() + ":");

  fillConnections([item](const event::Connection& conn) {
                    return ((item->text() == conn.clientIp()) ||
                            (item->text() == conn.serverIp()));
                  });
}

void MainWindow::onHost(QListWidgetItem* item, QListWidgetItem* previous)
{
  std::ignore = previous;

  m_ui->labelConnections->setText("Connections from/to " + item->text() + ":");

  fillConnections([item](const event::Connection& conn) {
                    return ((item->text() == conn.clientHostname()) ||
                            (item->text() == conn.serverHostname()));
                  });
}

void MainWindow::onConnection(QTableWidgetItem* current,
                              QTableWidgetItem* previous)
{
  std::ignore = previous;

  // Get connection.
  const event::Connection&
    conn = m_connections.closedConnections()[
             m_connectionIndices[current->tableWidget()->row(current)]
           ];

  m_ui->labelConnection->setText("Payloads for connection " +
                                 conn.client() +
                                 " -> " +
                                 conn.server() +
                                 ":");

  // Clear table contents.
  m_ui->payloads->setRowCount(0);

  const std::vector<event::Connection::Payload>& payloads = conn.payloads();

  // For each payload...
  for (const event::Connection::Payload& payload : payloads) {
    // Get number of rows.
    int row = m_ui->payloads->rowCount();

    // Insert row.
    m_ui->payloads->insertRow(row);

    // Set items.
    m_ui->payloads->setItem(row,
                            0,
                            new QTableWidgetItem(
                              getTimeString(payload.timestamp())
                            )
    );

    if (payload.direction() ==
        event::Connection::Payload::Direction::from_client) {
      m_ui->payloads->setItem(row, 1, new QTableWidgetItem("Client"));
    } else {
      m_ui->payloads->setItem(row, 1, new QTableWidgetItem("Server"));
    }

    QString size;
    size.setNum(payload.size());

    m_ui->payloads->setItem(row, 2, new QTableWidgetItem(size));
  }
}

void MainWindow::fillConnections(const std::function<
                                         bool(const event::Connection&)
                                       >& match)
{
  // Clear connection indices.
  m_connectionIndices.clear();

  // Clear table contents.
  m_ui->connections->setRowCount(0);

  // Get closed connections.
  const std::vector<event::Connection>&
    closedConnections = m_connections.closedConnections();

  // For each closed connection...
  int idx = 0;
  for (const event::Connection& conn : closedConnections) {
    if (match(conn)) {
      QString transferredClient;
      transferredClient.setNum(conn.transferredClient());

      QString transferredServer;
      transferredServer.setNum(conn.transferredServer());

      // Get number of rows.
      int row = m_ui->connections->rowCount();

      // Insert row.
      m_ui->connections->insertRow(row);

      // Set items.
      m_ui->connections->setItem(row,
                                 0,
                                 new QTableWidgetItem(
                                   getTimeString(conn.begin())
                                 )
      );

      m_ui->connections->setItem(row,
                                 1,
                                 new QTableWidgetItem(
                                   getTimeString(conn.end())
                                 )
      );

      m_ui->connections->setItem(row, 2, new QTableWidgetItem(conn.client()));
      m_ui->connections->setItem(row, 3, new QTableWidgetItem(conn.server()));

      m_ui->connections->setItem(row,
                                 4,
                                 new QTableWidgetItem(transferredClient));

      m_ui->connections->setItem(row,
                                 5,
                                 new QTableWidgetItem(transferredServer));

      m_connectionIndices.push_back(idx);
    }

    idx++;
  }
}

QString MainWindow::getTimeString(uint64_t timestamp)
{
  time_t t = static_cast<time_t>(timestamp / 1000000);
  struct tm tm;
  localtime_r(&t, &tm);

  QString res = QString("%1/%2/%3 %4:%5:%6.%7")
                .arg(1900 + tm.tm_year, 4, 10, QChar('0'))
                .arg(1 + tm.tm_mon, 2, 10, QChar('0'))
                .arg(tm.tm_mday, 2, 10, QChar('0'))
                .arg(tm.tm_hour, 2, 10, QChar('0'))
                .arg(tm.tm_min, 2, 10, QChar('0'))
                .arg(tm.tm_sec, 2, 10, QChar('0'))
                .arg(static_cast<unsigned>(timestamp % 1000000),
                     6,
                     10,
                     QChar('0'));

  return res;
}
