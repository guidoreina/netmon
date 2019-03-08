#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <functional>
#include <QMainWindow>
#include <QListWidgetItem>
#include <QTableWidgetItem>
#include "event.h"

namespace Ui {
  class MainWindow;
}

class MainWindow : public QMainWindow {
  Q_OBJECT

  public:
    // Constructor.
    explicit MainWindow(QWidget *parent = nullptr);

    // Destructor.
    ~MainWindow();

  private slots:
    // On file open.
    void onOpen();

    // On IP address selected.
    void onIpAddress(QListWidgetItem* item, QListWidgetItem* previous);

    // On host selected.
    void onHost(QListWidgetItem* item, QListWidgetItem* previous);

    // On connection selected.
    void onConnection(QTableWidgetItem* current, QTableWidgetItem* previous);

  private:
    // Events.
    event::Events m_events;

    // Connections.
    event::Connections m_connections;

    // Connections.
    std::vector<int> m_connectionIndices;

    // Main window.
    Ui::MainWindow* m_ui;

    // Fill connections.
    void fillConnections(const std::function<
                                 bool(const event::Connection&)
                               >& match);

    // Get time string.
    static QString getTimeString(uint64_t timestamp);
};

#endif // MAINWINDOW_H
