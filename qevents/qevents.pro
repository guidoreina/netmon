#-------------------------------------------------
#
# Project created by QtCreator 2019-02-08T06:21:09
#
#-------------------------------------------------

QT       += core gui
QMAKE_CXXFLAGS += -g -Wall --pedantic -std=c++11

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = qevents
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    event.cpp \
    connection.cpp

HEADERS  += mainwindow.h \
    connection.h \
    event.h

FORMS    += mainwindow.ui
