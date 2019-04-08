QT += core gui widgets

TARGET = App
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

CONFIG += c++11

SOURCES += \
        main.cpp \
        MainWindow.cpp

HEADERS += \
        MainWindow.hpp

FORMS += \
        MainWindow.ui