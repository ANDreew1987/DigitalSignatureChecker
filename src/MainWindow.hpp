#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include <QProgressBar>

#include "ImageLib/UI/FilterUI.hpp"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public Q_SLOTS:

	void applyFilter();

	void filterStarted();
	void filterStopped();

	void filterSelected(int);

private:
    Ui::MainWindow *ui;
	
	QProgressBar *m_FilterProgress;
	std::vector<QFilterUI*> m_Filters;
	QWidget *m_CurrentWidget;
};

#endif // MAINWINDOW_HPP
