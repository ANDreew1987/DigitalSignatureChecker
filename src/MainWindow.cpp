#include "MainWindow.hpp"
#include "ui_MainWindow.h"

#include "ImageLib/UI/ImageLibUI.hpp"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
	m_FilterProgress(new QProgressBar(this)),
	m_CurrentWidget(nullptr),
	m_Filters(GetFilters())
{
    ui->setupUi(this);

	connect(ui->pbApply, SIGNAL(clicked()), this, SLOT(applyFilter()));
	connect(ui->cbFilters, SIGNAL(currentIndexChanged(int)), this, SLOT(filterSelected(int)));

	m_FilterProgress->setRange(0, 100);

	ui->statusBar->addWidget(m_FilterProgress);

	for (auto f : m_Filters) {
		f->setParent(this);
		ui->cbFilters->addItem(f->filterName());
		connect(f, SIGNAL(progressChanged(int)), m_FilterProgress, SLOT(setValue(int)));
		connect(f, SIGNAL(filterStarted()), this, SLOT(filterStarted()));
		connect(f, SIGNAL(filterStopped()), this, SLOT(filterStopped()));
	}
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::applyFilter()
{
	QFilterUI *f = m_Filters[ui->cbFilters->currentIndex()];
	f->apply();
}

void MainWindow::filterStarted()
{
	ui->pbApply->setEnabled(false);
	ui->dockWidget->setEnabled(false);
}

void MainWindow::filterStopped()
{
	ui->pbApply->setEnabled(true);
	ui->dockWidget->setEnabled(true);
}

void MainWindow::filterSelected(int idx)
{
	if (m_CurrentWidget) {
		ui->frame->layout()->removeWidget(m_CurrentWidget);
	}
	m_CurrentWidget = m_Filters[idx];
	if (m_CurrentWidget) {
		ui->frame->layout()->addWidget(m_CurrentWidget);
	}
}
