#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include "spectre_attack.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);    
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_Login_clicked()
{
    spectre_attack s;
    QString utente = ui->lineEdit->text();
    QString psw = ui->password->text();
    const char *str_user, *str_psw;
    QByteArray array = utente.toLocal8Bit();
    str_user = array.data();
    QByteArray array2 = psw.toLocal8Bit();
    str_psw = array2.data();

    ui->textBrowser->clear();
    ui->textBrowser->append("Utente: ");
    s.attack(ui->textBrowser, str_user, false);
    ui->textBrowser->append("Password: ");
    s.attack(ui->textBrowser, str_psw, false);
    ui->textBrowser->append("");
    ui->textBrowser->update();
 }

void MainWindow::on_leak_Kernel_clicked()
{
    spectre_attack s2;
    ui->textBrowser->clear();
    s2.attack(ui->textBrowser,"",true);
    ui->textBrowser->update();
}
