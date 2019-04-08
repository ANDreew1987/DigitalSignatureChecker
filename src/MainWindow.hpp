#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>

#include <string>
#include <memory>

#include <openssl/rsa.h>

using std::string;
using std::unique_ptr;

using BIO_ptr = unique_ptr<BIO, decltype(&BIO_free)>;
using RSA_ptr = unique_ptr<RSA, decltype(&RSA_free)>;
using BIGNUM_ptr = unique_ptr<BIGNUM, decltype(&BN_free)>;

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


private slots:
    void on_pbGenKeys_clicked();
    void on_pbGenPrivateKeyFile_clicked();
    void on_pbGenPublicKeyFile_clicked();
    void on_pbFileToSign_clicked();
    void on_pbSignPrivateKey_clicked();
    void on_pbSignFile_clicked();
    void on_pbSign_clicked();
    void on_pbFileToVerify_clicked();
    void on_pbVerifyPublicKey_clicked();
    void on_pbVerifySignFile_clicked();
    void on_pbVerify_clicked();
private:
    Ui::MainWindow *ui;

    string strPrivateKeyFile;
    string strPublicKeyFile;
    string strFile;
    string strSign;

    void GenerateKeyPair(
        const string &prKeyFileName,
        const string &pubKeyFileName) noexcept(false);
    void SignFile(
        const string &fileName, 
        const string &prKeyFileName,
        const string &sigFileName) noexcept(false);
    void VerifyFile(
        const string &fileName, 
        const string &pubKeyFileName,
        const string &sigFileName) noexcept(false);
};

#endif // MAINWINDOW_HPP
