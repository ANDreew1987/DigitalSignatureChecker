#include "MainWindow.hpp"
#include "ui_MainWindow.h"

#include <stdexcept>
#include <vector>
#include <fstream>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <QMessageBox>
#include <QFileDialog>

using std::vector;
using std::ifstream;
using std::ofstream;
using std::runtime_error;

using ByteArray = vector<char>;
using EVP_MD_CTX_ptr = unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

const int keyLenght = 4096;

static int OpenSSLErrorCB(const char *cs, size_t cslen, void *str)
{
    if (str)
    {
        reinterpret_cast<std::string*>(str)->append(cs, cslen);
        return 1;
    }
    return 0;
}

static void HandleErrors() noexcept(false)
{
    std::string str;
    ERR_print_errors_cb(OpenSSLErrorCB, &str);
    throw runtime_error(str);
}

void GeneratePublicKey(
    const string &fileName, 
    RSA_ptr &rsa) noexcept(false)
{
    BIO_ptr bp_public{ BIO_new_file(fileName.c_str(), "wb"), BIO_free };
    if (PEM_write_bio_RSAPublicKey(bp_public.get(), rsa.get()) != 1)
    {
        HandleErrors();
    }
}

void GeneratePrivateKey(
    const string &fileName, 
    RSA_ptr &rsa) noexcept(false)
{
    BIO_ptr bp_private{ BIO_new_file(fileName.c_str(), "wb"), BIO_free };
    if (PEM_write_bio_RSAPrivateKey(
        bp_private.get(), rsa.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        HandleErrors();
    }
}

RSA_ptr CreateRSA(
    BIGNUM_ptr &bn) noexcept(false)
{
    RSA_ptr rsa{ RSA_new(), RSA_free };
    if (RSA_generate_key_ex(rsa.get(), keyLenght, bn.get(), nullptr) != 1)
    {
        HandleErrors();
    }
    return rsa;
}

BIGNUM_ptr CreateBigNum() noexcept(false)
{
    BIGNUM_ptr bn{ BN_new(), BN_free };
    if (BN_set_word(bn.get(), RSA_F4) != 1)
    {
        HandleErrors();
    }
    return bn;
}

BIO_ptr LoadKey(
    const string &fileName) noexcept(false)
{
    BIO_ptr input{ BIO_new(BIO_s_file()), BIO_free };
    if (BIO_read_filename(input.get(), fileName.c_str()) <= 0)
    {
        HandleErrors();
    }
    return input;
}

RSA_ptr LoadPrivateKey(
    const string &fileName) noexcept(false)
{
    BIO_ptr input = LoadKey(fileName);
    RSA *rsa = nullptr;
    rsa = PEM_read_bio_RSAPrivateKey(input.get(), &rsa, nullptr, nullptr);
    RSA_ptr result{ rsa, RSA_free };
    return result;
}

RSA_ptr LoadPublicKey(
    const string &fileName) noexcept(false)
{
    BIO_ptr input = LoadKey(fileName);
    RSA *rsa = nullptr;
    rsa = PEM_read_bio_RSAPublicKey(input.get(), &rsa, nullptr, nullptr);
    RSA_ptr result{ rsa, RSA_free };
    return result;
}

ByteArray ReadFile(
    const string &fileName)
{
    ifstream ifs(fileName, ifstream::binary | ifstream::ate);
    ifstream::pos_type pos = ifs.tellg();
    ByteArray result(pos);
    ifs.seekg(0, ifstream::beg);
    ifs.read(result.data(), pos);
    return result;
}

void WriteFile(
    const string &fileName,
    const ByteArray &data)
{
    ofstream ofs(fileName, ofstream::binary | ofstream::ate);
    ofs.write(data.data(), data.size());
}

MainWindow::MainWindow(
    QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    strPrivateKeyFile = ui->leGenPrivateKeyFile->text().toStdString();
    strPublicKeyFile = ui->leGenPublicKeyFile->text().toStdString();
    strFile = ui->leFileToSign->text().toStdString();
    strSign = ui->leSignFile->text().toStdString();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::GenerateKeyPair(
    const string &prKeyFileName,
    const string &pubKeyFileName) noexcept(false)
{
    BIGNUM_ptr bn = CreateBigNum();
    RSA_ptr rsa = CreateRSA(bn);
    ::GeneratePrivateKey(prKeyFileName, rsa);
    ::GeneratePublicKey(pubKeyFileName, rsa);
}

void MainWindow::SignFile(
    const string &fileName, 
    const string &prKeyFileName,
    const string &sigFileName) noexcept(false)
{
    RSA_ptr rsa = LoadPrivateKey(prKeyFileName);
    EVP_PKEY *prKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(prKey, rsa.get());
    EVP_MD_CTX_ptr rsaSigCtx{ EVP_MD_CTX_create(), EVP_MD_CTX_free };
    if (EVP_DigestSignInit(rsaSigCtx.get(), nullptr, EVP_sha512(), nullptr, prKey) <= 0)
    {
        HandleErrors();
    }
    ByteArray inData = ReadFile(fileName);
    if (EVP_DigestSignUpdate(rsaSigCtx.get(), inData.data(), inData.size()) <= 0)
    {
        HandleErrors();
    }
    size_t encLen = 0;
    if (EVP_DigestSignFinal(rsaSigCtx.get(), nullptr, &encLen) <= 0)
    {
        HandleErrors();
    }
    ByteArray sig(encLen);
    if (EVP_DigestSignFinal(rsaSigCtx.get(),
        reinterpret_cast<unsigned char*>(sig.data()), &encLen) <= 0)
    {
        HandleErrors();
    }
    WriteFile(sigFileName, sig);
}

void MainWindow::VerifyFile(
    const string &fileName, 
    const string &pubKeyFileName, 
    const string &sigFileName) noexcept(false)
{
    RSA_ptr rsa = LoadPublicKey(pubKeyFileName);
    EVP_PKEY *pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa.get());
    EVP_MD_CTX_ptr rsaVerifyCtx{ EVP_MD_CTX_create(), EVP_MD_CTX_free };
    if (EVP_DigestVerifyInit(rsaVerifyCtx.get(), nullptr, EVP_sha512(), nullptr, pubKey) <= 0)
    {
        HandleErrors();
    }
    ByteArray inData = ReadFile(fileName);
    if (EVP_DigestVerifyUpdate(rsaVerifyCtx.get(), inData.data(), inData.size()) <= 0)
    {
        HandleErrors();
    }
    ByteArray sig = ReadFile(sigFileName);
    int authStatus = EVP_DigestVerifyFinal(rsaVerifyCtx.get(),
        reinterpret_cast<unsigned char*>(sig.data()), sig.size());
    if (authStatus == 1)
    {
        return;
    }
    else if (authStatus == 0)
    {
        throw runtime_error("File " + fileName + " not authentic");
    }
    else
    {
        HandleErrors();
    }
}

void MainWindow::on_pbGenKeys_clicked()
{
    try {
        GenerateKeyPair(strPrivateKeyFile, strPublicKeyFile);
    }
    catch (runtime_error &e)
    {
        QMessageBox::critical(this, this->windowTitle(), QString(e.what()), QMessageBox::Ok);
        return;
    }
    QMessageBox::information(this, this->windowTitle(), tr("Keys generated"), QMessageBox::Ok);
}

void MainWindow::on_pbGenPrivateKeyFile_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        tr("Private key"), QDir::currentPath(), "OpenSSL keys (*.pem)");
    if (!fileName.isEmpty())
    {
        strPrivateKeyFile = fileName.toStdString();
        ui->leGenPrivateKeyFile->setText(fileName);
    }
}

void MainWindow::on_pbGenPublicKeyFile_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        tr("Public key"), QDir::currentPath(), "OpenSSL keys (*.pem)");
    if (!fileName.isEmpty())
    {
        strPublicKeyFile = fileName.toStdString();
        ui->leGenPublicKeyFile->setText(fileName);
    }
}

void MainWindow::on_pbFileToSign_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("File to sign"), QDir::currentPath(), "All files (*.*)");
    if (!fileName.isEmpty())
    {
        strFile = fileName.toStdString();
        ui->leFileToSign->setText(fileName);
    }
}

void MainWindow::on_pbSignPrivateKey_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("Private key"), QDir::currentPath(), "OpenSSL keys (*.pem)");
    if (!fileName.isEmpty())
    {
        strPrivateKeyFile = fileName.toStdString();
        ui->leSignPrivateKey->setText(fileName);
    }
}

void MainWindow::on_pbSignFile_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        tr("Sign file"), QDir::currentPath(), "Sign files (*.sign)");
    if (!fileName.isEmpty())
    {
        strSign = fileName.toStdString();
        ui->leSignFile->setText(fileName);
    }
}

void MainWindow::on_pbSign_clicked()
{
    try {
        SignFile(strFile, strPrivateKeyFile, strSign);
    }
    catch (runtime_error &e)
    {
        QMessageBox::critical(this, this->windowTitle(), QString(e.what()), QMessageBox::Ok);
        return;
    }
    QMessageBox::information(this, this->windowTitle(), tr("File signed"), QMessageBox::Ok);
}

void MainWindow::on_pbFileToVerify_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("File to verify"), QDir::currentPath(), "All files (*.*)");
    if (!fileName.isEmpty())
    {
        strFile = fileName.toStdString();
        ui->leFileToVerify->setText(fileName);
    }
}

void MainWindow::on_pbVerifyPublicKey_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("Public key"), QDir::currentPath(), "OpenSSL keys (*.pem)");
    if (!fileName.isEmpty())
    {
        strPublicKeyFile = fileName.toStdString();
        ui->leVerifyPublicKey->setText(fileName);
    }
}

void MainWindow::on_pbVerifySignFile_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        tr("Sign file"), QDir::currentPath(), "Sign files (*.sign)");
    if (!fileName.isEmpty())
    {
        strSign = fileName.toStdString();
        ui->leSignFile->setText(fileName);
    }
}

void MainWindow::on_pbVerify_clicked()
{
    try {
        VerifyFile(strFile, strPublicKeyFile, strSign);
    }
    catch (runtime_error &e)
    {
        QMessageBox::critical(this, this->windowTitle(), QString(e.what()), QMessageBox::Ok);
        return;
    }
    QMessageBox::information(this, this->windowTitle(), tr("File verifed"), QMessageBox::Ok);
}
