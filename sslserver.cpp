#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QStringList>
#include <iostream>

#include "sslserver.h"

struct SslServerPrivate
{
    QSslCertificate cert;
    QSslKey key;
    QSslSocket *sock;
};

SslServer::SslServer(const QSslCertificate &cert, const QSslKey &key, int port)
    : QTcpServer(),
      d(new SslServerPrivate)
{
    d->cert = cert;
    d->key = key;
    d->sock = 0;

    connect(this, SIGNAL(newConnection()), this, SLOT(throwNewConnection()));

    listen(QHostAddress::LocalHost, port);
}

SslServer::~SslServer()
{
    delete d;
}

void SslServer::throwNewConnection(){
  qDebug() << "---->>>>> Nova conexao";

}

void SslServer::ready()
{
    qDebug() << Q_FUNC_INFO;

    d->sock->write("This message is encrypted\n");

    // Slightly evil, but since want to close immediately in this example
    // we aren't going to wait for the main event loop.
    d->sock->waitForBytesWritten(1000);
    d->sock->close();
}

#if QT_VERSION >= 0x050000
void SslServer::incomingConnection(qintptr socketDescriptor)
#else
void SslServer::incomingConnection(int socketDescriptor)
#endif
{
    std::cout << "CONEXAO INICIADA!!\n";
    qDebug() << Q_FUNC_INFO;

    d->sock = new QSslSocket(this);
    if (!d->sock->setSocketDescriptor(socketDescriptor)) {
        qDebug() << "Unable set socket descriptor";

        delete d->sock;
        d->sock = 0;
        return;
    }

    connect(d->sock, SIGNAL(encrypted()), this, SLOT(ready()));

    d->sock->setLocalCertificate(d->cert);
    d->sock->setPrivateKey(d->key);

    d->sock->startServerEncryption();
}

