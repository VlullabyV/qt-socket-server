#include <QCoreApplication>
#include <QFile>
#include <QDebug>
#include <QSslCertificate>
#include <QSslKey>
#include <iostream>

#include "sslserver.h"

int main(int argc, char **argv)
{
    std::cout <<  "Entrei no main\n";
    QCoreApplication app(argc, argv);

    QFile certFile(argv[1]);
    if (!certFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Unable to load certificate";
        return 1;
    }

    QFile keyFile(argv[2]);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Unable to load key";
        return 1;
    }

    QSslCertificate cert(&certFile);
    QSslKey key(&keyFile, QSsl::Rsa);

    SslServer server(cert, key);

    return app.exec();
}
