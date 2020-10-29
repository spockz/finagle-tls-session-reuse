package com.github.spockz.finagle.tls

import java.io.InputStream
import java.security.KeyStore

import javax.net.ssl.{KeyManagerFactory, SSLContext, TrustManagerFactory}

object TlsUtil {
  def createMutualTlsContextFromResource(keyStore: String,
                                         keyStoreType: String,
                                         keyStorePassphrase: String,
                                         privateKeyPassphrase: String,
                                         trustKeystore: String,
                                         trustKeystorePassphrase: String
                                        ) =
    createMutualTlsContext(getClass.getResourceAsStream(keyStore), keyStoreType, keyStorePassphrase, privateKeyPassphrase, getClass.getResourceAsStream(trustKeystore), trustKeystorePassphrase)

  def createMutualTlsContext(keyStore: InputStream,
                             keyStoreType: String,
                             keyStorePassphrase: String,
                             privateKeyPassphrase: String,
                             trustKeystore: InputStream,
                             trustKeystorePassphrase: String): SSLContext = {
    require(Option(keyStore).isDefined, "Client keystore must be defined")
    require(Option(trustKeystore).isDefined, "Trust store must be defined")

    val kmf: KeyManagerFactory =
      createKeyManagerFactory(keyStore, keyStoreType, keyStorePassphrase, privateKeyPassphrase)

    val tmf: TrustManagerFactory =
      createTrustManagerFactory(trustKeystore, trustKeystorePassphrase)

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(kmf.getKeyManagers, tmf.getTrustManagers, null)
    sslContext
  }

  def createTrustManagerFactory(trustKeystore: InputStream, trustKeystorePassphrase: String): TrustManagerFactory = {
    require(Option(trustKeystore).isDefined, "Trust store must be defined")

    val trustKeystorePassphraseChars = trustKeystorePassphrase.toCharArray

    val ksTrust = KeyStore.getInstance("JKS")
    ksTrust.load(trustKeystore, trustKeystorePassphraseChars)

    // TrustManagers decide whether to allow connections
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    tmf.init(ksTrust)
    tmf
  }

  def createKeyManagerFactory(keyStore: InputStream,
                              keyStoreType: String,
                              keyStorePassphrase: String,
                              privateKeyPassphrase: String): KeyManagerFactory = {
    require(Option(keyStore).isDefined, "Client keystore must be defined")

    // Create and initialize the SSLContext with key material
    val clientKeystorePassphraseChars = keyStorePassphrase.toCharArray
    val clientKeyPassphraseChars = privateKeyPassphrase.toCharArray

    // First initialize the key and trust material
    val ksKeys = KeyStore.getInstance(keyStoreType)
    ksKeys.load(keyStore, clientKeystorePassphraseChars)

    // KeyManagers decide which key material to use
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    kmf.init(ksKeys, clientKeyPassphraseChars)
    kmf
  }
}
