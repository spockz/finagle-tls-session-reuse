package com.ing.apisdk.toolkit.connectivity.transport.http

import java.io.InputStream
import java.net.InetSocketAddress
import java.security.KeyStore
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}

import scala.collection.concurrent.TrieMap
import com.twitter.finagle
import com.twitter.finagle.Http.Client
import com.twitter.finagle.http.{Request, Response, Status}
import com.twitter.finagle.netty4.ssl.client.Netty4ClientEngineFactory
import com.twitter.finagle.ssl._
import com.twitter.finagle.ssl.client.{SslClientConfiguration, SslClientEngineFactory, SslClientSessionVerifier}
import com.twitter.finagle.{Address, Http, ListeningServer, Service}
import com.twitter.util.{Await, Duration, Future, Return}
import javax.net.ssl.{KeyManagerFactory, SSLContext, SSLSession, TrustManagerFactory}
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

class TlsTest extends AnyFlatSpec with Matchers {

  behavior of "Tls on server and client"

  it should "support session resumption with ssl context" in {
    testClientResumptionWithClient(addTlsFromResource)
  }

  it should "support session resumption with SslClientConfiguration" in {
    testClientResumptionWithClient(addTlsWithSslClientConfigurationFromKeystores)
  }

  it should "support session resumption with SslClientConfiguration read from PEMS" in {
    testClientResumptionWithClient(addTlsWithSslClientConfigurationFromPems)
  }

  it should "support session resumption with SslClientConfiguration and a caching ssl client engine factory" in {
    testClientResumptionWithClient(addTlsWithSslClientConfigurationAndCachingSslClientEngineFactory)
  }

  private def testClientResumptionWithClient(clientModifier: Client => Client): Unit = {
    // create server which closes the connection
    val server =
      finagle.Http.server.withTransport
        .tls(
          createMutalTlsContext
        )
        .serve(
          "localhost:0",
          Service.mk[Request, Response] {
            //Use keepAlive(false) to signal Finagle server to close the connection.
            req => Future.value(Response(Status.Created).keepAlive(false))
          }
        )

    val counter = new AtomicInteger();
    val sessionIds = new AtomicReference[Set[String]](Set.empty)

    val sessionTracker =
      new SslClientSessionVerifier {
        override def apply(address: Address, config: SslClientConfiguration, session: SSLSession): Boolean = {
          counter.incrementAndGet()
          sessionIds.updateAndGet(_ + session.getId.mkString(""))
          true
        }
      }

    // create client with a verifies that captures the session ids
    // Connect
    val client = createClient(server, clientModifier.andThen(configureWithSessionTracker(sessionTracker)))

    info("""###\n###First call\n###""")
    // make two calls
    Await.result(client(Request()).liftToTry) //.headerMap should contain("Connection" -> "close")

    info("""###\n###Second call\n###""")

    val res2 = Await.result(client(Request()).liftToTry) //.headerMap should contain("Connection" -> "close")

    res2 shouldBe a [Return[_]]
    // Amount of verifications should be 2
    counter.intValue() shouldBe 2
    // captured session ids should be singleton set
    sessionIds.get should have size 1
    Await.all(server.close(), client.close())
  }

  private def createMutalTlsContext = {
    createMutualTlsContext(getClass.getResourceAsStream("/identity.jks"),
      "JKS",
      "changeme",
      "changeme",
      getClass.getResourceAsStream("/trust.jks"),
      "changeme")
  }

  def createClient(address: ListeningServer, modifier: Client => Client = identity): Service[Request, Response] =
    modifier(Http.client).newService(s"localhost:${address.boundAddress.asInstanceOf[InetSocketAddress].getPort}", "somelabel")

  val addTlsFromResource: Client => Client =
    _.withTransport.tls(createMutalTlsContext)

  val addTlsWithSslClientConfigurationFromKeystores: Client => Client = {

    val clientConfiguration = SslClientConfiguration(
      Option.empty,
      KeyCredentialsConfig.keyManagerFactory(
        createKeyManagerFactory(getClass.getResourceAsStream("/identity.jks"), "JKS", "changeme", "changeme")
      ),
      TrustCredentialsConfig.trustManagerFactory(
        createTrustManagerFactory(getClass.getResourceAsStream("/trust.jks"), "changeme")
      ),
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

    _.withTransport.tls(clientConfiguration)
  }

  val addTlsWithSslClientConfigurationFromPems: Client => Client = {
    val clientConfiguration = SslClientConfiguration(
      Option.empty,
      KeyCredentials.Unspecified,
      TrustCredentials.Insecure,
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

    _.withTransport.tls(clientConfiguration)
  }

  val addTlsWithSslClientConfigurationAndCachingSslClientEngineFactory: Client => Client = {
    val clientConfiguration = SslClientConfiguration(
      Option.empty,
      KeyCredentials.Unspecified,
      TrustCredentials.Insecure,
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

    _.withTransport.tls(clientConfiguration, new CachingSslClientEngineFactory(Netty4ClientEngineFactory.apply()))
  }

  class CachingSslClientEngineFactory(underlying: SslClientEngineFactory) extends SslClientEngineFactory {

    private val cache: TrieMap[(Address, SslClientConfiguration), Engine] =
      TrieMap.empty

    override def apply(address: Address, config: SslClientConfiguration): Engine =
      cache.getOrElseUpdate((address, config), underlying(address, config))
  }

  def configureWithSessionTracker(sessionVerifier: SslClientSessionVerifier): Client => Client =
    _.configured(SslClientSessionVerifier.Param(sessionVerifier))


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
