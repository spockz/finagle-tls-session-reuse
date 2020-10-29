package com.github.spockz.finagle.it.tls

import java.net.InetSocketAddress
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}

import com.twitter.finagle
import com.twitter.finagle.Http.Client
import com.twitter.finagle.http.{Request, Response, Status}
import com.twitter.finagle.netty4.ssl.client.Netty4ClientEngineFactory
import com.twitter.finagle.ssl._
import com.twitter.finagle.ssl.client.{SslClientConfiguration, SslClientEngineFactory, SslClientSessionVerifier, SslContextClientEngineFactory}
import com.twitter.finagle.{Address, Http, ListeningServer, Service}
import com.twitter.util.{Await, Duration, Future, Return}
import javax.net.ssl.SSLSession
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import com.github.spockz.finagle.tls.TlsUtil.{createKeyManagerFactory, createMutualTlsContext, createTrustManagerFactory}

import scala.collection.concurrent.TrieMap

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

  it should "support session resumption with SslClientConfiguration and a cached Netty4ClientEngineFactory" in {
    testClientResumptionWithClient(addTlsWithSslClientConfigurationAndCachedNetty4ClientEngineFactory)
  }

  it should "support session resumption with SslClientConfiguration and a SslContextEngineFactory" in {
    testClientResumptionWithClient(addTlsWithSslClientConfigurationAndSslContextEngineFactory)
  }
  it should "support session resumption with SslClientConfiguration and a cached SslContextEngineFactory" in {
    testClientResumptionWithClient(addTlsWithSslClientConfigurationAndCachedSslContextEngineFactory)
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

    info("###")
    info("### First call")
    // make two calls
    info(Await.result(client(Request()).liftToTry, Duration.fromSeconds(1)).toString) //.headerMap should contain("Connection" -> "close")

    info("###")
    info("###Second call")

    val res2 = Await.result(client(Request()).liftToTry, Duration.fromSeconds(1)) //.headerMap should contain("Connection" -> "close")
    info(res2.toString)

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
      TrustCredentialsConfig.trustManagerFactory(
        createTrustManagerFactory(getClass.getResourceAsStream("/trust.jks"), "changeme")
      ),
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

    _.withTransport.tls(clientConfiguration)
  }

  val addTlsWithSslClientConfigurationAndCachedNetty4ClientEngineFactory: Client => Client = {
    val clientConfiguration = SslClientConfiguration(
      Option.empty,
      KeyCredentials.Unspecified,
      TrustCredentialsConfig.trustManagerFactory(
        createTrustManagerFactory(getClass.getResourceAsStream("/trust.jks"), "changeme")
      ),
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

    _.withTransport.tls(clientConfiguration, new CachingSslClientEngineFactory(Netty4ClientEngineFactory.apply()))
  }

  val addTlsWithSslClientConfigurationAndSslContextEngineFactory: Client => Client = {
    val clientConfiguration = SslClientConfiguration(
      Option.empty,
      KeyCredentials.Unspecified,
      TrustCredentials.Unspecified,
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

    _.withTransport.tls(clientConfiguration, new SslContextClientEngineFactory(createMutalTlsContext))
  }

  val addTlsWithSslClientConfigurationAndCachedSslContextEngineFactory: Client => Client = {
    val clientConfiguration = SslClientConfiguration(
      Option.empty,
      KeyCredentials.Unspecified,
      TrustCredentials.Unspecified,
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

    _.withTransport.tls(clientConfiguration, new CachingSslClientEngineFactory(new SslContextClientEngineFactory(createMutalTlsContext)))
  }

  class CachingSslClientEngineFactory(underlying: SslClientEngineFactory) extends SslClientEngineFactory {

    private val cache: TrieMap[(Address, SslClientConfiguration), Engine] =
      TrieMap.empty

    override def apply(address: Address, config: SslClientConfiguration): Engine =
      cache.getOrElseUpdate((address, config), underlying(address, config))
  }

  def configureWithSessionTracker(sessionVerifier: SslClientSessionVerifier): Client => Client =
    _.configured(SslClientSessionVerifier.Param(sessionVerifier))


}
