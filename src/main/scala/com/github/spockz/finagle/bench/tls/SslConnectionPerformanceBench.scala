package com.github.spockz.finagle.bench.tls

import java.util.concurrent.TimeUnit

import com.github.spockz.finagle.FinagleUtil
import com.twitter.finagle
import com.twitter.finagle.http.{Request, Response, Status}
import com.twitter.finagle.ssl._
import com.twitter.finagle.ssl.client.SslClientConfiguration
import com.twitter.finagle.{Http, Service}
import com.twitter.util.{Await, Duration, Future}
import com.github.spockz.finagle.bench.tls.finagle.Netty4ClientSslConfigurations
import com.github.spockz.finagle.tls.{ExternalClientEngineFactory, TlsUtil}
import org.openjdk.jmh.annotations._
import org.openjdk.jmh.infra.Blackhole


@State(Scope.Thread)
@Fork(1)
@BenchmarkMode(Array(Mode.Throughput, Mode.AverageTime, Mode.SingleShotTime))
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 10)
@Measurement(iterations = 10)
class SslConnectionPerformanceBench {

  val server =
    Http.server.withTransport
      .tls(
        TlsUtil
          .createMutualTlsContextFromResource("/identity.jks", "JKS", "changeme", "changeme", "/trust.jks", "changeme")
      )
      .serve(
        "localhost:0",
        Service.mk[Request, Response] {
          //Use keepAlive(false) to signal Finagle server to close the connection.
          req => Future.value(Response(Status.Created).keepAlive(false))
        }
      )

  val sslContextClient =
    Http.client.withTransport
      .tls(TlsUtil.createMutualTlsContextFromResource("/identity.jks", "JKS", "changeme", "changeme", "/trust.jks", "changeme"))
      .newService(FinagleUtil.socketsToName(server.boundAddress), "sslContextClient")

  val netty4ClientEngineFactoryClient =
    Http.client.withTransport
      .tls(
        SslClientConfiguration(
          Option.empty,
          KeyCredentialsConfig.keyManagerFactory(
            TlsUtil.createKeyManagerFactory(getClass.getResourceAsStream("/identity.jks"),
                                            "JKS",
                                            "changeme",
                                            "changeme")
          ),
          TrustCredentialsConfig.trustManagerFactory(
            TlsUtil.createTrustManagerFactory(getClass.getResourceAsStream("/trust.jks"), "changeme")
          ),
          CipherSuites.Unspecified,
          Protocols.Unspecified,
          ApplicationProtocols.Unspecified
        )
      )
      .newService(FinagleUtil.socketsToName(server.boundAddress), "netty4ClientEngineFactoryClient")

  val externalConfig =
    SslClientConfiguration(
      Option.empty,
      KeyCredentialsConfig.keyManagerFactory(
        TlsUtil.createKeyManagerFactory(getClass.getResourceAsStream("/identity.jks"),
          "JKS",
          "changeme",
          "changeme")
      ),
      TrustCredentialsConfig.trustManagerFactory(
        TlsUtil.createTrustManagerFactory(getClass.getResourceAsStream("/trust.jks"), "changeme")
      ),
      CipherSuites.Unspecified,
      Protocols.Unspecified,
      ApplicationProtocols.Unspecified
    )

  val netty4ExternalClientEngineFactoryClient =
    Http.client
      .withTransport.tls(externalConfig, new ExternalClientEngineFactory(Netty4ClientSslConfigurations.createClientContext(externalConfig, false)))
      .newService(FinagleUtil.socketsToName(server.boundAddress), "netty4ClientEngineFactoryClient")

  @Benchmark
  def sslContextClientEngineFactoryClient(blackhole: Blackhole): Unit = {
    blackhole.consume(Await.result(sslContextClient(Request()), Duration.fromSeconds(1)))
  }

  @Benchmark
  def netty4ClientEngineFactoryClient(blackhole: Blackhole): Unit = {
    blackhole.consume(Await.result(netty4ClientEngineFactoryClient(Request()), Duration.fromSeconds(1)))
  }

  @Benchmark
  def externalSslContextClientEngineFactoryClient(blackhole: Blackhole): Unit = {
    blackhole.consume(Await.result(netty4ExternalClientEngineFactoryClient(Request()), Duration.fromSeconds(1)))
  }

}
