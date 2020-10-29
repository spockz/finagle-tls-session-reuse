package com.github.spockz.finagle.bench.tls.finagle

import com.twitter.finagle.Address
import com.twitter.finagle.ssl.{ApplicationProtocols, Engine, KeyCredentials, SslConfigurationException, TrustCredentials}
import com.twitter.finagle.ssl.client.{SslClientConfiguration, SslClientEngineFactory}
import com.twitter.util.{Return, Throw, Try}
import com.twitter.util.security.{PrivateKeyFile, X509CertificateFile}
import io.netty.buffer.ByteBufAllocator
import io.netty.handler.ssl.{ApplicationProtocolConfig, SslContext, SslContextBuilder, SslProvider}
import io.netty.handler.ssl.ApplicationProtocolConfig.{Protocol, SelectedListenerFailureBehavior, SelectorFailureBehavior}
import io.netty.handler.ssl.util.InsecureTrustManagerFactory

import scala.jdk.CollectionConverters.seqAsJavaListConverter
import scala.util.control.NonFatal

/**
 * Convenience functions for setting values on a Netty `SslContextBuilder`
 * which are applicable to only client configurations and engines.
 */
object Netty4ClientSslConfigurations {

  /**
   * Configures the application protocols of the `SslContextBuilder`. This
   * method mutates the `SslContextBuilder`, and returns it as the result.
   *
   * @note This sets which application level protocol negotiation to
   * use ALPN.
   *
   * @note This also sets the `SelectorFailureBehavior` to NO_ADVERTISE,
   * and the `SelectedListenerFailureBehavior` to ACCEPT as those are the
   * only modes supported by both JDK and Native engines.
   */
  private def configureClientApplicationProtocols(
                                                   builder: SslContextBuilder,
                                                   applicationProtocols: ApplicationProtocols
                                                 ): SslContextBuilder = {
    // don't use NPN because https://github.com/netty/netty/issues/7346 breaks
    // web crawlers
    Netty4SslConfigurations.configureApplicationProtocols(
      builder,
      applicationProtocols,
      Protocol.ALPN
    )
  }

  /**
   * Creates an `SslContextBuilder` for a client with the supplied `KeyCredentials`.
   *
   * @note An `SslConfigurationException` will be thrown if there is an issue loading
   * the certificate(s) or private key.
   *
   * @note Will not validate the validity for certificates when configured
   *       with [[KeyCredentials.KeyManagerFactory]] in contrast to when
   *       configured with [[KeyCredentials.CertAndKey]], [[KeyCredentials.CertsAndKey]],
   *       or [[KeyCredentials.CertKeyAndChain]].
   */
  private def startClientWithKey(keyCredentials: KeyCredentials): SslContextBuilder = {
    val builder: SslContextBuilder = SslContextBuilder.forClient()
    val withKey = keyCredentials match {
      case KeyCredentials.Unspecified =>
        Return(builder) // Do Nothing
      case KeyCredentials.CertAndKey(certFile, keyFile) =>
        for {
          key <- new PrivateKeyFile(keyFile).readPrivateKey()
          cert <- new X509CertificateFile(certFile).readX509Certificate()
        } yield builder.keyManager(key, cert)
      case KeyCredentials.CertsAndKey(certsFile, keyFile) =>
        for {
          key <- new PrivateKeyFile(keyFile).readPrivateKey()
          certs <- new X509CertificateFile(certsFile).readX509Certificates()
        } yield builder.keyManager(key, certs: _*)
      case KeyCredentials.CertKeyAndChain(certFile, keyFile, chainFile) =>
        for {
          key <- new PrivateKeyFile(keyFile).readPrivateKey()
          cert <- new X509CertificateFile(certFile).readX509Certificate()
          chain <- new X509CertificateFile(chainFile).readX509Certificates()
        } yield builder.keyManager(key, cert +: chain: _*)
      case KeyCredentials.KeyManagerFactory(keyManagerFactory) =>
        Return(builder.keyManager(keyManagerFactory))
    }
    Netty4SslConfigurations.unwrapTryContextBuilder(withKey)
  }

  /**
   * Creates an `SslContext` based on the supplied `SslClientConfiguration`. This method uses
   * the `KeyCredentials`, `TrustCredentials`, and `ApplicationProtocols` from the provided
   * configuration, and forces the JDK provider if forceJdk is true.
   */
  def createClientContext(config: SslClientConfiguration, forceJdk: Boolean): SslContext = {
    val builder = startClientWithKey(config.keyCredentials)
    val withProvider = Netty4SslConfigurations.configureProvider(builder, forceJdk)
    val withTrust = Netty4SslConfigurations.configureTrust(withProvider, config.trustCredentials)
    val withAppProtocols =
      configureClientApplicationProtocols(withTrust, config.applicationProtocols)

    // We only want to use the `FinalizedSslContext` if we're using the non-JDK implementation.
//    if (!forceJdk) new FinalizedSslContext(withAppProtocols.build())
//    else
    withAppProtocols.build()
  }

  /**
   * Creates an `Engine` based on the supplied `Address`, `SslContext`, and `ByteBufAllocator`, and
   * then configures the underlying `SSLEngine` based on the supplied `SslClientConfiguration`.
   */
  def createClientEngine(
                          address: Address,
                          config: SslClientConfiguration,
                          context: SslContext,
                          allocator: ByteBufAllocator
                        ): Engine = {
    val sslEngine = address match {
      case Address.Inet(isa, _) =>
        context.newEngine(allocator, SslClientEngineFactory.getHostString(isa, config), isa.getPort)
      case _ =>
        context.newEngine(allocator)
    }
    val engine = Engine(sslEngine)
    SslClientEngineFactory.configureEngine(engine, config)
    engine
  }
}

/**
 * Convenience functions for setting values on a Netty `SslContextBuilder`
 * which are applicable to both client and server engines.
 */
private[finagle] object Netty4SslConfigurations {

  /**
   * Configures the trust credentials of the `SslContextBuilder`. This
   * method mutates the `SslContextBuilder`, and returns it as the result.
   *
   * @note TrustCredentials.Unspecified does not change the builder,
   */
  def configureTrust(
                      builder: SslContextBuilder,
                      trustCredentials: TrustCredentials
                    ): SslContextBuilder = {
    trustCredentials match {
      case TrustCredentials.Unspecified =>
        builder // Do Nothing
      case TrustCredentials.Insecure =>
        builder.trustManager(InsecureTrustManagerFactory.INSTANCE)
      case TrustCredentials.CertCollection(file) =>
        builder.trustManager(file)
      case TrustCredentials.TrustManagerFactory(trustManagerFactory) =>
        builder.trustManager(trustManagerFactory)
    }
  }

  /**
   * Configures the application protocols of the `SslContextBuilder`. This
   * method mutates the `SslContextBuilder`, and returns it as the result.
   *
   * @note This also sets the `SelectorFailureBehavior` to NO_ADVERTISE,
   * and the `SelectedListenerFailureBehavior` to ACCEPT as those are the
   * only modes supported by both JDK and Native engines.
   */
  def configureApplicationProtocols(
                                     builder: SslContextBuilder,
                                     applicationProtocols: ApplicationProtocols,
                                     negotiationProtocol: Protocol
                                   ): SslContextBuilder = {
    applicationProtocols match {
      case ApplicationProtocols.Unspecified =>
        builder // Do Nothing
      case ApplicationProtocols.Supported(protos) =>
        builder.applicationProtocolConfig(
          new ApplicationProtocolConfig(
            negotiationProtocol,
            SelectorFailureBehavior.NO_ADVERTISE,
            SelectedListenerFailureBehavior.ACCEPT,
            protos.asJava
          )
        )
    }
  }

  /**
   * Configures the SSL provider with the JDK SSL provider if `forceJDK` is true.
   *
   * @note This is necessary in environments where the native engine could fail to load.
   */
  def configureProvider(builder: SslContextBuilder, forceJdk: Boolean): SslContextBuilder =
    if (forceJdk) builder.sslProvider(SslProvider.JDK)
    else builder.sslProvider(SslProvider.OPENSSL_REFCNT)

  /**
   * Unwraps the `Try[SslContextBuilder]` and throws an `SslConfigurationException` for
   * `NonFatal` errors.
   */
  def unwrapTryContextBuilder(builder: Try[SslContextBuilder]): SslContextBuilder =
    builder match {
      case Return(sslContextBuilder) =>
        sslContextBuilder
      case Throw(NonFatal(nonFatal)) =>
        throw new SslConfigurationException(nonFatal)
      case Throw(throwable) =>
        throw throwable
    }

}
