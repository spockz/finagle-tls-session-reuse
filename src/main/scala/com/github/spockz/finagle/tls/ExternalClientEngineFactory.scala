package com.github.spockz.finagle.tls

import com.github.spockz.finagle.bench.tls.finagle.Netty4ClientSslConfigurations
import com.twitter.finagle.Address
import com.twitter.finagle.ssl.Engine
import com.twitter.finagle.ssl.client.{SslClientConfiguration, SslClientEngineFactory}
import io.netty.buffer.PooledByteBufAllocator
import io.netty.handler.ssl.SslContext

class ExternalClientEngineFactory(context: SslContext) extends SslClientEngineFactory {

  // use the default allocator
  private val allocator = PooledByteBufAllocator.DEFAULT

  def apply(address: Address, config: SslClientConfiguration): Engine = {
    Netty4ClientSslConfigurations.createClientEngine(address, config, context, allocator)
  }

}