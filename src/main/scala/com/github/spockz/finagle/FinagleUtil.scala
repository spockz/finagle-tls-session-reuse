package com.github.spockz.finagle

import java.net.{InetSocketAddress, SocketAddress}

object FinagleUtil {
  def socketsToName(boundAddress: SocketAddress): String = boundAddress match {
    case isa: InetSocketAddress => s"${isa.getHostString}:${isa.getPort}"
  }

}
