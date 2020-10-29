
name := "finagle-com.github.spockz.finagle.tls-session-reuse"

version := "0.1"

scalaVersion := "2.12.7"

enablePlugins(JmhPlugin)

libraryDependencies += "com.twitter" %% "finagle-http" % "20.9.0"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.2" % Test