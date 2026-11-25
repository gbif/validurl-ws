package org.gbif.ws.servlet;

import com.sun.net.httpserver.HttpServer;
import org.apache.http.client.methods.HttpGet;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class UrlValidationServletTest {

  // IP literals only: InetAddress.getByName doesn't do a DNS lookup for them
  private static boolean isPublic(String ip) throws UnknownHostException {
    return UrlValidationServlet.isPublic(InetAddress.getByName(ip));
  }

  @Test
  public void testPublicAddresses() throws UnknownHostException {
    assertTrue(isPublic("8.8.8.8"));
    assertTrue(isPublic("130.226.238.170"));
    assertTrue(isPublic("100.128.0.1"));    // just outside carrier-grade NAT
    assertTrue(isPublic("172.32.0.1"));     // just outside 172.16.0.0/12
    assertTrue(isPublic("2001:4860:4860::8888"));
  }

  @Test
  public void testNonPublicAddresses() throws UnknownHostException {
    assertFalse(isPublic("127.0.0.1"));
    assertFalse(isPublic("127.10.0.1"));
    assertFalse(isPublic("0.0.0.0"));
    assertFalse(isPublic("10.1.2.3"));
    assertFalse(isPublic("172.16.0.1"));
    assertFalse(isPublic("172.31.255.255"));
    assertFalse(isPublic("192.168.1.1"));
    assertFalse(isPublic("169.254.169.254"));
    assertFalse(isPublic("100.64.0.1"));
    assertFalse(isPublic("192.0.0.1"));
    assertFalse(isPublic("198.18.0.1"));
    assertFalse(isPublic("224.0.0.1"));
    assertFalse(isPublic("255.255.255.255"));
    assertFalse(isPublic("::1"));
    assertFalse(isPublic("::"));
    assertFalse(isPublic("fe80::1"));
    assertFalse(isPublic("fd00::1"));
    assertFalse(isPublic("::ffff:127.0.0.1")); // IPv4-mapped
    assertFalse(isPublic("::ffff:10.0.0.1"));
  }

  @Test
  public void testResolverRefusesNonPublicHosts() {
    assertThrows(UrlValidationServlet.NonPublicAddressException.class,
        () -> UrlValidationServlet.PUBLIC_ONLY_DNS_RESOLVER.resolve("localhost"));
    assertThrows(UrlValidationServlet.NonPublicAddressException.class,
        () -> UrlValidationServlet.PUBLIC_ONLY_DNS_RESOLVER.resolve("127.0.0.1"));
    assertThrows(UrlValidationServlet.NonPublicAddressException.class,
        () -> UrlValidationServlet.PUBLIC_ONLY_DNS_RESOLVER.resolve("::1"));
  }

  @Test
  public void testClientRefusesLocalServer() throws Exception {
    // a server on this machine answers, but the validator's client must not reach it
    HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext("/", exchange -> {
      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    });
    server.start();
    try {
      int port = server.getAddress().getPort();
      for (String url : new String[] {"http://localhost:" + port + "/", "http://127.0.0.1:" + port + "/"}) {
        HttpGet get = new HttpGet(url);
        try {
          assertThrows(UrlValidationServlet.NonPublicAddressException.class, () -> UrlValidationServlet.CLIENT.execute(get));
        } finally {
          get.abort();
        }
      }
    } finally {
      server.stop(0);
    }
  }
}
