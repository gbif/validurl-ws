package org.gbif.ws.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class UrlValidationServlet extends HttpServlet {

  private static final Logger LOG = LogManager.getLogger();
  private static final String URL_PARAM = "url";
  private static final String CALLBACK_PARAM = "callback";
  private static final String CHARSET = "UTF-8";

  /**
   * Resolves host names like the system resolver, but only to public internet addresses: the service checks whether a
   * URL is reachable from the internet, so other addresses are out of scope.
   * <p>
   * Must stay above CLIENT: static fields are set top to bottom, and a client built while this is still null silently
   * uses the system resolver (UrlValidationServletTest.testClientRefusesLocalServer).
   */
  static final DnsResolver PUBLIC_ONLY_DNS_RESOLVER = host -> {
    InetAddress[] addresses = SystemDefaultDnsResolver.INSTANCE.resolve(host);
    for (InetAddress address : addresses) {
      if (!isPublic(address)) {
        throw new NonPublicAddressException(host);
      }
    }
    return addresses;
  };
  static final HttpClient CLIENT = provideHttpClient();
  private static final ObjectMapper MAPPER = new ObjectMapper();

  // The timeout in milliseconds until a connection is established.
  // A timeout value of zero is interpreted as an infinite timeout.
  private static final int TIMEOUT = 5000;
  private static final int MAX_TOTAL_CONNECTIONS = 100;
  private static final int MAX_CONNECTIONS_PER_ROUTE = 10;


  /**
   * Gets a parameter but treats it case-insensitive.
   * <p>
   * So if we're looking for a <code>parameter</code> called <code>url</code> we'd also return a user-provided
   * parameter
   * with the name <code>URL</code>.
   *
   * @param req       the request in which to look for the user-provided parameter
   * @param parameter the case-insensitive parameter to look for
   *
   * @return either the parameter value if it could be found, null otherwise
   */
  public static String para(ServletRequest req, String parameter) {
    // lookup parameter names case-insensitive
    Map<String, String> paramLookup = new HashMap<>();

    Enumeration paramNames = req.getParameterNames();
    while (paramNames.hasMoreElements()) {
      String param = (String) paramNames.nextElement();
      paramLookup.put(param.toLowerCase(), param);
    }
    String normedParam = paramLookup.get(parameter.toLowerCase());
    String p = null;
    if (normedParam != null) {
      p = req.getParameter(normedParam);
      if (p != null) {
        p = p.trim();
      }
    }
    return p;
  }

  /**
   * Thrown when a host name resolves to an address that isn't on the public internet.
   */
  static class NonPublicAddressException extends UnknownHostException {
    NonPublicAddressException(String host) {
      super(host + " is not a public address");
    }
  }

  /**
   * @return true for addresses on the public internet; false for loopback, private, link-local, carrier-grade NAT,
   * unique local IPv6, multicast and other reserved ranges
   */
  static boolean isPublic(InetAddress address) {
    if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
        || address.isSiteLocalAddress() || address.isMulticastAddress()) {
      return false;
    }
    byte[] b = address.getAddress();
    if (address instanceof Inet4Address) {
      // bytes are signed in Java: & 0xff gives the usual 0-255 value
      int b0 = b[0] & 0xff;
      int b1 = b[1] & 0xff;
      int b2 = b[2] & 0xff;
      return b0 != 0                                    // 0.0.0.0/8 "this network"
          && !(b0 == 100 && b1 >= 64 && b1 <= 127)      // 100.64.0.0/10 carrier-grade NAT
          && !(b0 == 192 && b1 == 0 && b2 == 0)         // 192.0.0.0/24 IETF protocol assignments
          && !(b0 == 198 && (b1 == 18 || b1 == 19))     // 198.18.0.0/15 benchmarking
          && b0 < 240;                                  // 240.0.0.0/4 reserved, broadcast
    }
    // IPv6 (IPv4-mapped addresses come back as Inet4Address): fc00::/7 unique local, fec0::/10 is site-local above
    int first = b[0] & 0xff;
    return first != 0xfc && first != 0xfd;
  }

  private static HttpClient provideHttpClient() {
    SSLContext sslContext;
    try {
      sslContext = SSLContext.getDefault();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Failed to create SSL context", e);
    }
    SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);

    // the socket factories go to the connection manager: the client's own SSL socket factory is ignored once a
    // connection manager is set
    Registry<ConnectionSocketFactory> socketFactories = RegistryBuilder.<ConnectionSocketFactory>create()
        .register("http", PlainConnectionSocketFactory.getSocketFactory())
        .register("https", sslsf)
        .build();
    PoolingHttpClientConnectionManager cm =
        new PoolingHttpClientConnectionManager(socketFactories, PUBLIC_ONLY_DNS_RESOLVER);
    cm.setMaxTotal(MAX_TOTAL_CONNECTIONS);
    cm.setDefaultMaxPerRoute(MAX_CONNECTIONS_PER_ROUTE);

    RequestConfig requestConfig = RequestConfig.custom()
        .setConnectTimeout(TIMEOUT)
        .setSocketTimeout(TIMEOUT)
        .build();

    return HttpClients.custom()
        .setConnectionManager(cm)
        .setDefaultRequestConfig(requestConfig)
        .setUserAgent("GBIF-Url-Validator")
        .build();
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    // before parsing set content type and other response headers
    resp.setContentType("application/json; charset=" + CHARSET);
    resp.setCharacterEncoding(CHARSET);

    // get url param
    String url = para(req, URL_PARAM);
    String callback = para(req, CALLBACK_PARAM);

    // some response, return status code & headers as json
    Map<String, Object> data = new HashMap<>();
    data.put("success", false);
    data.put("url", url);

    if (url == null || url.trim().isEmpty()) {
      resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Missing url parameter");
      resp.flushBuffer();
      return;
    }

    // validate url
    HttpGet get = null;
    try {
      LOG.info("Testing URL: {}", url);
      get = new HttpGet(url);
      long start = System.currentTimeMillis();
      HttpResponse response = CLIENT.execute(get);
      long end = System.currentTimeMillis();

      int code = response.getStatusLine().getStatusCode();
      data.put("status", code);
      data.put("success", code >= 200 && code < 300);

      Map<String, String> header = new HashMap<>();
      for (Header h : response.getAllHeaders()) {
        header.put(h.getName(), h.getValue());
      }
      data.put("header", header);
      data.put("responseTime", (end - start));

      resp.setStatus(HttpServletResponse.SC_OK);

    } catch (IllegalArgumentException | IllegalStateException e) {
      data.put("error", "InvalidUrlParameter");
    } catch (NonPublicAddressException e) {
      LOG.info("Refused non-public URL: {}", url);
      data.put("error", "NonPublicAddress");
    } catch (ConnectTimeoutException e) {
      data.put("error", "ConnectionTimeout");
    } catch (ClientProtocolException e) {
      data.put("error", "ClientProtocolException");
    } catch (IOException e) {
      data.put("error", "IOException");
    } catch (Exception e) {
      data.put("error", e.getMessage());
      LOG.error("Error testing url", e);
    } finally {
      if (get != null) {
        get.abort();
      }
    }

    // write response
    try (Writer writer = new OutputStreamWriter(resp.getOutputStream(), CHARSET)) {
      if (callback == null || callback.isEmpty()) {
        MAPPER.writeValue(writer, data);
      } else {
        MAPPER.writeValue(writer, new JSONPObject(callback, data));
      }
    }

    resp.flushBuffer();
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    doGet(req, resp);
  }
}
