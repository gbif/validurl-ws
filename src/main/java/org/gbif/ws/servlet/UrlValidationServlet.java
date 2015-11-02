package org.gbif.ws.servlet;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.util.JSONPObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UrlValidationServlet extends HttpServlet {

  private static final Logger LOG = LoggerFactory.getLogger(UrlValidationServlet.class);
  private static final String URL_PARAM = "url";
  private static final String CALLBACK_PARAM = "callback";
  private static final String CHARSET = "UTF-8";
  private static final DefaultHttpClient CLIENT = provideHttpClient();
  private static final ObjectMapper MAPPER = new ObjectMapper();

  // The timeout in milliseconds until a connection is established.
  // A timeout value of zero is interpreted as an infinite timeout.
  private static final int TIMEOUT = 5000;
  private static final int MAX_TOTAL_CONNECTIONS = 100;
  private static final int MAX_CONNECTIONS_PER_ROUTE = 10;


  /**
   * Gets a parameter but treats it case insensitive.
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
    // lookup parameter names case insensitive
    Map<String, String> paramLookup = new HashMap<String, String>();

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

  private static DefaultHttpClient provideHttpClient() {
    HttpParams params = new BasicHttpParams();
    SchemeRegistry schemeRegistry = new SchemeRegistry();
    schemeRegistry.register(new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));
    schemeRegistry.register(new Scheme("https", 443, SSLSocketFactory.getSocketFactory()));

    HttpConnectionParams.setConnectionTimeout(params, TIMEOUT);
    HttpConnectionParams.setSoTimeout(params, TIMEOUT);

    params.setParameter(CoreProtocolPNames.USER_AGENT, "GBIF-Url-Validator");
    params.setBooleanParameter(ClientPNames.HANDLE_REDIRECTS, true);

    ThreadSafeClientConnManager cm = new ThreadSafeClientConnManager(schemeRegistry);
    cm.setMaxTotal(MAX_TOTAL_CONNECTIONS);
    cm.setDefaultMaxPerRoute(MAX_CONNECTIONS_PER_ROUTE);

    return new DefaultHttpClient(cm, params);
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    // before parsing set content type and other response headers
    resp.setContentType("application/json; charset=" + CHARSET);
    resp.setCharacterEncoding(CHARSET);

    // get url param
    String url = para(req, URL_PARAM);
    String callback = para(req, CALLBACK_PARAM);

    // some response, return status code & headers as json
    Map<String, Object> data = new HashMap<String, Object>();
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

      Map<String, String> header = new HashMap<String, String>();
      for (Header h : response.getAllHeaders()) {
        header.put(h.getName(), h.getValue());
      }
      data.put("header", header);
      data.put("responseTime", (end - start));

      resp.setStatus(HttpServletResponse.SC_OK);

    } catch (IllegalArgumentException e) {
      data.put("error", "InvalidUrlParameter");
    } catch (IllegalStateException e) {
      data.put("error", "InvalidUrlParameter");
    } catch (ConnectTimeoutException e) {
      data.put("error", "ConnectionTimeout");
    } catch (ClientProtocolException e) {
      data.put("error", "ClientProtocolException");
    } catch (IOException e) {
      data.put("error", "IOException");
    } catch (Exception e) {
      data.put("error", e.getMessage());
      LOG.error("Error testing url {}", e);
    } finally {
      if (get != null) {
        get.abort();
      }
    }

    // write response
    Writer writer = new OutputStreamWriter(resp.getOutputStream(), CHARSET);
    try {
      if (callback == null || callback.isEmpty()) {
        MAPPER.writeValue(writer, data);
      } else {
        MAPPER.writeValue(writer, new JSONPObject(callback, data));
      }
    } finally {
      writer.close();
    }

    resp.flushBuffer();
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    doGet(req, resp);
  }
}
