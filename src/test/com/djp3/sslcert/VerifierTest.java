package com.djp3.sslcert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.InvalidParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.djp3.sslcert.Verifier.Configuration;
import com.djp3.sslcert.crl.CRLVerifier;
import com.djp3.sslcert.crl.X509CRLWrapper;
import com.djp3.sslcert.ct.CTVerifier;
import com.djp3.sslcert.ocsp.OCSPVerifier;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;

public class VerifierTest {

  private static URI goodURI = null;
  private static URI goodURI2 = null;
  private static URI badURIRevoked_OCSP_ONLY = null;
  private static URI badURISCTFailed = null;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    //System.setProperty("log4j.configurationFile","src/test/resources/JustFatals.log4j.xml");
    System.setProperty("log4j.configurationFile", "src/test/resources/Everything.log4j.xml");

    Security.addProvider(new BouncyCastleJsseProvider());
    Security.addProvider(new BouncyCastleProvider());

    try {
      goodURI =
          new URIBuilder()
              .setScheme("https")
              .setHost("raw.github.com")
              .setPath("/djp3/p2p4java/production/bootstrapMasterList.json")
              .build();
      goodURI2 = new URIBuilder().setScheme("https").setHost("www.cnn.com").setPath("/").build();
      badURIRevoked_OCSP_ONLY = new URIBuilder().setScheme("https").setHost("revoked.badssl.com").setPath("/").build();
      badURISCTFailed =
          new URIBuilder()
              .setScheme("https")
              .setHost("invalid-expected-sct.badssl.com")
              .setPath("/")
              .build();
    } catch (URISyntaxException e) {
      fail("This should have worked");
    }
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Before
  public void setUp() throws Exception {
    Security.addProvider(new BouncyCastleJsseProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @After
  public void tearDown() throws Exception {}

  public ResponseHandler<String> makeResponseHandler() {
    return new ResponseHandler<String>() {
      @Override
      public String handleResponse(final HttpResponse response)
          throws ClientProtocolException, IOException {
        StatusLine statusLine = response.getStatusLine();
        HttpEntity entity = response.getEntity();

        if (statusLine.getStatusCode() >= 300) {
          throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
        }

        ContentType contentType = ContentType.getOrDefault(entity);
        Charset charset = contentType.getCharset();
        if (entity != null) {
          return EntityUtils.toString(entity, charset);
        } else {
          return null;
        }
      }
    };
  }

  public CloseableHttpClient makeHTTPClient(SSLConnectionSocketFactory sslsf) {
    return HttpClients.custom()
        .setSSLSocketFactory(sslsf)
        .setDefaultRequestConfig(makeRequestConfig())
        .setRetryHandler(new DefaultHttpRequestRetryHandler(0, false))
        .build();
  }

  public RequestConfig makeRequestConfig() {
    return RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
  }

  @Test
  /** Degenerate conditions */
  public void test00() {
    /** ***** CT ***** */
    CTVerifier ctVerifier = null;
    try {
      ctVerifier = new CTVerifier(null);
      fail("Should have thrown an exception without a configuration");
    } catch (InvalidParameterException e) {
      //Okay this is expected
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    Configuration configurationCT = new CTVerifier.Configuration();
    configurationCT.useCache = false;
    try {
      ctVerifier = new CTVerifier(configurationCT);
      assertNull(ctVerifier.getCache());
      assertNull(ctVerifier.getCacheStats());
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    configurationCT = new CTVerifier.Configuration();
    configurationCT.useCache = true;
    try {
      ctVerifier = new CTVerifier(configurationCT);
      assertNotNull(ctVerifier.getCache());
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    try {
      ctVerifier.getCache().put(BigInteger.ONE, null); //null should not be allowed
      fail("Should not allow null entries.  Code assumes this won't happen");
    } catch (NullPointerException e) {
      //okay
    }
    ctVerifier
        .getCache()
        .put(
            BigInteger.TEN,
            new VerificationStatus(VerificationStatus.BAD, null)); //null date should get cleaned up
    assertEquals(1, ctVerifier.getCache().size());
    ctVerifier.triggerGarbageCollection();
    assertEquals(0, ctVerifier.getCache().size());

    /** ***** OCSP ***** */
    OCSPVerifier ocspVerifier = null;
    try {
      ocspVerifier = new OCSPVerifier(null);
      fail("Should have thrown an exception without a configuration");
    } catch (InvalidParameterException e) {
      //Okay this is expected
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    Configuration configurationOCSP = new OCSPVerifier.Configuration();
    configurationOCSP.useCache = false;
    try {
      ocspVerifier = new OCSPVerifier(configurationOCSP);
      assertNull(ocspVerifier.getCache());
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    configurationOCSP = new OCSPVerifier.Configuration();
    configurationOCSP.useCache = true;
    try {
      ocspVerifier = new OCSPVerifier(configurationOCSP);
      assertNotNull(ocspVerifier.getCache());
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    try {
      ocspVerifier.getCache().put(BigInteger.ONE, null); //null should not be allowed
      fail("Should not allow null entries.  Code assumes this won't happen");
    } catch (NullPointerException e) {
      //okay
    }
    ocspVerifier
        .getCache()
        .put(
            BigInteger.TEN,
            new VerificationStatus(VerificationStatus.BAD, null)); //null date should get cleaned up
    assertEquals(1, ocspVerifier.getCache().size());
    ocspVerifier.triggerGarbageCollection();
    assertEquals(0, ocspVerifier.getCache().size());

    /** ***** CRL ***** */
    CRLVerifier crlVerifier = null;
    try {
      crlVerifier = new CRLVerifier(null);
      fail("Should have thrown an exception without a configuration");
    } catch (InvalidParameterException e) {
      //Okay this is expected
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    Configuration configurationCRL = new CRLVerifier.Configuration();
    configurationCRL.useCache = false;
    try {
      crlVerifier = new CRLVerifier(configurationCRL);
      assertNull(crlVerifier.getCache());
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    configurationCRL = new CRLVerifier.Configuration();
    configurationCRL.useCache = true;
    try {
      crlVerifier = new CRLVerifier(configurationCRL);
      assertNotNull(crlVerifier.getCache());
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    try {
      crlVerifier.getCache().put("hello", null); //null should not be allowed
      fail("Should not allow null entries.  Code assumes this won't happen");
    } catch (NullPointerException e) {
      //okay
    }

    crlVerifier.getCache().put("world", new X509CRLWrapper(null)); //null date should get cleaned up
    assertEquals(1, crlVerifier.getCache().size());
    crlVerifier.triggerGarbageCollection();
    assertEquals(0, crlVerifier.getCache().size());
  }

  @Test
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: no
   * 	load it: N/A
   * 	store it: N/A
   * CT cache: yes
   * 	load it: no
   * 	store it: no
   *
   * <p>URL: good URL
   */
  public void test01() {
    Configuration configurationCT = new CTVerifier.Configuration();
    configurationCT.useCache = false;
    CTVerifier ctVerifier = null;
    try {
      ctVerifier = new CTVerifier(configurationCT);
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, null, ctVerifier)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf = new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Build the request
    HttpUriRequest httpUriRequest = new HttpGet(goodURI);

    //Execute the request
    String data;
    try {
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    ctVerifier.triggerGarbageCollection();

    try {
      ctVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: no
   * 	load it: N/A
   * 	store it: N/A
   * CT cache: yes
   * 	load it: no
   * 	store it: no
   *
   * <p>URL: bad URL
   */
  public void test02() {
    Configuration configurationCT = new CTVerifier.Configuration();
    configurationCT.useCache = false;
    CTVerifier ctVerifier = null;
    try {
      ctVerifier = new CTVerifier(configurationCT);
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, null, ctVerifier)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf = new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Build the request
    HttpGet httpUriRequest = new HttpGet(badURISCTFailed);

    //Execute the request
    try {
      httpClient.execute(httpUriRequest, responseHandler);
      fail("Should not have worked");
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }

    ctVerifier.triggerGarbageCollection();

    try {
      ctVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: no
   * 	load it: N/A
   * 	store it: N/A
   * CT cache: yes
   * 	load it: no
   * 	store it: yes
   *
   * <p>URL: good and bad URL
   */
  public void test03() {
    Configuration configurationCT = new CTVerifier.Configuration();
    configurationCT.useCache = true;
    configurationCT.loadCacheFromColdStorageOnStart = false;
    configurationCT.loadCacheColdStorageFileName = "src/test/resources/CT.cache";
    configurationCT.storeCacheToColdStorageOnQuit = true;
    configurationCT.storeCacheColdStorageFileName = "src/test/resources/CT.cache";

    CTVerifier ctVerifier = null;
    try {
      ctVerifier = new CTVerifier(configurationCT);
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, null, ctVerifier)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Empty cache to start
    assertEquals(0, ctVerifier.getCacheStats().requestCount());
    assertEquals(0, ctVerifier.getCacheStats().hitCount());
    assertEquals(0, ctVerifier.getCacheStats().missCount());
    assertEquals(0, ctVerifier.getCacheStats().loadCount());

    HttpUriRequest httpUriRequest;
    String data;
    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI);
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    //Load the cache with 1 or more cert lookups
    long requestCount1 = ctVerifier.getCacheStats().requestCount();
    long hitCount1 = ctVerifier.getCacheStats().hitCount();
    long missCount1 = ctVerifier.getCacheStats().missCount();
    long loadCount1 = ctVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1 > 0);
    assertTrue(hitCount1 <= missCount1); //Possibly loaded the same CRL twice in one URL
    assertTrue(missCount1 > 0);
    assertTrue(loadCount1 > 0);

    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI2);
      data = httpClient.execute(httpUriRequest, responseHandler);
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      fail("Should have worked:" + e);
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }

    //Load the cache with additional cert lookups that should be different
    long requestCount2 = ctVerifier.getCacheStats().requestCount();
    long hitCount2 = ctVerifier.getCacheStats().hitCount();
    long missCount2 = ctVerifier.getCacheStats().missCount();
    long loadCount2 = ctVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2 > 0);
    assertTrue(hitCount2 <= missCount2);
    assertTrue(missCount2 > 0);
    assertTrue(loadCount2 > 0);

    assertTrue(requestCount2 > requestCount1);
    assertTrue(loadCount2 > loadCount1);

    ctVerifier.triggerGarbageCollection();

    try {
      ctVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
 
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: no
   * 	load it: N/A
   * 	store it: N/A
   * CT cache: yes
   * 	load it: yes
   * 	store it: yes
   *
   * <p>URL: good and bad URL
   */
  public void test04() {
    test03(); //Make sure there is a cache to load

    Configuration configurationCT = new CTVerifier.Configuration();
    configurationCT.useCache = true;
    configurationCT.loadCacheFromColdStorageOnStart = true;
    configurationCT.loadCacheColdStorageFileName = "src/test/resources/CT.cache";
    configurationCT.storeCacheToColdStorageOnQuit = true;
    configurationCT.storeCacheColdStorageFileName = "src/test/resources/CT.cache";

    CTVerifier ctVerifier = null;
    try {
      ctVerifier = new CTVerifier(configurationCT);
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, null, ctVerifier)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Load with the results of the previous cache save but stats should be reset
    long requestCount1 = ctVerifier.getCacheStats().requestCount();
    long hitCount1 = ctVerifier.getCacheStats().hitCount();
    long missCount1 = ctVerifier.getCacheStats().missCount();
    long loadCount1 = ctVerifier.getCacheStats().loadCount();
    assertEquals(0, requestCount1);
    assertEquals(0, hitCount1);
    assertEquals(0, missCount1);
    assertEquals(0, loadCount1);

    HttpUriRequest httpUriRequest;
    String data;
    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI);
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    requestCount1 = ctVerifier.getCacheStats().requestCount();
    hitCount1 = ctVerifier.getCacheStats().hitCount();
    missCount1 = ctVerifier.getCacheStats().missCount();
    loadCount1 = ctVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1 > 0);
    assertTrue(hitCount1 > 0); //Because we loaded the cache from disk
    assertEquals(0, missCount1); //Because we loaded the cache from disk
    assertEquals(0, loadCount1); //Because we loaded the cache from disk

    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI2);
      data = httpClient.execute(httpUriRequest, responseHandler);
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      fail("Should have worked:" + e);
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }

    long requestCount2 = ctVerifier.getCacheStats().requestCount();
    long hitCount2 = ctVerifier.getCacheStats().hitCount();
    long missCount2 = ctVerifier.getCacheStats().missCount();
    long loadCount2 = ctVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2 > 0);
    assertTrue(hitCount2 > 0); //Because we loaded the cache from disk
    assertEquals(0, missCount2); //Because we loaded the cache from disk
    assertEquals(0, loadCount2); //Because we loaded the cache from disk

    assertTrue(requestCount2 > requestCount1);
    assertTrue(loadCount2 >= loadCount1);

    ctVerifier.triggerGarbageCollection();

    try {
      ctVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
 
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: yes
   * 	load it: no
   * 	store it: no
   * CT cache: no
   * 	load it: N/A
   * 	store it: N/A
   *
   * <p>URL: good URL
   */
  public void test05() {
    Configuration configurationCRL = new CRLVerifier.Configuration();
    configurationCRL.useCache = false;
    CRLVerifier crlVerifier = null;
    try {
      crlVerifier = new CRLVerifier(configurationCRL);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, crlVerifier, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf = new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());
    

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();
    
    //Build the request
    HttpGet httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);

    //Execute the request
    try {
      httpClient.execute(httpUriRequest, responseHandler);
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
      fail("Should have worked because it's not revoked by CRL");
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    } catch (IOException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    }

    crlVerifier.triggerGarbageCollection();

    try {
      crlVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
 
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: yes
   * 	load it: no
   * 	store it: no
   * CT cache: no
   * 	load it: N/A
   * 	store it: N/A
   *
   * <p>URL: bad URL
   */
  public void test06() {
    Configuration configurationCRL = new CRLVerifier.Configuration();
    configurationCRL.useCache = false;
    CRLVerifier crlVerifier = null;
    try {
      crlVerifier = new CRLVerifier(configurationCRL);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, crlVerifier, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Build the request
    HttpGet httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);

    //Execute the request
    try {
      httpClient.execute(httpUriRequest, responseHandler);
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
      fail("Should have worked because it's not revoked by CRL");
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    } catch (IOException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    }

    crlVerifier.triggerGarbageCollection();

    try {
      crlVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: yes
   * 	load it: no
   * 	store it: yes
   * CT cache: no
   * 	load it: N/A
   * 	store it: N/A
   *
   * <p>URL: good and bad URL
   */
  public void test07() {
    Configuration configurationCRL = new CRLVerifier.Configuration();

    configurationCRL.useCache = true;
    configurationCRL.loadCacheFromColdStorageOnStart = false;
    configurationCRL.loadCacheColdStorageFileName = "src/test/resources/CRL.cache";
    configurationCRL.storeCacheToColdStorageOnQuit = true;
    configurationCRL.storeCacheColdStorageFileName = "src/test/resources/CRL.cache";
    CRLVerifier crlVerifier = null;
    try {
      crlVerifier = new CRLVerifier(configurationCRL);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, crlVerifier, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Empty cache to start
    assertEquals(0, crlVerifier.getCacheStats().requestCount());
    assertEquals(0, crlVerifier.getCacheStats().hitCount());
    assertEquals(0, crlVerifier.getCacheStats().missCount());
    assertEquals(0, crlVerifier.getCacheStats().loadCount());

    HttpUriRequest httpUriRequest;
    String data;
    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI);
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    //Load the cache with 1 or more cert lookups
    long requestCount1 = crlVerifier.getCacheStats().requestCount();
    long hitCount1 = crlVerifier.getCacheStats().hitCount();
    long missCount1 = crlVerifier.getCacheStats().missCount();
    long loadCount1 = crlVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1 > 0);
    assertTrue(hitCount1 <= missCount1); //Possibly loaded the same CRL twice in one URL
    assertTrue(missCount1 > 0);
    assertTrue(loadCount1 > 0);

    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);
      data = httpClient.execute(httpUriRequest, responseHandler);
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
      fail("Should have worked because it's not revoked by CRL");
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    } catch (IOException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    }

    //Load the cache with additional cert lookups that should be different
    long requestCount2 = crlVerifier.getCacheStats().requestCount();
    long hitCount2 = crlVerifier.getCacheStats().hitCount();
    long missCount2 = crlVerifier.getCacheStats().missCount();
    long loadCount2 = crlVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2 > 0);
    assertTrue(hitCount2 <= missCount2);
    assertTrue(missCount2 > 0);
    assertTrue(loadCount2 > 0);

    assertTrue(requestCount2 >= requestCount1);
    assertTrue(loadCount2 >= loadCount1);

    crlVerifier.triggerGarbageCollection();

    try {
      crlVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: no load it: N/A store it: N/A CRL cache: yes load it: yes store it: yes CT cache:
   * no load it: N/A store it: N/A
   *
   * <p>URL: good and bad URL
   */
  /**
   * OCSP cache: no 
   * 	load it: N/A
   * 	store it: N/A
   * CRL cache: yes
   * 	load it: yes
   * 	store it: yes
   * CT cache: no
   * 	load it: N/A
   * 	store it: N/A
   *
   * <p>URL: good and bad URL
   */
  public void test08() {

    test07(); //Make sure there is a cache to load

    Configuration configurationCRL = new CRLVerifier.Configuration();
    configurationCRL.useCache = true;
    configurationCRL.loadCacheFromColdStorageOnStart = true;
    configurationCRL.loadCacheColdStorageFileName = "src/test/resources/CRL.cache";
    configurationCRL.storeCacheToColdStorageOnQuit = true;
    configurationCRL.storeCacheColdStorageFileName = "src/test/resources/CRL.cache";
    CRLVerifier crlVerifier = null;
    try {
      crlVerifier = new CRLVerifier(configurationCRL);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    //Load with the results of the previous cache save but stats should be reset
    long requestCount1 = crlVerifier.getCacheStats().requestCount();
    long hitCount1 = crlVerifier.getCacheStats().hitCount();
    long missCount1 = crlVerifier.getCacheStats().missCount();
    long loadCount1 = crlVerifier.getCacheStats().loadCount();
    assertEquals(0, requestCount1);
    assertEquals(0, hitCount1);
    assertEquals(0, missCount1);
    assertEquals(0, loadCount1);

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(null, crlVerifier, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf = new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Execute the request
    HttpGet httpUriRequest;
    String data;
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI);
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    requestCount1 = crlVerifier.getCacheStats().requestCount();
    hitCount1 = crlVerifier.getCacheStats().hitCount();
    missCount1 = crlVerifier.getCacheStats().missCount();
    loadCount1 = crlVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1 > 0);
    assertTrue(hitCount1 > 0); //Because we loaded the cache from disk
    assertEquals(0, missCount1); //Because we loaded the cache from disk
    assertEquals(0, loadCount1); //Because we loaded the cache from disk

    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);
      data = httpClient.execute(httpUriRequest, responseHandler);
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
      fail("Should have worked because it's not revoked by CRL");
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    } catch (IOException e) {
      fail("Should not have received this: " + e);
      fail("Should have worked because it's not revoked by CRL");
    }
    long requestCount2 = crlVerifier.getCacheStats().requestCount();
    long hitCount2 = crlVerifier.getCacheStats().hitCount();
    long missCount2 = crlVerifier.getCacheStats().missCount();
    long loadCount2 = crlVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2 > 0);
    assertTrue(hitCount2 > 0); //Because we loaded the cache from disk
    assertEquals(0, missCount2); //Because we loaded the cache from disk
    assertEquals(0, loadCount2); //Because we loaded the cache from disk

    assertTrue(requestCount2 >= requestCount1);
    assertTrue(loadCount2 >= loadCount1);

    crlVerifier.triggerGarbageCollection();

    try {
      crlVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: yes load it: no store it: no CRL cache: no load it: N/A store it: N/A CT cache: no
   * load it: N/A store it: N/A
   *
   * <p>URL: good URL
   */
  public void test09() {
    Configuration configurationOCSP = new OCSPVerifier.Configuration();
    configurationOCSP.useCache = false;
    OCSPVerifier ocspVerifier = null;
    try {
      ocspVerifier = new OCSPVerifier(configurationOCSP);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(ocspVerifier, null, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Build the request
    HttpUriRequest httpUriRequest = new HttpGet(goodURI);

    //Execute the request
    String data;
    try {
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    ocspVerifier.triggerGarbageCollection();

    try {
      ocspVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: yes load it: no store it: no CRL cache: no load it: N/A store it: N/A CT cache: no
   * load it: N/A store it: N/A
   *
   * <p>URL: bad URL
   */
  public void test10() {
    Configuration configurationOCSP = new OCSPVerifier.Configuration();
    configurationOCSP.useCache = false;
    OCSPVerifier ocspVerifier = null;
    try {
      ocspVerifier = new OCSPVerifier(configurationOCSP);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(ocspVerifier, null, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Build the request
    HttpGet httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);

    //Execute the request
    try {
      httpClient.execute(httpUriRequest, responseHandler);
      fail("Should not have worked");
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }

    ocspVerifier.triggerGarbageCollection();

    try {
      ocspVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: yes load it: no store it: yes CRL cache: no load it: N/A store it: N/A CT cache: no
   * load it: N/A store it: N/A
   *
   * <p>URL: good and bad URL
   */
  public void test11() {
    Configuration configurationOCSP = new OCSPVerifier.Configuration();

    configurationOCSP.useCache = true;
    configurationOCSP.loadCacheFromColdStorageOnStart = false;
    configurationOCSP.loadCacheColdStorageFileName = "src/test/resources/OCSP.cache";
    configurationOCSP.storeCacheToColdStorageOnQuit = true;
    configurationOCSP.storeCacheColdStorageFileName = "src/test/resources/OCSP.cache";
    OCSPVerifier ocspVerifier = null;
    try {
      ocspVerifier = new OCSPVerifier(configurationOCSP);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(ocspVerifier, null, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Empty cache to start
    assertEquals(0, ocspVerifier.getCacheStats().requestCount());
    assertEquals(0, ocspVerifier.getCacheStats().hitCount());
    assertEquals(0, ocspVerifier.getCacheStats().missCount());
    assertEquals(0, ocspVerifier.getCacheStats().loadCount());

    HttpUriRequest httpUriRequest;
    String data;
    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI);
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    //Load the cache with 1 or more cert lookups
    long requestCount1 = ocspVerifier.getCacheStats().requestCount();
    long hitCount1 = ocspVerifier.getCacheStats().hitCount();
    long missCount1 = ocspVerifier.getCacheStats().missCount();
    long loadCount1 = ocspVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1 > 0);
    assertTrue(hitCount1 <= missCount1); //Possibly loaded the same CRL twice in one URL
    assertTrue(missCount1 > 0);
    assertTrue(loadCount1 > 0);

    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);
      data = httpClient.execute(httpUriRequest, responseHandler);
      fail("Should not have worked");
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }

    //Load the cache with additional cert lookups that should be different
    long requestCount2 = ocspVerifier.getCacheStats().requestCount();
    long hitCount2 = ocspVerifier.getCacheStats().hitCount();
    long missCount2 = ocspVerifier.getCacheStats().missCount();
    long loadCount2 = ocspVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2 > 0);
    assertTrue(hitCount2 <= missCount2);
    assertTrue(missCount2 > 0);
    assertTrue(loadCount2 > 0);

    assertTrue(requestCount2 > requestCount1);
    assertTrue(loadCount2 > loadCount1);

    ocspVerifier.triggerGarbageCollection();

    try {
      ocspVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: yes load it: yes store it: yes CRL cache: no load it: N/A store it: N/A CT cache:
   * no load it: N/A store it: N/A
   *
   * <p>URL: good and bad URL
   */
  public void test12() {

    test11(); //Make sure there is a cache to load

    Configuration configurationOCSP = new OCSPVerifier.Configuration();
    configurationOCSP.useCache = true;
    configurationOCSP.loadCacheFromColdStorageOnStart = true;
    configurationOCSP.loadCacheColdStorageFileName = "src/test/resources/OCSP.cache";
    configurationOCSP.storeCacheToColdStorageOnQuit = true;
    configurationOCSP.storeCacheColdStorageFileName = "src/test/resources/OCSP.cache";
    OCSPVerifier ocspVerifier = null;
    try {
      ocspVerifier = new OCSPVerifier(configurationOCSP);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    //Load with the results of the previous cache save but stats should be reset
    long requestCount1 = ocspVerifier.getCacheStats().requestCount();
    long hitCount1 = ocspVerifier.getCacheStats().hitCount();
    long missCount1 = ocspVerifier.getCacheStats().missCount();
    long loadCount1 = ocspVerifier.getCacheStats().loadCount();
    assertEquals(0, requestCount1);
    assertEquals(0, hitCount1);
    assertEquals(0, missCount1);
    assertEquals(0, loadCount1);

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(ocspVerifier, null, null)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    //Execute the request
    HttpGet httpUriRequest;
    String data;
    try {
      //Build the request
      httpUriRequest = new HttpGet(goodURI);
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    requestCount1 = ocspVerifier.getCacheStats().requestCount();
    hitCount1 = ocspVerifier.getCacheStats().hitCount();
    missCount1 = ocspVerifier.getCacheStats().missCount();
    loadCount1 = ocspVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1 > 0);
    assertTrue(hitCount1 > 0); //Because we loaded the cache from disk
    assertEquals(0, missCount1); //Because we loaded the cache from disk
    assertEquals(0, loadCount1); //Because we loaded the cache from disk

    //Execute the request
    try {
      //Build the request
      httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);
      data = httpClient.execute(httpUriRequest, responseHandler);
      fail("Should not have worked");
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }
    long requestCount2 = ocspVerifier.getCacheStats().requestCount();
    long hitCount2 = ocspVerifier.getCacheStats().hitCount();
    long missCount2 = ocspVerifier.getCacheStats().missCount();
    long loadCount2 = ocspVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2 > 0);
    assertTrue(hitCount2 > 0); //Because we loaded the cache from disk
    assertEquals(0, missCount2); //Because we loaded the cache from disk
    assertEquals(0, loadCount2); //Because we loaded the cache from disk

    assertTrue(requestCount2 > requestCount1);
    assertTrue(loadCount2 >= loadCount1);

    ocspVerifier.triggerGarbageCollection();

    try {
      ocspVerifier.shutdown(); //Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  @Test
  /**
   * OCSP cache: yes load it: yes store it: yes CRL cache: yes load it: yes store it: yes CT cache:
   * yes load it: yes store it: yes
   *
   * <p>URL: good and and two bad URLs
   */
  public void test13() {
    test03(); // Make sure there is a CT cache to load
    test07(); // Make sure there is a CRL cache to load
    test11(); // Make sure there is a OCSP cache to load

    Configuration configurationCT = new CTVerifier.Configuration();
    configurationCT.useCache = true;
    configurationCT.loadCacheFromColdStorageOnStart = true;
    configurationCT.loadCacheColdStorageFileName = "src/test/resources/CT.cache";
    configurationCT.storeCacheToColdStorageOnQuit = true;
    configurationCT.storeCacheColdStorageFileName = "src/test/resources/CT.cache";

    CTVerifier ctVerifier = null;
    try {
      ctVerifier = new CTVerifier(configurationCT);
    } catch (ClassNotFoundException
        | IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException e) {
      fail("Should have worked:" + e);
    }

    Configuration configurationCRL = new CRLVerifier.Configuration();
    configurationCRL.useCache = true;
    configurationCRL.loadCacheFromColdStorageOnStart = true;
    configurationCRL.loadCacheColdStorageFileName = "src/test/resources/CRL.cache";
    configurationCRL.storeCacheToColdStorageOnQuit = true;
    configurationCRL.storeCacheColdStorageFileName = "src/test/resources/CRL.cache";
    CRLVerifier crlVerifier = null;
    try {
      crlVerifier = new CRLVerifier(configurationCRL);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    Configuration configurationOCSP = new OCSPVerifier.Configuration();
    configurationOCSP.useCache = true;
    configurationOCSP.loadCacheFromColdStorageOnStart = true;
    configurationOCSP.loadCacheColdStorageFileName = "src/test/resources/OCSP.cache";
    configurationOCSP.storeCacheToColdStorageOnQuit = true;
    configurationOCSP.storeCacheColdStorageFileName = "src/test/resources/OCSP.cache";
    OCSPVerifier ocspVerifier = null;
    try {
      ocspVerifier = new OCSPVerifier(configurationOCSP);
    } catch (ClassNotFoundException | IOException e) {
      fail("Should have worked:" + e);
    }

    // Load with the results of the previous cache save but stats should be reset
    long requestCount1_CT = ctVerifier.getCacheStats().requestCount();
    long hitCount1_CT = ctVerifier.getCacheStats().hitCount();
    long missCount1_CT = ctVerifier.getCacheStats().missCount();
    long loadCount1_CT = ctVerifier.getCacheStats().loadCount();
    assertEquals(0, requestCount1_CT);
    assertEquals(0, hitCount1_CT);
    assertEquals(0, missCount1_CT);
    assertEquals(0, loadCount1_CT);

    long requestCount1_OCSP = ocspVerifier.getCacheStats().requestCount();
    long hitCount1_OCSP = ocspVerifier.getCacheStats().hitCount();
    long missCount1_OCSP = ocspVerifier.getCacheStats().missCount();
    long loadCount1_OCSP = ocspVerifier.getCacheStats().loadCount();
    assertEquals(0, requestCount1_OCSP);
    assertEquals(0, hitCount1_OCSP);
    assertEquals(0, missCount1_OCSP);
    assertEquals(0, loadCount1_OCSP);

    long requestCount1_CRL = crlVerifier.getCacheStats().requestCount();
    long hitCount1_CRL = crlVerifier.getCacheStats().hitCount();
    long missCount1_CRL = crlVerifier.getCacheStats().missCount();
    long loadCount1_CRL = crlVerifier.getCacheStats().loadCount();
    assertEquals(0, requestCount1_CRL);
    assertEquals(0, hitCount1_CRL);
    assertEquals(0, missCount1_CRL);
    assertEquals(0, loadCount1_CRL);

    SSLContext ctx = null;
    try {
      ctx = SSLContext.getInstance("TLSv1.2", "BCJSSE");
      ctx.init(
          new KeyManager[0],
          new TrustManager[] {new MyTrustManager(ocspVerifier, crlVerifier, ctVerifier)},
          new SecureRandom());
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | KeyManagementException
        | KeyStoreException e) {
      fail("Should have worked:" + e);
    }

    SSLConnectionSocketFactory sslsf = null;
    SSLContext.setDefault(ctx);
    sslsf =
        new SSLConnectionSocketFactory(ctx, new org.apache.http.conn.ssl.DefaultHostnameVerifier());

    CloseableHttpClient httpClient = makeHTTPClient(sslsf);

    ResponseHandler<String> responseHandler = makeResponseHandler();

    // Execute the request
    HttpGet httpUriRequest;
    String data;
    try {
      // Build the request
      httpUriRequest = new HttpGet(goodURI);
      data = httpClient.execute(httpUriRequest, responseHandler);
      JSONObject jo = (JSONObject) JSONValue.parse(data);
      JSONArray ja = (JSONArray) jo.get("rendezvous_nodes");
      String s = (String) ja.get(0);
      assertTrue(s.contains("tcp"));
    } catch (IOException e) {
      fail("Should have worked:" + e);
    }

    requestCount1_CT = ctVerifier.getCacheStats().requestCount();
    hitCount1_CT = ctVerifier.getCacheStats().hitCount();
    missCount1_CT = ctVerifier.getCacheStats().missCount();
    loadCount1_CT = ctVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1_CT > 0);
    assertTrue(hitCount1_CT > 0); // Because we loaded the cache from disk
    assertEquals(0, missCount1_CT); // Because we loaded the cache from disk
    assertEquals(0, loadCount1_CT); // Because we loaded the cache from disk

    requestCount1_OCSP = ocspVerifier.getCacheStats().requestCount();
    hitCount1_OCSP = ocspVerifier.getCacheStats().hitCount();
    missCount1_OCSP = ocspVerifier.getCacheStats().missCount();
    loadCount1_OCSP = ocspVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1_OCSP > 0);
    assertTrue(hitCount1_OCSP > 0); // Because we loaded the cache from disk
    assertEquals(0, missCount1_OCSP); // Because we loaded the cache from disk
    assertEquals(0, loadCount1_OCSP); // Because we loaded the cache from disk

    requestCount1_CRL = crlVerifier.getCacheStats().requestCount();
    hitCount1_CRL = crlVerifier.getCacheStats().hitCount();
    missCount1_CRL = crlVerifier.getCacheStats().missCount();
    loadCount1_CRL = crlVerifier.getCacheStats().loadCount();
    assertTrue(requestCount1_CRL > 0);
    assertTrue(hitCount1_CRL > 0); // Because we loaded the cache from disk
    assertEquals(0, missCount1_CRL); // Because we loaded the cache from disk
    assertEquals(0, loadCount1_CRL); // Because we loaded the cache from disk

    // Execute the request
    try {
      // Build the request
      httpUriRequest = new HttpGet(badURIRevoked_OCSP_ONLY);
      data = httpClient.execute(httpUriRequest, responseHandler);
      fail("Should not have worked");
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }

    long requestCount2_CT = ctVerifier.getCacheStats().requestCount();
    long hitCount2_CT = ctVerifier.getCacheStats().hitCount();
    long missCount2_CT = ctVerifier.getCacheStats().missCount();
    long loadCount2_CT = ctVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2_CT > 0);
    assertTrue(hitCount2_CT > 0); // Because we loaded the cache from disk and it had the good URI
    assertEquals(
        0,
        missCount2_CT); // Because we knew the cert was revoked by OCSP and it short-circuited CT check
    assertEquals(
        0,
        loadCount2_CT); // Because we knew the cert was revoked by OCSP and it short-circuited CT check

    long requestCount2_OCSP = ocspVerifier.getCacheStats().requestCount();
    long hitCount2_OCSP = ocspVerifier.getCacheStats().hitCount();
    long missCount2_OCSP = ocspVerifier.getCacheStats().missCount();
    long loadCount2_OCSP = ocspVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2_OCSP > 0);
    assertTrue(hitCount2_OCSP > 0); // Because we loaded the cache from disk
    assertEquals(0, missCount2_OCSP); // Because we loaded the cache from disk
    assertEquals(0, loadCount2_OCSP); // Because we loaded the cache from disk

    long requestCount2_CRL = crlVerifier.getCacheStats().requestCount();
    long hitCount2_CRL = crlVerifier.getCacheStats().hitCount();
    long missCount2_CRL = crlVerifier.getCacheStats().missCount();
    long loadCount2_CRL = crlVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2_CRL > 0);
    assertTrue(hitCount2_CRL > 0); // Because we loaded the cache from disk
    assertEquals(0, missCount2_CRL); // Because we loaded the cache from disk
    assertEquals(0, loadCount2_CRL); // Because we loaded the cache from disk

    assertTrue(requestCount2_CT >= requestCount1_CT);
    assertTrue(loadCount2_CT >= loadCount1_CT);

    assertTrue(requestCount2_OCSP >= requestCount1_OCSP);
    assertTrue(loadCount2_OCSP >= loadCount1_OCSP);

    assertTrue(requestCount2_CRL >= requestCount1_CRL);
    assertTrue(loadCount2_CRL >= loadCount1_CRL);

    // Reset cache to test cache resetting, this just ends up saving and reloading the same cache
    ocspVerifier.resetCache();
    crlVerifier.resetCache();
    ctVerifier.resetCache();

    // Execute the request
    try {
      // Build the request
      httpUriRequest = new HttpGet(goodURI2);
      data = httpClient.execute(httpUriRequest, responseHandler);
      //fail("Should not have worked");
    } catch (org.bouncycastle.tls.TlsFatalAlert e) {
      assertTrue(e.getMessage().contains("certificate_unknown(46)"));
    } catch (ClientProtocolException e) {
      fail("Should not have received this: " + e);
    } catch (IOException e) {
      fail("Should not have received this: " + e);
    }

    requestCount2_CT = ctVerifier.getCacheStats().requestCount();
    hitCount2_CT = ctVerifier.getCacheStats().hitCount();
    missCount2_CT = ctVerifier.getCacheStats().missCount();
    loadCount2_CT = ctVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2_CT > 0);
    assertTrue(hitCount2_CT > 0);
    assertEquals(0, missCount2_CT); // We've seen everything before
    assertEquals(0, loadCount2_CT); // We've seen everything before

    requestCount2_OCSP = ocspVerifier.getCacheStats().requestCount();
    hitCount2_OCSP = ocspVerifier.getCacheStats().hitCount();
    missCount2_OCSP = ocspVerifier.getCacheStats().missCount();
    loadCount2_OCSP = ocspVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2_OCSP > 0);
    assertEquals(0, hitCount2_OCSP); // This is the first time OCSP has seen this URI
    assertTrue(missCount2_OCSP > 0);
    assertTrue(loadCount2_OCSP > 0);

    requestCount2_CRL = crlVerifier.getCacheStats().requestCount();
    hitCount2_CRL = crlVerifier.getCacheStats().hitCount();
    missCount2_CRL = crlVerifier.getCacheStats().missCount();
    loadCount2_CRL = crlVerifier.getCacheStats().loadCount();
    assertTrue(requestCount2_CRL > 0);
    assertEquals(0, hitCount2_CRL); // This is the first time CRL has seen this URI
    assertTrue(missCount2_CRL > 0);
    assertTrue(loadCount2_CRL > 0);

    ocspVerifier.triggerGarbageCollection();
    crlVerifier.triggerGarbageCollection();
    ctVerifier.triggerGarbageCollection();

    try {
      ocspVerifier.shutdown(); // Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
    try {
      crlVerifier.shutdown(); // Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
    try {
      ctVerifier.shutdown(); // Save the cache
    } catch (IOException e) {
      fail("This should have worked: " + e);
    }
  }

  public class MyTrustManager implements X509TrustManager {

    private X509TrustManager x509Tm;

    private OCSPVerifier ocspVerifier = null;
    private CRLVerifier crlVerifier = null;
    private CTVerifier ctVerifier = null;

    public MyTrustManager(OCSPVerifier ocspVerifier, CRLVerifier crlVerifier, CTVerifier ctVerifier)
        throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
      this.ocspVerifier = ocspVerifier;
      this.crlVerifier = crlVerifier;
      this.ctVerifier = ctVerifier;
      TrustManagerFactory tmf = null;
      tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(), "BCJSSE");
      tmf.init((KeyStore) null);

      // Get hold of the default trust manager
      for (TrustManager tm : tmf.getTrustManagers()) {
        if (tm instanceof X509TrustManager) {
          x509Tm = (X509TrustManager) tm;
          break;
        }
      }
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {}

    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      if (x509Tm == null) {
        throw new CertificateException("Cacerts could not be loaded");
      }

      x509Tm.checkServerTrusted(chain, authType);
      int n = chain.length;
      for (int i = 0; i < (n - 1); i++) {
        X509Certificate cert = chain[i];
        X509Certificate issuer = chain[i + 1];
        if (cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()) == false) {
          throw new CertificateVerificationException("Certificates do not chain");
        }

        VerificationStatus ocsp_status = null;

        //First check with OCSP protocol
        if (ocspVerifier != null) {
          try {
            ocsp_status = ocspVerifier.checkRevocationStatus(cert, issuer, chain);
            if (ocsp_status.getStatus() == VerificationStatus.BAD) {
              throw new CertificateVerificationException(
                  "Certificate revoked by OCSP on "
                      + SimpleDateFormat.getInstance().format(ocsp_status.getRevokeDate()));
            }
          } catch (CertificateVerificationException e) {
            if (ocsp_status == null) {
              ocsp_status = new VerificationStatus(VerificationStatus.BAD, cert.getNotAfter());
            } else if (ocsp_status.getStatus() == VerificationStatus.BAD) {
              throw e;
            }
          }
        }

        //If needed, check with CRL protocol
        if (crlVerifier != null) {
          //Then check with CRL protocol
          VerificationStatus crl_status = null;
          //If we passed OCSP then check with CRL protocol
          if ((ocsp_status == null) || (ocsp_status.getStatus() == VerificationStatus.GOOD)) {
            crl_status = crlVerifier.checkRevocationStatus(cert, issuer, chain);
            if (crl_status.getStatus() == VerificationStatus.BAD) {
              throw new CertificateVerificationException(
                  "Certificate revoked by CRL on "
                      + SimpleDateFormat.getInstance().format(crl_status.getRevokeDate()));
            }
          }
        }

        if (i == 0) {
          //Check with Certificate Transparency protocol
          if (ctVerifier != null) {
            //Then check with CRL protocol
            VerificationStatus ct_status = null;
            //System.out.print("Checking the status of :"+cert.getSerialNumber());
            ct_status = ctVerifier.checkRevocationStatus(cert, chain);
            //System.out.println("\t"+ct_status.getStatus());
            if (ct_status.getStatus() == VerificationStatus.BAD) {
              throw new CertificateVerificationException(
                  "Certificate not supported by CT (Certificate Transparency) ");
            }
          }
        }
      }
    }

    public X509Certificate[] getAcceptedIssuers() {
      return x509Tm.getAcceptedIssuers();
    }
  }
}
