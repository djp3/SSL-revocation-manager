package net.djp3.sslcert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import net.djp3.sslcert.Verifier.Configuration;
import net.djp3.sslcert.crl.CRLVerifier;
import net.djp3.sslcert.ocsp.OCSPVerifier;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;

public class VerifierTest {
	
	private static URI goodURI = null;
	private static URI badURI = null;

	@BeforeAll
	static void setUpBeforeClass() throws Exception {
		//GlobalsForTesting.reset("testSupport/JustFatals.log4j.xml");
		System.setProperty("log4j.configurationFile","src/test/resources/Everything.log4j.xml");
		
		Security.addProvider(new BouncyCastleJsseProvider());		
		
		try {
			goodURI = new URIBuilder().setScheme("https").setHost("raw.github.com").setPath("/djp3/p2p4java/production/bootstrapMasterList.json").build();
			badURI = new URIBuilder().setScheme("https").setHost("revoked.badssl.com").setPath("/").build();
		} catch (URISyntaxException e) {
			fail("This should have worked");
		}
	}

	@AfterAll
	static void tearDownAfterClass() throws Exception {
	}

	@BeforeEach
	void setUp() throws Exception {
	}

	@AfterEach
	void tearDown() throws Exception {
	}

	
	public ResponseHandler<String> makeResponseHandler() {
		return new ResponseHandler<String>() {
			@Override
			public String handleResponse(final HttpResponse response) throws ClientProtocolException, IOException {
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
							.setRetryHandler(new DefaultHttpRequestRetryHandler(0,false))
							.build();
	}

	public RequestConfig makeRequestConfig() {
		return RequestConfig.custom()
					.setCookieSpec(CookieSpecs.STANDARD)
					.build();
	}

	@Test
	/** OCSP cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 *   CRL cache: yes
	 * 	   load it: no
	 * 	  store it: no 
	 * 
	 *   URL: good URL
	 */
	public void test01(){
		Configuration configurationCRL = new CRLVerifier.Configuration();
		configurationCRL.useCache = false;
		CRLVerifier crlVerifier = null;
		try {
			crlVerifier = new CRLVerifier(configurationCRL);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
			
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(null,crlVerifier)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
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
			fail("Should have worked:"+e);
		}
		
		crlVerifier.triggerGarbageCollection();
		
		try {
			crlVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}

	@Test
	/** OCSP cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 *   CRL cache: yes
	 * 	   load it: no
	 * 	  store it: no 
	 * 
	 *   URL: bad URL
	 */
	public void test02(){
		Configuration configurationCRL = new CRLVerifier.Configuration();
		configurationCRL.useCache = false;
		CRLVerifier crlVerifier = null;
		try {
			crlVerifier = new CRLVerifier(configurationCRL);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(null,crlVerifier)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
		CloseableHttpClient httpClient = makeHTTPClient(sslsf);
		
		ResponseHandler<String> responseHandler = makeResponseHandler();
		
		//Build the request
		HttpGet httpUriRequest = new HttpGet(badURI);
		
		//Execute the request
		try {
			httpClient.execute(httpUriRequest, responseHandler);
			fail("Should not have worked");
		} catch (org.bouncycastle.tls.TlsFatalAlert e) {  
			assertTrue(e.getMessage().contains("bad_certificate(42)"));
		} catch (ClientProtocolException e) {
			fail("Should not have received this: "+e);
		} catch (IOException e) {
			fail("Should not have received this: "+e);
		}
		
		crlVerifier.triggerGarbageCollection();
		
		try {
			crlVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}
	
	@Test
	/** OCSP cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 *   CRL cache: yes
	 * 	   load it: no
	 * 	  store it: yes 
	 * 
	 *   URL: good and bad URL
	 */
	public void test03(){
		Configuration configurationCRL = new CRLVerifier.Configuration();

		configurationCRL.useCache = true;
		configurationCRL.loadCacheFromColdStorageOnStart = false;
		configurationCRL.loadCacheColdStorageFileName = "src/test/resources/CRL.cache";
		configurationCRL.storeCacheToColdStorageOnQuit= true;
		configurationCRL.storeCacheColdStorageFileName= "src/test/resources/CRL.cache";
		CRLVerifier crlVerifier = null;
		try {
			crlVerifier = new CRLVerifier(configurationCRL);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(null,crlVerifier)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
		CloseableHttpClient httpClient = makeHTTPClient(sslsf);
		
		ResponseHandler<String> responseHandler = makeResponseHandler();
		
		//Empty cache to start
		assertEquals(0,crlVerifier.getCacheStats().requestCount());
		assertEquals(0,crlVerifier.getCacheStats().hitCount());
		assertEquals(0,crlVerifier.getCacheStats().missCount());
		assertEquals(0,crlVerifier.getCacheStats().loadCount());
		
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
			fail("Should have worked:"+e);
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
			httpUriRequest = new HttpGet(badURI);
			data = httpClient.execute(httpUriRequest, responseHandler);
			fail("Should not have worked");
		} catch (org.bouncycastle.tls.TlsFatalAlert e) {  
			assertTrue(e.getMessage().contains("bad_certificate(42)"));
		} catch (ClientProtocolException e) {
			fail("Should not have received this: "+e);
		} catch (IOException e) {
			fail("Should not have received this: "+e);
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
		
		assertTrue(requestCount2 > requestCount1);
		assertTrue(loadCount2 > loadCount1);
		
		crlVerifier.triggerGarbageCollection();
		
		try {
			crlVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}
	
	@Test
	/** OCSP cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 *   CRL cache: yes
	 * 	   load it: yes
	 * 	  store it: yes 
	 * 
	 *   URL: good and bad URL
	 */
	public void test04(){
		
		test03(); //Make sure there is a cache to load
		
		Configuration configurationCRL = new CRLVerifier.Configuration();
		configurationCRL.useCache = true;
		configurationCRL.loadCacheFromColdStorageOnStart = true;
		configurationCRL.loadCacheColdStorageFileName = "src/test/resources/CRL.cache";
		configurationCRL.storeCacheToColdStorageOnQuit= true;
		configurationCRL.storeCacheColdStorageFileName= "src/test/resources/CRL.cache";
		CRLVerifier crlVerifier = null;
		try {
			crlVerifier = new CRLVerifier(configurationCRL);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		//Load with the results of the previous cache save but stats should be reset
		long requestCount1 = crlVerifier.getCacheStats().requestCount();
		long hitCount1 = crlVerifier.getCacheStats().hitCount();
		long missCount1 = crlVerifier.getCacheStats().missCount();
		long loadCount1 = crlVerifier.getCacheStats().loadCount();
		assertEquals(0,requestCount1);
		assertEquals(0, hitCount1);
		assertEquals(0,missCount1);
		assertEquals(0,loadCount1);
				
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(null,crlVerifier)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
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
			fail("Should have worked:"+e);
		}
		
		requestCount1 = crlVerifier.getCacheStats().requestCount();
		hitCount1 = crlVerifier.getCacheStats().hitCount();
		missCount1 = crlVerifier.getCacheStats().missCount();
		loadCount1 = crlVerifier.getCacheStats().loadCount();
		assertTrue(requestCount1 > 0);
		assertTrue(hitCount1 > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount1); //Because we loaded the cache from disk
		assertEquals(0,loadCount1); //Because we loaded the cache from disk
		
		//Execute the request
		try {
			//Build the request
			httpUriRequest = new HttpGet(badURI);
			data = httpClient.execute(httpUriRequest, responseHandler);
			fail("Should not have worked");
		} catch (org.bouncycastle.tls.TlsFatalAlert e) {  
			assertTrue(e.getMessage().contains("bad_certificate(42)"));
		} catch (ClientProtocolException e) {
			fail("Should not have received this: "+e);
		} catch (IOException e) {
			fail("Should not have received this: "+e);
		}
		long requestCount2 = crlVerifier.getCacheStats().requestCount();
		long hitCount2 = crlVerifier.getCacheStats().hitCount();
		long missCount2 = crlVerifier.getCacheStats().missCount();
		long loadCount2 = crlVerifier.getCacheStats().loadCount();
		assertTrue(requestCount2 > 0);
		assertTrue(hitCount2 > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount2); //Because we loaded the cache from disk
		assertEquals(0,loadCount2); //Because we loaded the cache from disk
		
		assertTrue(requestCount2 > requestCount1);
		assertTrue(loadCount2 >= loadCount1);
		
		crlVerifier.triggerGarbageCollection();
		
		try {
			crlVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}
	

	@Test
	/** OCSP cache: yes
	 * 	   load it: no
	 * 	  store it: no 
	 *   CRL cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 * 
	 *   URL: good URL
	 */
	public void test05(){
		Configuration configurationOCSP = new OCSPVerifier.Configuration();
		configurationOCSP.useCache = false;
		OCSPVerifier ocspVerifier = null;
		try {
			ocspVerifier = new OCSPVerifier(configurationOCSP);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
			
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(ocspVerifier,null)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
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
			fail("Should have worked:"+e);
		}
		
		ocspVerifier.triggerGarbageCollection();
		
		try {
			ocspVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}

	@Test
	/** OCSP cache: yes
	 * 	   load it: no
	 * 	  store it: no 
	 *   CRL cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 * 
	 *   URL: bad URL
	 */
	public void test06(){
		Configuration configurationOCSP = new OCSPVerifier.Configuration();
		configurationOCSP.useCache = false;
		OCSPVerifier ocspVerifier = null;
		try {
			ocspVerifier = new OCSPVerifier(configurationOCSP);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(ocspVerifier,null)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
		CloseableHttpClient httpClient = makeHTTPClient(sslsf);
		
		ResponseHandler<String> responseHandler = makeResponseHandler();
		
		//Build the request
		HttpGet httpUriRequest = new HttpGet(badURI);
		
		//Execute the request
		try {
			httpClient.execute(httpUriRequest, responseHandler);
			fail("Should not have worked");
		} catch (org.bouncycastle.tls.TlsFatalAlert e) {  
			assertTrue(e.getMessage().contains("bad_certificate(42)"));
		} catch (ClientProtocolException e) {
			fail("Should not have received this: "+e);
		} catch (IOException e) {
			fail("Should not have received this: "+e);
		}
		
		ocspVerifier.triggerGarbageCollection();
		
		try {
			ocspVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}
	
	@Test
	/** OCSP cache: yes
	 * 	   load it: no
	 * 	  store it: yes 
	 *   CRL cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 * 
	 *   URL: good and bad URL
	 */
	public void test07(){
		Configuration configurationOCSP = new OCSPVerifier.Configuration();

		configurationOCSP.useCache = true;
		configurationOCSP.loadCacheFromColdStorageOnStart = false;
		configurationOCSP.loadCacheColdStorageFileName = "src/test/resources/OCSP.cache";
		configurationOCSP.storeCacheToColdStorageOnQuit= true;
		configurationOCSP.storeCacheColdStorageFileName= "src/test/resources/OCSP.cache";
		OCSPVerifier ocspVerifier = null;
		try {
			ocspVerifier = new OCSPVerifier(configurationOCSP);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(ocspVerifier,null)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
		CloseableHttpClient httpClient = makeHTTPClient(sslsf);
		
		ResponseHandler<String> responseHandler = makeResponseHandler();
		
		//Empty cache to start
		assertEquals(0,ocspVerifier.getCacheStats().requestCount());
		assertEquals(0,ocspVerifier.getCacheStats().hitCount());
		assertEquals(0,ocspVerifier.getCacheStats().missCount());
		assertEquals(0,ocspVerifier.getCacheStats().loadCount());
		
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
			fail("Should have worked:"+e);
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
			httpUriRequest = new HttpGet(badURI);
			data = httpClient.execute(httpUriRequest, responseHandler);
			fail("Should not have worked");
		} catch (org.bouncycastle.tls.TlsFatalAlert e) {  
			assertTrue(e.getMessage().contains("bad_certificate(42)"));
		} catch (ClientProtocolException e) {
			fail("Should not have received this: "+e);
		} catch (IOException e) {
			fail("Should not have received this: "+e);
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
			fail("This should have worked: "+e);
		}
	}
	
	@Test
	/** OCSP cache: yes
	 * 	   load it: yes
	 * 	  store it: yes 
	 *   CRL cache: no
	 * 	   load it: N/A
	 * 	  store it: N/A
	 * 
	 *   URL: good and bad URL
	 */
	public void test08(){
		
		test07(); //Make sure there is a cache to load
		
		Configuration configurationOCSP = new OCSPVerifier.Configuration();
		configurationOCSP.useCache = true;
		configurationOCSP.loadCacheFromColdStorageOnStart = true;
		configurationOCSP.loadCacheColdStorageFileName = "src/test/resources/OCSP.cache";
		configurationOCSP.storeCacheToColdStorageOnQuit= true;
		configurationOCSP.storeCacheColdStorageFileName= "src/test/resources/OCSP.cache";
		OCSPVerifier ocspVerifier = null;
		try {
			ocspVerifier = new OCSPVerifier(configurationOCSP);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		//Load with the results of the previous cache save but stats should be reset
		long requestCount1 = ocspVerifier.getCacheStats().requestCount();
		long hitCount1 = ocspVerifier.getCacheStats().hitCount();
		long missCount1 = ocspVerifier.getCacheStats().missCount();
		long loadCount1 = ocspVerifier.getCacheStats().loadCount();
		assertEquals(0,requestCount1);
		assertEquals(0, hitCount1);
		assertEquals(0,missCount1);
		assertEquals(0,loadCount1);
				
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(ocspVerifier,null)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
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
			fail("Should have worked:"+e);
		}
		
		requestCount1 = ocspVerifier.getCacheStats().requestCount();
		hitCount1 = ocspVerifier.getCacheStats().hitCount();
		missCount1 = ocspVerifier.getCacheStats().missCount();
		loadCount1 = ocspVerifier.getCacheStats().loadCount();
		assertTrue(requestCount1 > 0);
		assertTrue(hitCount1 > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount1); //Because we loaded the cache from disk
		assertEquals(0,loadCount1); //Because we loaded the cache from disk
		
		//Execute the request
		try {
			//Build the request
			httpUriRequest = new HttpGet(badURI);
			data = httpClient.execute(httpUriRequest, responseHandler);
			fail("Should not have worked");
		} catch (org.bouncycastle.tls.TlsFatalAlert e) {  
			assertTrue(e.getMessage().contains("bad_certificate(42)"));
		} catch (ClientProtocolException e) {
			fail("Should not have received this: "+e);
		} catch (IOException e) {
			fail("Should not have received this: "+e);
		}
		long requestCount2 = ocspVerifier.getCacheStats().requestCount();
		long hitCount2 = ocspVerifier.getCacheStats().hitCount();
		long missCount2 = ocspVerifier.getCacheStats().missCount();
		long loadCount2 = ocspVerifier.getCacheStats().loadCount();
		assertTrue(requestCount2 > 0);
		assertTrue(hitCount2 > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount2); //Because we loaded the cache from disk
		assertEquals(0,loadCount2); //Because we loaded the cache from disk
		
		assertTrue(requestCount2 > requestCount1);
		assertTrue(loadCount2 >= loadCount1);
		
		ocspVerifier.triggerGarbageCollection();
		
		try {
			ocspVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}
		
	@Test
	/** OCSP cache: yes
	 * 	   load it: yes
	 * 	  store it: yes 
	 *   CRL cache: yes
	 * 	   load it: yes
	 * 	  store it: yes
	 * 
	 *   URL: good and bad URL
	 */
	public void test09(){
		test03(); //Make sure there is a CRL cache to load
		test07(); //Make sure there is a OCSP cache to load
		
		Configuration configurationCRL = new CRLVerifier.Configuration();
		configurationCRL.useCache = true;
		configurationCRL.loadCacheFromColdStorageOnStart = true;
		configurationCRL.loadCacheColdStorageFileName = "src/test/resources/CRL.cache";
		configurationCRL.storeCacheToColdStorageOnQuit= true;
		configurationCRL.storeCacheColdStorageFileName= "src/test/resources/CRL.cache";
		CRLVerifier crlVerifier = null;
		try {
			crlVerifier = new CRLVerifier(configurationCRL);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		Configuration configurationOCSP = new OCSPVerifier.Configuration();
		configurationOCSP.useCache = true;
		configurationOCSP.loadCacheFromColdStorageOnStart = true;
		configurationOCSP.loadCacheColdStorageFileName = "src/test/resources/OCSP.cache";
		configurationOCSP.storeCacheToColdStorageOnQuit= true;
		configurationOCSP.storeCacheColdStorageFileName= "src/test/resources/OCSP.cache";
		OCSPVerifier ocspVerifier = null;
		try {
			ocspVerifier = new OCSPVerifier(configurationOCSP);
		} catch (ClassNotFoundException | IOException e) {
			fail("Should have worked:"+e);
		}
		
		//Load with the results of the previous cache save but stats should be reset
		long requestCount1_OCSP = ocspVerifier.getCacheStats().requestCount();
		long hitCount1_OCSP = ocspVerifier.getCacheStats().hitCount();
		long missCount1_OCSP = ocspVerifier.getCacheStats().missCount();
		long loadCount1_OCSP = ocspVerifier.getCacheStats().loadCount();
		assertEquals(0,requestCount1_OCSP);
		assertEquals(0, hitCount1_OCSP);
		assertEquals(0,missCount1_OCSP);
		assertEquals(0,loadCount1_OCSP);
		
		long requestCount1_CRL = crlVerifier.getCacheStats().requestCount();
		long hitCount1_CRL = crlVerifier.getCacheStats().hitCount();
		long missCount1_CRL = crlVerifier.getCacheStats().missCount();
		long loadCount1_CRL = crlVerifier.getCacheStats().loadCount();
		assertEquals(0,requestCount1_CRL);
		assertEquals(0, hitCount1_CRL);
		assertEquals(0,missCount1_CRL);
		assertEquals(0,loadCount1_CRL);
				
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLSv1.2","BCJSSE");
			ctx.init(	new KeyManager[0],
						new TrustManager[] {
								new MyTrustManager(ocspVerifier,crlVerifier)
							},
							new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException | KeyStoreException e) {
			fail("Should have worked:"+e);
		}
		
		SSLConnectionSocketFactory sslsf = null;
		SSLContext.setDefault(ctx);
		sslsf = new SSLConnectionSocketFactory( ctx,new org.apache.http.conn.ssl.DefaultHostnameVerifier());
		
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
			fail("Should have worked:"+e);
		}
		
		requestCount1_OCSP = ocspVerifier.getCacheStats().requestCount();
		hitCount1_OCSP = ocspVerifier.getCacheStats().hitCount();
		missCount1_OCSP = ocspVerifier.getCacheStats().missCount();
		loadCount1_OCSP = ocspVerifier.getCacheStats().loadCount();
		assertTrue(requestCount1_OCSP > 0);
		assertTrue(hitCount1_OCSP > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount1_OCSP); //Because we loaded the cache from disk
		assertEquals(0,loadCount1_OCSP); //Because we loaded the cache from disk
		
		requestCount1_CRL = crlVerifier.getCacheStats().requestCount();
		hitCount1_CRL = crlVerifier.getCacheStats().hitCount();
		missCount1_CRL = crlVerifier.getCacheStats().missCount();
		loadCount1_CRL = crlVerifier.getCacheStats().loadCount();
		assertTrue(requestCount1_CRL > 0);
		assertTrue(hitCount1_CRL > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount1_CRL); //Because we loaded the cache from disk
		assertEquals(0,loadCount1_CRL); //Because we loaded the cache from disk
		
		//Execute the request
		try {
			//Build the request
			httpUriRequest = new HttpGet(badURI);
			data = httpClient.execute(httpUriRequest, responseHandler);
			fail("Should not have worked");
		} catch (org.bouncycastle.tls.TlsFatalAlert e) {  
			assertTrue(e.getMessage().contains("bad_certificate(42)"));
		} catch (ClientProtocolException e) {
			fail("Should not have received this: "+e);
		} catch (IOException e) {
			fail("Should not have received this: "+e);
		}
		long requestCount2_OCSP = ocspVerifier.getCacheStats().requestCount();
		long hitCount2_OCSP = ocspVerifier.getCacheStats().hitCount();
		long missCount2_OCSP = ocspVerifier.getCacheStats().missCount();
		long loadCount2_OCSP = ocspVerifier.getCacheStats().loadCount();
		assertTrue(requestCount2_OCSP > 0);
		assertTrue(hitCount2_OCSP > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount2_OCSP); //Because we loaded the cache from disk
		assertEquals(0,loadCount2_OCSP); //Because we loaded the cache from disk
		
		long requestCount2_CRL = crlVerifier.getCacheStats().requestCount();
		long hitCount2_CRL = crlVerifier.getCacheStats().hitCount();
		long missCount2_CRL = crlVerifier.getCacheStats().missCount();
		long loadCount2_CRL = crlVerifier.getCacheStats().loadCount();
		assertTrue(requestCount2_CRL > 0);
		assertTrue(hitCount2_CRL > 0); //Because we loaded the cache from disk
		assertEquals(0,missCount2_CRL); //Because we loaded the cache from disk
		assertEquals(0,loadCount2_CRL); //Because we loaded the cache from disk
		
		assertTrue(requestCount2_OCSP >= requestCount1_OCSP);
		assertTrue(loadCount2_OCSP >= loadCount1_OCSP);
		
		assertTrue(requestCount2_CRL >= requestCount1_CRL);
		assertTrue(loadCount2_CRL >= loadCount1_CRL);
		
		ocspVerifier.triggerGarbageCollection();
		crlVerifier.triggerGarbageCollection();
		
		try {
			ocspVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
		try {
			crlVerifier.shutdown(); //Save the cache
		} catch (IOException e) {
			fail("This should have worked: "+e);
		}
	}
		

	public class MyTrustManager implements X509TrustManager{
	
		private X509TrustManager x509Tm;

		private OCSPVerifier ocspVerifier = null;
		private CRLVerifier crlVerifier = null;
	
	
	
		public MyTrustManager(OCSPVerifier ocspVerifier, CRLVerifier crlVerifier) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
			this.ocspVerifier = ocspVerifier;
			this.crlVerifier = crlVerifier;
			TrustManagerFactory tmf = null;
			tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(),"BCJSSE");
			tmf.init((KeyStore) null);
           
			// Get hold of the default trust manager
			for (TrustManager tm : tmf.getTrustManagers()) {
				if (tm instanceof X509TrustManager) {
					x509Tm = (X509TrustManager) tm;
					break;
				}
			}
		}

		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			if (x509Tm == null) {
				throw new CertificateException("Cacerts could not be loaded");
			}

			x509Tm.checkServerTrusted(chain, authType);
			int n = chain.length;
			for (int i = 0; i < n - 1; i++) {
				X509Certificate cert = chain[i];
				X509Certificate issuer = chain[i + 1];
				if (cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()) == false) {
					throw new CertificateVerificationException("Certificates do not chain");
				}
       		
				RevocationStatus ocsp_status = null;
       		
				//First check with OCSP protocol
				if(ocspVerifier != null) {
					try {
						ocsp_status = ocspVerifier.checkRevocationStatus(cert, issuer);
						if(ocsp_status.getStatus() == RevocationStatus.REVOKED) {
							throw new CertificateVerificationException("Certificate revoked by OCSP on "+SimpleDateFormat.getInstance().format(ocsp_status.getRevokeDate()));
						}
					}catch(CertificateVerificationException e) {
						if(ocsp_status == null) {
							ocsp_status = new RevocationStatus(RevocationStatus.UNKNOWN);
						}
						else if (ocsp_status.getStatus() == RevocationStatus.REVOKED) {
							throw e;
						}
					}
				}
       	
				//If needed, check with CRL protocol
				if(crlVerifier != null) {
					//Then check with CRL protocol
					RevocationStatus crl_status = null;
					//If we passed OCSP then check with CRL protocol
					if((ocsp_status == null) || (ocsp_status.getStatus() == RevocationStatus.GOOD) || (ocsp_status.getStatus() == RevocationStatus.UNKNOWN)) {
						crl_status = crlVerifier.checkRevocationStatus(cert, issuer);
						if(crl_status.getStatus() == RevocationStatus.REVOKED) {
							throw new CertificateVerificationException("Certificate revoked by CRL on "+SimpleDateFormat.getInstance().format(crl_status.getRevokeDate()));
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
