/*
	Copyright 2007-2018
		Donald J. Patterson
*/
/*
	This file is part of SSL Revocation Manager , i.e. "SSLRM"

    SSLRM is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    SSLRM is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with SSLRM.  If not, see <http://www.gnu.org/licenses/>.
*/

package com.djp3.sslcert.ocsp;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidParameterException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.djp3.sslcert.CertificateVerificationException;
import com.djp3.sslcert.VerificationStatus;
import com.djp3.sslcert.Verifier;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheStats;

/**
 * This is used to check if an SSL Certificate is revoked or not by using its CA using the Online
 * CertificateStatus Protocol (OCSP).
 */
public class OCSPVerifier extends Verifier<BigInteger, VerificationStatus> {

  private static transient volatile Logger log = null;

  public static Logger getLog() {
    if (log == null) {
      log = LogManager.getLogger(OCSPVerifier.class);
    }
    return log;
  }

  public OCSPVerifier(Configuration config)
      throws FileNotFoundException, ClassNotFoundException, IOException {
    super(config);
  }

	/**
	 * This is run periodically by the cache to clean out any cache entries that have expired: Not according to cache
	 * semantics but by virtue of the information associated with the revocation data.
	 */
	protected Runnable getValidityCheckerCode() {
		return new Runnable() {
			@Override
			public void run() {
				Cache<BigInteger, VerificationStatus> cache = getCache();
				if (config.useCache && (cache != null)) {
					StringBuffer info = new StringBuffer();
					info.append("\nRunning validity check on OCSP Cache");
					CacheStats stats = cache.stats();
					long presize = cache.size();
					String chunk = "" 
							+ "\tAverage Load Penalty: " 
							+ stats.averageLoadPenalty()
							+ "\t            Hit Rate: " 
							+ stats.hitRate() 
							+ "\tLoad Exception Count: "
							+ stats.loadExceptionCount() 
							+ "\t       Request Count: " 
							+ stats.requestCount() 
							+ "\n";
					Date now = new Date();
					for (Entry<BigInteger, VerificationStatus> x : cache.asMap().entrySet()) {
						VerificationStatus resp = x.getValue();
						Date nextUpdate = resp.getNextUpdate();
						if ((nextUpdate == null) || (nextUpdate.before(now))) {
							cache.invalidate(x.getKey());
						}
					}
					info.append("\tPre Size: " + presize + "\tPost Size: " + cache.size());
					info.append(chunk);
					getLog().debug(info.toString());
				}
			}
		};
	}

  /**
   * This method generates an OCSP Request to be sent to an OCSP endpoint.
   *
   * @param issuerCert is the Certificate of the Issuer of the peer certificate we are interested
   *     in.
   * @param serialNumber of the peer certificate.
   * @return generated OCSP request.
   * @throws CertificateVerificationException
   */
  private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
      throws CertificateVerificationException {

    try {
      JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder =
          new JcaDigestCalculatorProviderBuilder();
      DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
      DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);

      // Generate the id for the certificate we are looking for
      CertificateID id =
          new CertificateID(
              digestCalculator, new JcaX509CertificateHolder(issuerCert), serialNumber);

      // basic request generation with nonce
      OCSPReqBuilder builder = new OCSPReqBuilder();

      builder.addRequest(id);

      // create details for nonce extension. The nonce extension is used to bind
      // a request to a response to prevent replay attacks. As the name implies,
      // the nonce value is something that the client should only use once within a
      // reasonably
      // small period.
      // create details for nonce extension
      BigInteger nonce = BigInteger.valueOf(r.nextLong());
      Extension ext =
          new Extension(
              OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
              false,
              new DEROctetString(nonce.toByteArray()).getEncoded());
      builder.setRequestExtensions(new Extensions(new Extension[] {ext}));

      return builder.build();
    } catch (OCSPException
        | OperatorCreationException
        | CertificateEncodingException
        | IOException e) {
      throw new CertificateVerificationException(
          "Cannot generate OCSP Request with the given certificate", e);
    }
  }

  /**
   * Gets an ASN.1 encoded OCSP response (as defined in RFC 2560) from the given service URL.
   * Currently supports only HTTP.
   *
   * @param serviceUrl URL of the OCSP endpoint.
   * @param request an OCSP request object.
   * @return OCSP response encoded in ASN.1 structure.
   * @throws CertificateVerificationException
   */
  protected OCSPResp getOCSPResponse(String serviceUrl, OCSPReq request)
      throws CertificateVerificationException {

    // Make sure we got good input
    if ((serviceUrl == null) || (request == null)) {
      throw new InvalidParameterException(
          "Need non-null parameters: serviceUrl:\""
              + serviceUrl
              + "\", request:\""
              + request
              + "\"");
    }
    if (!serviceUrl.startsWith("http:")) {
      throw new CertificateVerificationException(
          "Only http: supported for serviceUrl:\"" + serviceUrl + "\"");
    }

    // Build HTTP Post
    URI uri;
    try {
      uri = new URI(serviceUrl);
    } catch (URISyntaxException e) {
      throw new CertificateVerificationException(
          "Unable to parse serviceUrl:\"" + serviceUrl + "\"");
    }
    HttpPost httpPost = new HttpPost(uri);
    httpPost.setHeader("Content-Type", "application/ocsp-request");
    httpPost.setHeader("Accept", "application/ocsp-response");
    ByteArrayEntity byteArrayEntity;
    try {
      byteArrayEntity = new ByteArrayEntity(request.getEncoded());
    } catch (IOException e) {
      throw new CertificateVerificationException(
          "Unable to parse request:\"" + request + "\"\n" + e);
    }
    httpPost.setEntity(byteArrayEntity);

    // Send request out
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      try (CloseableHttpResponse httpResponse = httpClient.execute(httpPost)) {
        // Evaluate response
        int code = httpResponse.getStatusLine().getStatusCode();
        // Check errors in response:
        if (code / 100 != 2) {
          throw new CertificateVerificationException(
              "Error getting ocsp response. Response code is " + code + " to " + uri);
        }

        InputStream in = httpResponse.getEntity().getContent();
        return new OCSPResp(in);
      }
    } catch (IOException e) {
      throw new CertificateVerificationException(
          "Unable to execute request:\"" + serviceUrl + "\"\n" + e);
    }
  }

  private VerificationStatus getOCSPResponseDirect(
      X509Certificate peerCert, X509Certificate issuerCert)
      throws CertificateVerificationException {

    OCSPReq request = generateOCSPRequest(issuerCert, peerCert.getSerialNumber());

    // This list will sometimes have non ocsp urls as well.
    List<String> locations = null;
    try {
      locations = getAIALocations(peerCert);
    } catch (CertificateVerificationException e) {
      //Some kind of problem getting AIA Locations
      getLog().info("Problem finding AIA Locations\n" + e);
      return new VerificationStatus(VerificationStatus.BAD, new Date());
    }

    // Check each location
    for (String serviceUrl : locations) {

      OCSPResp ocspResponse = null;
      ocspResponse = getOCSPResponse(serviceUrl, request); // Possibly cached

      if (ocspResponse.getStatus() != OCSPResp.SUCCESSFUL) {
        continue; // Server didn't provide a response so try the next one
      }

      BasicOCSPResp basicResponse;
      try {
        basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
      } catch (OCSPException e) {
        throw new CertificateVerificationException("Unable to execute OCSP request:\n" + e);
      }

      SingleResp[] responses = (basicResponse == null) ? null : basicResponse.getResponses();
      if (responses != null && responses.length == 1) {
        VerificationStatus resp = new VerificationStatus(responses[0]);
        return resp;
      }
    }
    return null;
  }

  /**
   * Gets the revocation status of the given peer certificate. Uses the cache if it has been
   * configured
   *
   * @param peerCert The certificate we want to check if revoked.
   * @param issuerCert Needed to create OCSP request.
   * @return revocation status of the peer certificate.
   * @throws CertificateVerificationException
   * @throws ExecutionException
   */
  public VerificationStatus checkRevocationStatus(
      final X509Certificate peerCert,
      final X509Certificate issuerCert,
      final X509Certificate[] fullChain)
      throws CertificateVerificationException {

    VerificationStatus status;

    // check cache
    Cache<BigInteger, VerificationStatus> cache = getCache();
    if (config.useCache && (cache != null)) {
      try {
        status =
            cache.get(
                peerCert.getSerialNumber(),
                new Callable<VerificationStatus>() {
                  public VerificationStatus call() throws CertificateVerificationException {
                    return getOCSPResponseDirect(peerCert, issuerCert);
                  }
                });
      } catch (ExecutionException e) {
        throw new CertificateVerificationException(e);
      }
    } else {
      status = getOCSPResponseDirect(peerCert, issuerCert);
    }

    return status;
  }

  /**
   * Authority Information Access (AIA) is a non-critical extension in an X509 Certificate. This
   * contains the URL of the OCSP endpoint if one is available. TODO: This might contain non OCSP
   * urls as well. Handle this.
   *
   * @param cert is the certificate
   * @return a lit of URLs in AIA extension of the certificate which will hopefully contain an OCSP
   *     endpoint.
   * @throws CertificateVerificationException
   */
  private List<String> getAIALocations(X509Certificate cert)
      throws CertificateVerificationException {

    // Gets the DER-encoded OCTET string for the extension value for Authority
    // information access Points
    byte[] aiaExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
    if (aiaExtensionValue == null) {
      throw new CertificateVerificationException(
          "Certificate doesn't have authority information access points");
    }

    ASN1InputStream asn1In = null;
    try {
      asn1In = new ASN1InputStream(new ByteArrayInputStream(aiaExtensionValue));

      DEROctetString aiaDEROctetString;
      try {
        aiaDEROctetString = (DEROctetString) (asn1In.readObject());
      } catch (IOException e) {
        throw new CertificateVerificationException("Unable to read AIA extensions.\n" + e);
      }

      AuthorityInformationAccess authorityInformationAccess = null;

      try (ASN1InputStream asn1InOctets = new ASN1InputStream(aiaDEROctetString.getOctets())) {
        ASN1Sequence aiaASN1Sequence = (ASN1Sequence) asn1InOctets.readObject();
        authorityInformationAccess = AuthorityInformationAccess.getInstance(aiaASN1Sequence);
      } catch (IOException e) {
        throw new CertificateVerificationException("Unable to read AIA extensions.\n" + e);
      }

      List<String> ocspUrlList = new ArrayList<String>();
      AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
      for (AccessDescription accessDescription : accessDescriptions) {
        GeneralName gn = accessDescription.getAccessLocation();
        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
          ASN1String str = ASN1IA5String.getInstance(gn.getName());
          //DERIA5String str = DERIA5String.getInstance(gn.getName());
          String accessLocation = str.getString();
          ocspUrlList.add(accessLocation);
        }
      }
      if (ocspUrlList.isEmpty()) {
        throw new CertificateVerificationException("Cant get OCSP urls from certificate");
      }

      return ocspUrlList;
    } finally {
      if (asn1In != null) {
        try {
          asn1In.close();
        } catch (IOException e) {
        }
      }
    }
  }
}
