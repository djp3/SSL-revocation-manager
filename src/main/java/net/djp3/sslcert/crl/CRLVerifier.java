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

package net.djp3.sslcert.crl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidParameterException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheStats;

import net.djp3.sslcert.CertificateVerificationException;
import net.djp3.sslcert.VerificationStatus;
import net.djp3.sslcert.Verifier;

/**
 * This is used to check if an SSL Certificate is revoked or not by using the Certificate Revocation
 * List (CRL) published by the CA.
 */
public class CRLVerifier extends Verifier<String, X509CRLWrapper> {

  private static transient volatile Logger log = null;

  public static Logger getLog() {
    if (log == null) {
      log = LogManager.getLogger(CRLVerifier.class);
    }
    return log;
  }

  static CertificateFactory cf = null;

  public static X509CRL extractX509CRLFromStream(InputStream crlStream)
      throws CertificateVerificationException {
    try {
      if (cf == null) {
        cf = CertificateFactory.getInstance("X.509");
      }
      return (X509CRL) cf.generateCRL(crlStream);
    } catch (CertificateException e) {
      throw new CertificateVerificationException(e);
    } catch (CRLException e) {
      throw new CertificateVerificationException(
          "Cannot generate X509CRL from the stream data" + e);
    }
  }

  public CRLVerifier(Configuration config)
      throws FileNotFoundException, ClassNotFoundException, IOException {
    super(config);
  }

  /**
   * This is run periodically by the cache to clean out any cache entries that have expired: Not
   * according to cache semantics but by virtue of the information associated with the revocation
   * data.
   */
  protected Runnable getValidityCheckerCode() {
    return new Runnable() {
      @Override
      public void run() {
        Cache<String, X509CRLWrapper> cache = getCache();
        if (config.useCache && (cache != null)) {
          getLog().debug("Running validity check on CRL Cache");
          CacheStats stats = cache.stats();
          getLog()
              .debug(
                  "OCSP Cache stats:\n"
                      + "\tAverage Load Penalty: "
                      + stats.averageLoadPenalty()
                      + "\n"
                      + "\t            Hit Rate: "
                      + stats.hitRate()
                      + "\n"
                      + "\tLoad Exception Count: "
                      + stats.loadExceptionCount()
                      + "\n"
                      + "\t       Request Count: "
                      + stats.requestCount());
          Date now = new Date();
          for (Entry<String, X509CRLWrapper> x : cache.asMap().entrySet()) {
            X509CRL resp = x.getValue().getX509CRL();
            if (resp == null) {
              cache.invalidate(x.getKey());
            } else {
              Date nextUpdate = resp.getNextUpdate();
              if ((nextUpdate == null) || (nextUpdate.before(now))) {
                cache.invalidate(x.getKey());
              }
            }
          }
        }
      }
    };
  }

  /**
   * Checks revocation status (Good, Revoked) of the peer certificate.
   *
   * @param peerCert peer certificate
   * @param issuerCert issuer certificate of the peer. not used currently.
   * @return revocation status of the peer certificate.
   * @throws CertificateVerificationException
   */
  public VerificationStatus checkRevocationStatus(
      final X509Certificate peerCert,
      final X509Certificate issuerCert,
      final X509Certificate[] fullChain)
      throws CertificateVerificationException {

    List<String> list = getCrlDistributionPoints(peerCert);
    //check with distributions points in the list one by one. if one fails go to the other.
    for (String crlUrl : list) {
      getLog().debug("Trying to get CRL for URL: " + crlUrl);

      //TODO: Do we need to check if URL has the same domain name as issuerCert?
      X509CRLWrapper x509CRLWrapper = null;
      try {
        Cache<String, X509CRLWrapper> cache = getCache();
        if (config.useCache && (cache != null)) {
          x509CRLWrapper =
              cache.get(
                  crlUrl,
                  new Callable<X509CRLWrapper>() {
                    public X509CRLWrapper call()
                        throws IOException, CertificateVerificationException {
                      return downloadCRLFromWeb(crlUrl);
                    }
                  });
        } else {
          x509CRLWrapper = downloadCRLFromWeb(crlUrl);
        }
      } catch (IOException | ExecutionException e) {
        getLog()
            .debug(
                "Either the url is bad or cannot build X509CRL. Check with the next url in the list.",
                e);
      }
      if (x509CRLWrapper.getX509CRL() != null) {
        return getRevocationStatus(x509CRLWrapper.getX509CRL(), peerCert, fullChain);
      }
    }
    //If there is no CRL then it is not revoked by CRL
    return new VerificationStatus(VerificationStatus.GOOD, peerCert.getNotAfter());
  }

  private VerificationStatus getRevocationStatus(
      X509CRL x509CRL, X509Certificate peerCert, X509Certificate[] fullChain) {
    if (x509CRL == null) {
      throw new InvalidParameterException("Can't check revocation status of null");
    }

    if (peerCert == null) {
      throw new InvalidParameterException("Can't check revocation status of null");
    }

    if (x509CRL.isRevoked(peerCert)) {
      VerificationStatus ret =
          new VerificationStatus(VerificationStatus.BAD, peerCert.getNotAfter());
      ret.setRevokeDate(x509CRL.getRevokedCertificate(peerCert).getRevocationDate());
      return ret;
    } else {
      return new VerificationStatus(VerificationStatus.GOOD, peerCert.getNotAfter());
    }
  }

  /** Downloads CRL from the crlUrl. Does not support HTTPS */
  protected X509CRLWrapper downloadCRLFromWeb(String crlURL)
      throws IOException, CertificateVerificationException {
    InputStream crlStream = null;
    try {
      URL url = new URL(crlURL);
      crlStream = url.openStream();
      return new X509CRLWrapper(extractX509CRLFromStream(crlStream));
    } catch (MalformedURLException e) {
      throw new CertificateVerificationException("CRL Url is malformed", e);
    } catch (IOException e) {
      throw new CertificateVerificationException(
          "Cant reach URI: " + crlURL + " - only support HTTP", e);
    } finally {
      if (crlStream != null) crlStream.close();
    }
  }

  /**
   * Extracts all CRL distribution point URLs from the "CRL Distribution Point" extension in a X.509
   * certificate. If CRL distribution point extension is unavailable, returns an empty list.
   */
  private List<String> getCrlDistributionPoints(X509Certificate cert)
      throws CertificateVerificationException {

    List<String> crlUrls = new ArrayList<String>();
    //Gets the DER-encoded OCTET string for the extension value for CRLDistributionPoints
    byte[] crlDPExtensionValue = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
    if (crlDPExtensionValue == null) {
      return crlUrls;
      //throw new CertificateVerificationException("Certificate doesn't have CRL distribution points");
    }
    //crlDPExtensionValue is encoded in ASN.1 format.
    ASN1InputStream asn1In = null;
    try {
      //crlDPExtensionValue is encoded in ASN.1 format.
      asn1In = new ASN1InputStream(crlDPExtensionValue);
      // DER (Distinguished Encoding Rules) is one of ASN.1 encoding rules defined in ITU-T X.690,
      // 2002, specification. ASN.1 encoding rules can be used to encode any data object into a
      // binary file.
      CRLDistPoint distPoint;
      ASN1InputStream asn1InOctets = null;
      try {
        DEROctetString crlDEROctetString = (DEROctetString) asn1In.readObject();
        //Get Input stream in octets
        asn1InOctets = new ASN1InputStream(crlDEROctetString.getOctets());
        ASN1Primitive asn1Primitive = asn1InOctets.readObject();
        distPoint = CRLDistPoint.getInstance(asn1Primitive);
      } catch (IOException e) {
        throw new CertificateVerificationException("Cannot read certificate to get CRL urls", e);
      } finally {
        if (asn1InOctets != null) {
          try {
            asn1InOctets.close();
          } catch (IOException e) {
          }
        }
      }

      //Loop through ASN1Encodable DistributionPoints
      for (DistributionPoint dp : distPoint.getDistributionPoints()) {
        //get ASN1Encodable DistributionPointName
        DistributionPointName dpn = dp.getDistributionPoint();
        if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
          //Create ASN1Encodable General Names
          GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
          // Look for a URI
          for (GeneralName genName : genNames) {
            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
              //DERIA5String contains an ascii string.
              //A IA5String is a restricted character string type in the ASN.1 notation
              String url = DERIA5String.getInstance(genName.getName()).getString().trim();
              crlUrls.add(url);
            }
          }
        }
      }
      if (crlUrls.isEmpty()) {
        throw new CertificateVerificationException("Cant get CRL urls from certificate");
      }
      return crlUrls;
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
