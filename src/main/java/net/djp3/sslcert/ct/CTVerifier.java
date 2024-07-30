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

package net.djp3.sslcert.ct;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;
import org.certificatetransparency.ctlog.CertificateInfo;
import org.certificatetransparency.ctlog.LogInfo;
import org.certificatetransparency.ctlog.LogSignatureVerifier;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.utils.VerifySignature;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheStats;

import net.djp3.sslcert.CertificateVerificationException;
import net.djp3.sslcert.VerificationStatus;
import net.djp3.sslcert.Verifier;

/**
 * This is used to check if an SSL connection has a known good server side certificate that can be
 * verified. If it is it is an accepted connection, otherwise it is rejected.
 *
 * <p>Currently this class just checks for the presence of properly signed CT log promises embedded
 * in the SSL certificate. It does not request the proof from the CT authority that it was
 * incorporated into the transparency log. Hopefully someone will volunteer to add that capacity in
 * the future.
 *
 * <p>There are three ways that certificate transparency information can be exchanged in the
 * connection handshake:
 *
 * <ul>
 *   <li>X509v3 certificate extension
 *   <li>TLS extension
 *   <li>OSCP stapling
 * </ul>
 *
 * This only validates using the first approach. Reference this base code:
 * https://github.com/google/certificate-transparency-java and this pull request on it
 * https://github.com/google/certificate-transparency-java/pull/28
 */
public class CTVerifier extends Verifier<BigInteger, VerificationStatus> {

  private static transient volatile Logger log = null;

  public static Logger getLog() {
    if (log == null) {
      log = LogManager.getLogger(CTVerifier.class);
    }
    return log;
  }

  /** Number of different CT logs needed verify the certificate to achieve acceptable status */
  private final int MIN_VALID_SCTS = 2;

  /** A CT log's Id is created by using this hash algorithm on the CT log public key */
  private static final String LOG_ID_HASH_ALGORITHM = "SHA-256";

  private Map<String, LogSignatureVerifier> verifiers = new HashMap<String, LogSignatureVerifier>();

  public CTVerifier(Configuration config)
      throws FileNotFoundException, ClassNotFoundException, IOException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    super(config);
    buildLogSignatureVerifiers();
  }

  /** Parses a key and determines the key algorithm (RSA or EC) based on the ASN1 OID. */
  private static String determineKeyAlgorithm(byte[] keyBytes) {
    ASN1Sequence asn1Seq = ASN1Sequence.getInstance(keyBytes);
    DLSequence dlSeq = (DLSequence) asn1Seq.getObjects().nextElement();
    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) dlSeq.getObjects().nextElement();
    ASN1Primitive x = PKCSObjectIdentifiers.rsaEncryption.toASN1Primitive();

    if (oid.equals(x)) {
      return "RSA";
    } else if (oid.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
      return "EC";
    } else {
      throw new IllegalArgumentException("Unsupported key type " + oid);
    }
  }

  /**
   * Construct LogSignatureVerifiers for each of the trusted CT logs.
   *
   * @throws InvalidKeySpecException the CT log key isn't RSA or EC, the key is probably corrupt.
   * @throws NoSuchAlgorithmException the crypto provider couldn't supply the hashing algorithm or
   *     the key algorithm. This probably means you are using an ancient or bad crypto provider.
   */
  private void buildLogSignatureVerifiers()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    MessageDigest hasher = MessageDigest.getInstance(LOG_ID_HASH_ALGORITHM);
    for (String trustedLogKey : TrustedLogKeys.getTrustedLogKeys()) {
      hasher.reset();
      byte[] keyBytes = Base64.decode(trustedLogKey);
      String logId = Base64.toBase64String(hasher.digest(keyBytes));
      KeyFactory keyFactory = KeyFactory.getInstance(determineKeyAlgorithm(keyBytes));
      PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
      verifiers.put(logId, new LogSignatureVerifier(new LogInfo(publicKey)));
    }
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
					info.append("\nRunning validity check on CT Cache");
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

  private VerificationStatus getCTValidationDirect(
      X509Certificate certificate, X509Certificate[] chain)
      throws CertificateVerificationException {

    if (!CertificateInfo.hasEmbeddedSCT(certificate)) {
      getLog().info("  This certificate does not have any Signed Certificate Timestamps in it.");
      return new VerificationStatus(VerificationStatus.BAD, certificate.getNotAfter());
    }

    try {
      List<Ct.SignedCertificateTimestamp> sctsInCertificate =
          VerifySignature.parseSCTsFromCert(certificate);
      if (sctsInCertificate.size() < MIN_VALID_SCTS) {
        getLog()
            .info(
                "Too few SCTs are present, I want at least "
                    + MIN_VALID_SCTS
                    + " CT logs to vouch for this certificate.");
        return new VerificationStatus(VerificationStatus.BAD, certificate.getNotAfter());
      }

      List<Certificate> certificateList = Arrays.asList(chain);

      int validSctCount = 0;
      for (Ct.SignedCertificateTimestamp sct : sctsInCertificate) {
        String logId = Base64.toBase64String(sct.getId().getKeyId().toByteArray());
        if (verifiers.containsKey(logId)) {
          getLog().debug("SCT trusted log " + logId);
          if (verifiers.get(logId).verifySignature(sct, certificateList)) {
            ++validSctCount;
            /** TODO: validate proof with the log authority * */
          }
        } else {
          getLog().info("SCT untrusted log " + logId);
        }
      }

      if (validSctCount < MIN_VALID_SCTS) {
        getLog()
            .info(
                "Too few SCTs are present, I want at least "
                    + MIN_VALID_SCTS
                    + " CT logs to vouch for this certificate. Only saw "
                    + validSctCount);
        return new VerificationStatus(VerificationStatus.BAD, certificate.getNotAfter());
      } else {
        return new VerificationStatus(VerificationStatus.GOOD, certificate.getNotAfter());
      }
    } catch (IOException e) {
      /* Could not parse the embedded information in the certificate */
      getLog().warn(e.getLocalizedMessage());
      return new VerificationStatus(VerificationStatus.BAD, certificate.getNotAfter());
    }
  }

  /**
   * Gets the revocation status of the given peer certificate. Uses the cache if it has been
   * configured
   *
   * @param peerCert The certificate we want to check if revoked.
   * @return revocation status of the peer certificate.
   * @throws CertificateVerificationException
   */
  public VerificationStatus checkRevocationStatus(
      final X509Certificate peerCert, X509Certificate[] fullChain)
      throws CertificateVerificationException {
    return checkRevocationStatus(peerCert, null, fullChain);
  }

  /**
   * Gets the revocation status of the given peer certificate. Uses the cache if it has been
   * configured
   *
   * @param peerCert The certificate we want to check if revoked.
   * @param issuerCert Not needed for a Certificate Transparency check
   * @return revocation status of the peer certificate.
   * @throws CertificateVerificationException
   */
  @Override
  public VerificationStatus checkRevocationStatus(
      final X509Certificate peerCert, final X509Certificate issuerCert, X509Certificate[] fullchain)
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
                    getLog().debug("Cache miss ");
                    return getCTValidationDirect(peerCert, fullchain);
                  }
                });
      } catch (ExecutionException e) {
        throw new CertificateVerificationException(e);
      }
    } else {
      status = getCTValidationDirect(peerCert, fullchain);
    }

    return status;
  }
}
