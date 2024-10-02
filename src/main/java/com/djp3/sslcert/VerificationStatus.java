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

package com.djp3.sslcert;

import java.io.Serializable;
import java.util.Date;

import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;

public class VerificationStatus implements Serializable {

  /** */
  private static final long serialVersionUID = 1333379539806083746L;

  public static final int GOOD = 0;
  public static final int BAD = 1;

  private Integer status = null;
  private Date verificationFailureDate =
      null; //The date after which the certificate becomes bad (if applicable)
  private Integer verificationReason = null;
  private Date nextUpdate = null;

  public VerificationStatus(SingleResp singleResp) throws CertificateVerificationException {
    setNextUpdate(singleResp.getNextUpdate());

    CertificateStatus certStatus = singleResp.getCertStatus();
    if (certStatus == null) {
      setStatus(GOOD);
    } else if (certStatus instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
      setStatus(BAD);
      RevokedStatus revokeStatus = (org.bouncycastle.cert.ocsp.RevokedStatus) certStatus;
      setRevokeDate(revokeStatus.getRevocationTime());
      if (revokeStatus.hasRevocationReason()) {
        setRevokeReason(revokeStatus.getRevocationReason());
      }
    } else {
      throw new CertificateVerificationException("Cant recognize Certificate Status");
    }
  }

  public VerificationStatus(int status, Date nextUpdate) {
    setStatus(status);
    setNextUpdate(nextUpdate);
  }

  public void setStatus(int status) {
    this.status = status;
  }

  public int getStatus() {
    return status;
  }

  public void setRevokeDate(Date revokeDate) {
    this.verificationFailureDate = revokeDate;
  }

  public Date getRevokeDate() {
    return verificationFailureDate;
  }

  public void setRevokeReason(Integer reason) {
    this.verificationReason = reason;
  }

  public Integer getRevokeReason() {
    return verificationReason;
  }

  public Date getNextUpdate() {
    return nextUpdate;
  }

  public void setNextUpdate(Date nextUpdate) {
    this.nextUpdate = nextUpdate;
  }
}
