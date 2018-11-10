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

package net.djp3.sslcert;

import java.io.Serializable;
import java.util.Date;

import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;

public class RevocationStatus implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 6110748765739524230L;
	
	public static final int GOOD = 0;
	public static final int UNKNOWN = 1;
	public static final int REVOKED = 2;
	
	private int status = UNKNOWN;
	private Date revokeDate = null;
	private Integer revokeReason = null;
	private Date nextUpdate = null;
	
  
    public RevocationStatus(SingleResp singleResp) throws CertificateVerificationException {
    	setNextUpdate(singleResp.getNextUpdate());
    	
    	CertificateStatus certStatus = singleResp.getCertStatus();
   		if (certStatus == null) {
   			setStatus(GOOD);
   		} else if (certStatus instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
   			setStatus(REVOKED);
   			RevokedStatus revokeStatus = (org.bouncycastle.cert.ocsp.RevokedStatus) certStatus;
   			setRevokeDate(revokeStatus.getRevocationTime());
   			if(revokeStatus.hasRevocationReason()) {
   				setRevokeReason(revokeStatus.getRevocationReason());
   			}
   		} else if (certStatus instanceof org.bouncycastle.cert.ocsp.UnknownStatus) {
   			setStatus(UNKNOWN);
   		}
   		else {
    		throw new CertificateVerificationException("Cant recognize Certificate Status");
    	}
	}

	public RevocationStatus(int status) {
    	setStatus(status);
    }
    

	public void setStatus(int status) {
        this.status = status;
    }
    
    public int getStatus() {
    	return status;
    }
    
    public void setRevokeDate(Date revokeDate) {
    	this.revokeDate = revokeDate; 
    }
    
    public Date getRevokeDate() {
    	return revokeDate;
    }
    
    public void setRevokeReason(Integer reason) {
    	this.revokeReason = reason; 
    }
    
    public Integer getRevokeReason() {
    	return revokeReason;
    }
    
    public Date getNextUpdate() {
  		return nextUpdate;
  	}

  	public void setNextUpdate(Date nextUpdate) {
  		this.nextUpdate = nextUpdate;
  	}
}

