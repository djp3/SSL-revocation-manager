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

import java.security.cert.CertificateException;

public class CertificateVerificationException extends CertificateException {
  /** */
  private static final long serialVersionUID = -8725765076032198731L;

  public CertificateVerificationException(String message) {
    super(message);
  }

  public CertificateVerificationException(Throwable throwable) {
    super(throwable);
  }

  public CertificateVerificationException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
