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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

import net.djp3.sslcert.CertificateVerificationException;

public class X509CRLWrapper implements Serializable {

  /** */
  private static final long serialVersionUID = 6399203416305063378L;

  private X509CRL data;

  public X509CRLWrapper(X509CRL data) {
    this.data = data;
  }

  public X509CRL getX509CRL() {
    return this.data;
  }

  private void readObject(ObjectInputStream objectinputStream)
      throws ClassNotFoundException, IOException {
    try {
      //Read in DER format
      byte[] incoming = (byte[]) objectinputStream.readObject();
      //Wrap in an Input Stream
      InputStream targetStream = new ByteArrayInputStream(incoming);
      this.data = CRLVerifier.extractX509CRLFromStream(targetStream);
    } catch (ClassCastException e) {
      System.out.println("classcastexception");
    } catch (CertificateVerificationException e) {
      throw new IOException(e);
    }
  }

  private void writeObject(ObjectOutputStream outputStream) throws IOException {
    try {
      //Convert to DER format
      byte[] encoded = data.getEncoded();
      outputStream.writeObject(encoded);
    } catch (CRLException e) {
      throw new IOException(e);
    } finally {
      outputStream.flush();
    }
  }
}
