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

package com.djp3.sslcert.ct;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A collection of CT logs that are trusted for the purposes of this test. Derived from
 * https://www.certificate-transparency.org/known-logs ->
 * https://www.gstatic.com/ct/log_list/log_list.json
 *
 * @author djp3
 */
public final class TrustedLogKeys {

  private static transient volatile Logger log = null;

  public static Logger getLog() {
    if (log == null) {
      log = LogManager.getLogger(TrustedLogKeys.class);
    }
    return log;
  }

  private static final String[] TRUSTED_LOG_KEYS = {
    //"description": "Google 'Argon2024' log",
    // "log_id": "7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA==",
    // "description": "Google 'Argon2025h1' log",
    // "log_id": "TnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIIKh+WdoqOTblJji4WiH5AltIDUzODyvFKrXCBjw/Rab0/98J4LUh7dOJEY7+66+yCNSICuqRAX+VPnV8R1Fmg==",
    // "description": "Google 'Argon2025h2' log",
    // "log_id": "EvFONL1TckyEBhnDjz96E/jntWKHiJxtMAWE6+WGJjo=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr+TzlCzfpie1/rJhgxnIITojqKk9VK+8MZoc08HjtsLzD8e5yjsdeWVhIiWCVk6Y6KomKTYeKGBv6xVu93zQug==",
    // "description": "Google 'Xenon2024' log",
    // "log_id": "dv+IPwq2+5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQ=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==",
    // "description": "Google 'Xenon2025h1' log",
    // "log_id": "zxFW7tUufK/zh1vZaS6b6RpxZ0qwF+ysAdJbd87MOwg=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEguLOkEA/gQ7f6uEgK14uMFRGgblY7a+9/zanngtfamuRpcGY4fLN6xcgcMoqEuZUeFDc/239HKe2Oh/5JqkbvQ==",
    // "description": "Google 'Xenon2025h2' log",
    // "log_id": "3dzKNJXX4RYF55Uy+sef+D0cUN/bADoUEnYKLKy7yCo=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa+Cv7QZ8Pe/ZDuRYSwTYKkeZkIl6uTaldcgEuMviqiu1aJ2IKaKlz84rmhWboD6dlByyt0ryUexA7WJHpANJhg==",
    // "description": "Cloudflare 'Nimbus2024' Log",
    // "log_id": "2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7Gbe4/mizX+OpIpLayKjVGKJfyTttegiyk3cR0zyswz6ii5H+Ksw6ld3Ze+9p6UJd02gdHrXSnDK0TxW8oVSA==",
    // "description": "Cloudflare 'Nimbus2025'",
    // "log_id": "zPsPaoVxCWX+lZtTzumyfCLphVwNl422qX5UwP5MDbA=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGoAaFRkZI3m0+qB5jo3VwdzCtZaSfpTgw34UfAoNLUaonRuxQWUMX5jEWhd5gVtKFEHsr6ldDqsSGXHNQ++7lw==",
    // "description": "DigiCert Yeti2024 Log",
    // "log_id": "SLDja9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHM=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV7jBbzCkfy7k8NDZYGITleN6405Tw7O4c4XBGA0jDliE0njvm7MeLBrewY+BGxlEWLcAd2AgGnLYgt6unrHGSw==",
    // "description": "DigiCert Yeti2025 Log",
    // "log_id": "fVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebg=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE35UAXhDBAfc34xB00f+yypDtMplfDDn+odETEazRs3OTIMITPEy1elKGhj3jlSR82JGYSDvw8N8h8bCBWlklQw==",
    // "description": "DigiCert Nessie2024 Log",
    // "log_id": "c9meiRtMlnigIH1HneayxhzQUV5xGSqMa4AQesF3crU=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELfyieza/VpHp/j/oPfzDp+BhUuos6QWjnycXgQVwa4FhRIr4OxCAQu0DLwBQIfxBVISjVNUusnoWSyofK2YEKw==",
    // "description": "DigiCert Nessie2025 Log",
    // "log_id": "5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlA=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vDwp4uBLgk5O59C2jhEX7TM7Ta72EN/FklXhwR/pQE09+hoP7d4H2BmLWeadYC3U6eF1byrRwZV27XfiKFvOA==",
    // "description": "DigiCert 'Wyvern2024h1' Log",
    // "log_id": "tp3cvDwave9vn9YMiLEGe3fwgmiLLXhl0Es5q+knpXU=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaKZ5FNFY56uqKWl/YO1o6BD2B4TA+1kEWgnJHeFL+83cA/OoKka5hE1pMOwjNcGO/J+0ICTXFayH9x7BCzx2Gg==",
    // "description": "DigiCert 'Wyvern2024h2' Log",
    // "log_id": "DCrvLEpbmIPU3aOC/lD7UYiz6XMzoexToJ3Jp50NCCA=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHMSnFTQen3FtRcrcVKJBJC7QvGd+BzeTM+CPL03G3RMPMejE4cBURMU2qISmITOHL7PT3rvFfrQ7u3tB61xbQ==",
    // "description": "DigiCert 'Wyvern2025h1' Log",
    // "log_id": "cyAiDwgWivnzxKaLCrJqmkoA7vV3hYoITQUA1KVCRFk=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp8uAYYYbH7WrKyB2WYNmDs6uuG87iALrQ/SHkMuL2qwOGVDg+SQOqyaTjD+eDZZYRJ07ioDFyL7hiUZrSEzWCQ==",
    // "description": "DigiCert 'Wyvern2025h2' Log",
    // "log_id": "7TxL1ugGwqSiAFfbyyTiOAHfUS/txIbFcA8g3bc+P+A=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4NtB7+QEvctrLkzM8WzeQVh//pT2evZg7Yt2cqOiHDETMjWh8gjSaMU0p1YIHGPeleKBaZeNHqi3ZlEldU14Lg==",
    // "description": "DigiCert 'Sphinx2024h1' Log",
    // "log_id": "2wds3mqLeOxY1gVklutqJqjFnnISk+isAyfd3onbWio=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExuQpaZj+KJJXEk2e7Q7nMqLmnCd4pCl8mdXb+iLB3V6n9NjqyNdEjeDxjAoBHdgiqNPrySKONvtKsXCcXcHoMw==",
    // "description": "DigiCert 'Sphinx2024h2' Log",
    // "log_id": "3Mleb6KZubD9vWymo24dcsQhL90eD0dVOjbWzxrRHY0=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2wlBhOfR8VslCXvoxphRXimF/YHeidfQhqSw5RXsXXsXVV/JeY3kIjbn6b84P9Hp1AmEgb62we0bF+oml7rpmg==",
    // "description": "DigiCert 'Sphinx2025h1' Log",
    // "log_id": "3oWB11AkfGvNy69WN8XngcZM5G7WF2OfjzSnJsnivTc=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4y8fTYkFdSl4uyI9B2JRFHCU5zzq9e6upkiahlJOnlzjlZcou1JLKv3IyYlORTEX043y584YEViYLGBvWCA2bg==",
    // "description": "DigiCert 'Sphinx2025h2' Log",
    // "log_id": "pELFBklgYVSPD9TqnPt6LSZFTYepfy/fRVn2J086hFQ=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQYxQE1SxGQW3f0ogbqN1Y8o09Mx06jI7tosDFKhSfzKHXlmeD6sYnilstXJ3GidUhV3BeySoNOPNiM7UUBu+aQ==",
    // "description": "Sectigo 'Sabre' CT log",
    // "log_id": "VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
    // "description": "Sectigo 'Sabre2024h1'",
    // "log_id": "ouK/1h7eLy8HoNZObTen3GVDsMa1LqLat4r4mm31F9g=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELAH2zjG8qhRhUf5reoeuptObx4ctClrIT7VU3MmToADuyhy5p7Z7RzvlT6psFhxwLsjsU1pMIUx+JwsTFF78hQ==",
    // "description": "Sectigo 'Sabre2024h2'",
    // "log_id": "GZgQcQnw1lIuMIDSnj9ku4NuKMz5D1KO7t/OSj8WtMo=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEehBMiucie20quo76a0qB1YWuA+//S/xNUz23jLt1CcnqFn7BdxbSwkV0bY3E4Yg339TzYGX8oHXwIGaOSswZ2g==",
    // "description": "Sectigo 'Sabre2025h1'",
    // "log_id": "4JKz/AwdyOdoNh/eYbmWTQpSeBmKctZyxLBNpW1vVAQ=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfi858egjjrMyBK9NV/bbxXSkem07B1EMWvuAMAXGWgzEdtYGqFdN+9/kgpDCQa5wszGi4/o9XyxdBM20nVWrQQ==",
    // "description": "Sectigo 'Sabre2025h2'",
    // "log_id": "GgT/SdBUHUCv9qDDv/HYxGcvTuzuI0BomGsXQC7ciX0=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhRMRLXvzk4HkuXzZZDvntYOZZnlZR2pCXta9Yy63kUuuvFbExW4JoNdkGsjBr4mL9VjYuut7g1Lp9OClzc2SzA==",
    // "description": "Sectigo 'Mammoth2024h1'",
    // "log_id": "KdA6G7Z0qnEc0wNbZVfBT4qni0/oOJRJ7KRT+US9JGg=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpFmQ83EkJPfDVSdWnKNZHve3n86rThlmTdCK+p1ipCTwOyDkHRRnyPzkN/JLOFRaz59rB5DQDn49TIey6D8HzA==",
    // "description": "Sectigo 'Mammoth2024h1b'",
    // "log_id": "UIUBWNy2BZXADpKoEQLszf4/a3hYQp9XmDU4ydpSUGM=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo9UHKHoENK7KvoB5Tz72QfQkBOHWNloaCfLRuoQXrh6hfAAdVHOQdSGo0dpeEOGM7LKKjMjn3c3iB/BOFgJXNw==",
    // "description": "Sectigo 'Mammoth2024h2'",
    // "log_id": "3+FW66oFr7WcD4ZxjajAMk6uVtlup/WlagHRwTu+Ulw=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhWYiJG6+UmIKoK/DJRo2LqdgiaJlv6RfvYVqlAWBNZBUMZXnEZ6jLg+F76eIV4tjGoHBQZ197AE627nBJ/RlHg==",
    // "description": "Sectigo 'Mammoth2025h1'",
    // "log_id": "E0rfGrWYQgl4DG/vTHqRpBa3I0nOWFdq367ap8Kr4CI=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEzxBtTB9LkqhqGvSxVdrmP5+79Uh4rpdsLqFEW6U4D2ojm1WjUQCnrCDzFTfm05yYks8DDLdhvvrPmbNd1hb5Q==",
    // "description": "Sectigo 'Mammoth2025h2'",
    // "log_id": "rxgaKNaMo+CpikycZ6sJ+Lu8IrquvLE4o6Gd0/m2Aw0=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiOLHs9c3o5HXs8XaB1EEK4HtwkQ7daDmZeFKuhuxnKkqhDEprh2L8TOfEi6QsRVnZqB8C1tif2yaajCbaAIWbw==",
    // "description": "Let's Encrypt 'Oak2024H1' log",
    // "log_id": "O1N3dT4tuYBOizBbBv5AO2fYT8P0x70ADS1yb+H61Bc=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVkPXfnvUcre6qVG9NpO36bWSD+pet0Wjkv3JpTyArBog7yUvuOEg96g6LgeN5uuk4n0kY59Gv5RzUo2Wrqkm/Q==",
    // "description": "Let's Encrypt 'Oak2024H2' log",
    // "log_id": "PxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE13PWU0fp88nVfBbC1o9wZfryUTapE4Av7fmU01qL6E8zz8PTidRfWmaJuiAfccvKu5+f81wtHqOBWa+Ss20waA==",
    // "description": "Let's Encrypt 'Oak2025h1'",
    // "log_id": "ouMK5EXvva2bfjjtR2d3U9eCW4SU1yteGyzEuVCkR+c=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKeBpU9ejnCaIZeX39EsdF5vDvf8ELTHdLPxikl4y4EiROIQfS4ercpnMHfh8+TxYVFs3ELGr2IP7hPGVPy4vHA==",
    // "description": "Let's Encrypt 'Oak2025h2'",
    // "log_id": "DeHyMCvTDcFAYhIJ6lUu/Ed0fLHX6TDvDkIetH5OqjQ=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtXYwB63GyNLkS9L1vqKNnP10+jrW+lldthxg090fY4eG40Xg1RvANWqrJ5GVydc9u8H3cYZp9LNfkAmqrr2NqQ==",
    // "description": "Trust Asia Log2024-2",
    // "log_id": "h0+1DcAp2ZMd5XPp8omejkUzs5LTiwpGJXS/D+6y/B4=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp2TieYE/YdfsxvhlKB2gtGYzwyXVCpV4nI/+pCrYj35y4P6of/ixLYXAjhJ0DS+Mq9d/eh7ZhDM56P2JX5ZICA==",
    // "description": "TrustAsia Log2025a",
    // "log_id": "KOKBOP2DIUXpqdaqdTdtg3eohRKzwH9yQUgh3L3pjGY=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOWxpAl5K534o6DfGO+VXQNse6GRqbiAfexcAgjibi98MnC9loRfpmLpZbV8kFi6ItX59WlUt6iUTjIJriYRTQ==",
    // "description": "TrustAsia Log2025b",
    // "log_id": "KCyL3YEP+QkSCs4W1uDsIBvqgqOkrxnZ7/tZ6D/cQmg=",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqqCL22cUXZeJHQiNBtfBlI6w+kxG1VMIeCsEU2zz3rHRU0DakFfmGp48xwO4vS+pz+h7XuFLYOU4Q2CXwVsvZQ==",
  };

  public static String[] getTrustedLogKeys() {
    if (System.currentTimeMillis() > 1735707600000L) {
      getLog().warn("You might need to consider updating this list of logs");
    }
    return TRUSTED_LOG_KEYS;
  }
}
