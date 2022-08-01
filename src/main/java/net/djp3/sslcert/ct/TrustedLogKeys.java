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
    //"Google 'Argon2022' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeIPc6fGmuBg6AJkv/z7NFckmHvf/OqmjchZJ6wm2qN200keRDg352dWpi7CHnSV51BpQYAj1CQY5JuRAwrrDwg==",
    //"Google 'Argon2023' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA==",
    //"Google 'Xenon2022' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+WS9FSxAYlCVEzg8xyGwOrmPonoV14nWjjETAIdZvLvukPzIWBMKv6tDNlQjpIHNrUcUt1igRPpqoKDXw2MeKw==",
    //"Google 'Xenon2023' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEchY+C+/vzj5g3ZXLY3q5qY1Kb2zcYYCmRV4vg6yU84WI0KV00HuO/8XuQqLwLZPjwtCymeLhQunSxgAnaXSuzg==",
    //"Google 'Icarus' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==",
    //"Google 'Pilot' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==",
    //"Google 'Rocketeer' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
    //"Google 'Skydiver' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==",
    //"Google 'Submariner' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOfifIGLUV1Voou9JLfA5LZreRLSUMOCeeic8q3Dw0fpRkGMWV0Gtq20fgHQweQJeLVmEByQj9p81uIW4QkWkTw==",
    //"Google 'Daedalus' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbgwcuu4rakGFYB17fqsILPwMCqUIsz7VcCTRbR0ttrfzizbcI02VYxK75IaNzOnR7qFAot8LowYKMMqNrKQpVg==",
    //"Google 'Testtube' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8i8S7qiGEs9NXv0ZJFh6uuOmR2Q7dPprzk9XNNGkUXjzqx2SDvRfiwKYwBljfWujozHESVPQyydGaHhkaSz/g==",
    //"Google 'Crucible' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKATl2B3SAbxyzGOfNRB+AytNTGvdF/FFY6HzWb+/HPE4lJ37vx2nEm99KYUy9SoNzF5VyTwCQG5nL/c5Q77yQQ==",
    //"Google 'Solera2018' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEuFqn5cy1nACARlWIUjeJaRDKl0mcf9gvFZXpPhHsyykizXvULF5GZNGfucWIyUccBRfmYJZTTrXqw0mVts7hA==",
    //"Google 'Solera2019' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJUwGinXUWVNaBiK2Vl/rdyMkxKaWJHR8dj9yD5AlZEtEbfvAMQQ8o7DQyXVm7TX+eAA9wL2Vtt6DpoMEL0q/rw==",
    //"Google 'Solera2020' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiKfWtuoWCPMEzSKySjMjXpo38WOdZr6Yq0WYa2JQOv1uVMxkqHywf9Gz1kGeRLq/Rz3tVVvXgqb4jQ1UqKVKnw==",
    //"Google 'Solera2021' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1glwxqXsw2VqlAbHSeWbTthMGNIuACVn8Jj/jrnY2iN2uVUrEEwLj5VUCb+WF2XY44+mfUVYY7R/d8TIZ4olnw==",
    //"Google 'Solera2022' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFWj6UQDxzHWmgzQtQQ7REDC0nxnU9mpOmA0lv5trA0t7IRzSkh4DOznPe+nkxmaC8iS1capCtKjyYhUNRrvWqA==",
    //"Google 'Solera2023' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK9Y56IP6DGQy2d9moYGJChZPoktXoYwaG0MBN/4X5MSFmBaYJfNm3mCwzLVefkjh2wz8Q6q2S75hS/OeHGiZUg==",
    //"Cloudflare 'Nimbus2022' Log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESLJHTlAycmJKDQxIv60pZG8g33lSYxYpCi5gteI6HLevWbFVCdtZx+m9b+0LrwWWl/87mkNN6xE0M4rnrIPA/w==",
    //"Cloudflare 'Nimbus2023' Log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/8tkhjLRp0SXrlZdTzNkTd6HqmcmXiDJz3fAdWLgOhjmv4mohvRhwXul9bgW0ODgRwC9UGAgH/vpGHPvIS1qA==",
    //"DigiCert Yeti2023 Log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfQ0DsdWYitzwFTvG3F4Nbj8Nv5XIVYzQpkyWsU4nuSYlmcwrAp6m092fsdXEw6w1BAeHlzaqrSgNfyvZaJ9y0Q==",
    //"DigiCert Nessie2022 Log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJyTdaAMoy/5jvg4RR019F2ihEV1McclBKMe2okuX7MCv/C87v+nxsfz1Af+p+0lADGMkmNd5LqZVqxbGvlHYcQ==",
    //"DigiCert Nessie2023 Log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEXu8iQwSCRSf2CbITGpUpBtFVt8+I0IU0d1C36Lfe1+fbwdaI0Z5FktfM2fBoI1bXBd18k2ggKGYGgdZBgLKTg==",
    //"DigiCert Yeti2022-2 Log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHWlePwrycXfNnV3DNEkA7mB34XJ2dKh8XH0J8jIdBX4u/lsx1Tr9czRuSRROUFiWWsTH9L4FZKT31+WxbTMMww==",
    //"Symantec Deneb",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEloIeo806gIQel7i3BxmudhoO+FV2nRIzTpGI5NBIUFzBn2py1gH1FNbQOG7hMrxnDTfouiIQ0XKGeSiW+RcemA==",
    //"Sectigo 'Sabre' CT log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
    //"Sectigo 'Mammoth' CT log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==",
    //"Sectigo 'Dodo' CT log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPXCMfVjQ2oWSgrewu4fIW4Sfh3lco90CwKZ061pvAI1eflh6c8ACE90pKM0muBDHCN+j0HV7scco4KKQPqq4A==",
    //"Let's Encrypt 'Oak2022' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhjyxDVIjWt5u9sB/o2S8rcGJ2pdZTGA8+IpXhI/tvKBjElGE5r3de4yAfeOPhqTqqc+o7vPgXnDgu/a9/B+RLg==",
    //"Let's Encrypt 'Oak2023' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsz0OeL7jrVxEXJu+o4QWQYLKyokXHiPOOKVUL3/TNFFquVzDSer7kZ3gijxzBp98ZTgRgMSaWgCmZ8OD74mFUQ==",
    //"Let's Encrypt 'Testflume2019' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAg3+vFOesFW51rKECekioAt9Zo50atRoOJ0qLxF7DIEHsHneXLEpgO1WMreleRy1vEbUJD7TXoH9r8qSDGvyew==",
    //"Let's Encrypt 'Testflume2020' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjdjcoKpeBShHgHvRm3BxD5+l+eHZudv3KmD5SDcLcI01Vj5TDTmxanQKCgpvm9pfnfB6URMQV3hhU1I02jRoRw==",
    //"Let's Encrypt 'Testflume2021' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdCLoJNt1QcNa7sNDp7g7oTJ+o/UIYEM6N/IZWT+dhdqtJZC+AODJ/4exdOwG04B4K6WrN1VB2ELKQIc/wU1lCw==",
    //"Let's Encrypt 'Testflume2022' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjy/rXcABuf0yhrm1+XgjDnh4XPD7vfMoyJOyT+KA+c2zuXVR98yQmp/Bl5ZFdGFwJuFcVrCw7IDo0EGKs7UCww==",
    //"Let's Encrypt 'Testflume2023' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8aLpnumqeISmQEB3hKPgtPJQG3jP2IftfaUQ4WPUihNBwUOEk1R9BMg5RGQwebWSsRlGIRiCvtE97Q45Vh3mqA==",
    //"Let's Encrypt 'Clicky' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHxoVg3cAdWK5n/YGBe2ViYNBgZfn4NQz/na6O8lJws3xz/4ScNe+qCJfsqRnAntxrh2sqOnRCNXO7zN6w18A3A==",
    //"Trust Asia Log2022",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu1LyFs+SC8555lRtwjdTpPX5OqmzBewdvRbsMKwu+HliNRWOGtgWLuRIa/bGE/GWLlwQ/hkeqBi4Dy3DpIZRlw==",
    //"Trust Asia Log2023",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpBFS2xdBTpDUVlESMFL4mwPPTJ/4Lji18Vq6+ji50o8agdqVzDPsIShmxlY+YDYhINnUrF36XBmhBX3+ICP89Q==",
    //"Nordu 'flimsy' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4qWq6afhBUi0OdcWUYhyJLNXTkGqQ9PMS5lqoCgkV2h1ZvpNjBH2u8UbgcOQwqDo66z6BWQJGolozZYmNHE2kQ==",
    //"Nordu 'plausible' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9UV9+jO2MCTzkabodO2F7LM03MUBc8MrdAtkcW6v6GA9taTTw9QJqofm0BbdAsbtJL/unyEf0zIkRgXjjzaYqQ==",
    //"Up In The Air 'Behind the Sofa' log",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWTmyppTGMrn+Y2keMDujW9WwQ8lQHpWlLadMSkmOi4+3+MziW5dy1eo/sSFI6ERrf+rvIv/f9F87bXcEsa+Qjw=="
  };

  public static String[] getTrustedLogKeys() {
    if (System.currentTimeMillis() > 1690873200000L) {
      getLog().warn("You might need to consider updating this list of logs");
    }
    return TRUSTED_LOG_KEYS;
  }
}
