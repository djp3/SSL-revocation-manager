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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheStats;

public abstract class Verifier<K extends Serializable, V extends Serializable> {

  protected static SecureRandom r = new SecureRandom();

  private static transient volatile Logger log = null;

  public static Logger getLog() {
    if (log == null) {
      log = LogManager.getLogger(Verifier.class);
    }
    return log;
  }

  public static class Configuration {
    /* Use a cache */
    public boolean useCache = true;
    public boolean trackCacheStats = true;

    /* Cache Cold Storage */
    public boolean loadCacheFromColdStorageOnStart = false;
    public String loadCacheColdStorageFileName = null;
    public boolean storeCacheToColdStorageOnQuit = false;
    public String storeCacheColdStorageFileName = null;

    /* Cache parameters */
    public Integer cacheMaxSize = 1000;

    /* Check validity of cache entries periodically */
    public long duration = 60;
    public TimeUnit timeUnit = TimeUnit.MINUTES;
  }

  protected final Configuration config;
  private Cache<K, V> cache;
  private CacheStats cacheStatsBaseline;
  protected ScheduledExecutorService scheduler;
  protected ScheduledFuture<?> validityCheckerHandle;

  public Verifier(Configuration config)
      throws FileNotFoundException, ClassNotFoundException, IOException {
    if (config == null) {
      throw new InvalidParameterException("config must not be null");
    }

    this.config = config;

    //Set up cache
    resetCache();
  }

  protected abstract Runnable getValidityCheckerCode();

  protected Cache<K, V> getCache() {
    return cache;
  }

  private void setCache(Cache<K, V> newCache) {
    this.cache = newCache;
  }

  @SuppressWarnings("unchecked")
  private void loadCache() {
    try {
      try (FileInputStream fis = new FileInputStream(config.loadCacheColdStorageFileName)) {
        try (ObjectInputStream ois = new ObjectInputStream(fis)) {
          Map<? extends K, ? extends V> cacheLoad =
              (Map<? extends K, ? extends V>) ois.readObject();
          getCache().putAll(cacheLoad);
        }
      }
    } catch (FileNotFoundException e) {
      getLog()
          .error(
              "Unable to find file to load cache from (First load?): "
                  + config.loadCacheColdStorageFileName
                  + "\n"
                  + e);
    } catch (IOException e) {
      getLog()
          .error(
              "Unable to find file to load cache from (First load?): "
                  + config.loadCacheColdStorageFileName
                  + "\n"
                  + e);
    } catch (ClassNotFoundException e) {
      getLog()
          .error(
              "Unable to load objects into cache from (First load?): "
                  + config.loadCacheColdStorageFileName
                  + "\n"
                  + e);
    }
    getLog().info("Loaded cache from " + config.loadCacheColdStorageFileName);
  }

  protected void saveCache() throws FileNotFoundException, IOException {
    try (FileOutputStream fos = new FileOutputStream(config.storeCacheColdStorageFileName)) {
      try (ObjectOutputStream oos = new ObjectOutputStream(fos)) {
        HashMap<K, V> hashMap = new HashMap<K, V>(getCache().asMap());
        oos.writeObject(hashMap);
      }
    }
    getLog().info("Saved cache to " + config.storeCacheColdStorageFileName);
  }

  public synchronized void shutdown() throws FileNotFoundException, IOException {
    if (config.useCache && (getCache() != null)) {
      if (validityCheckerHandle != null) {
        validityCheckerHandle.cancel(false);
        scheduler.shutdownNow();
      }
      if (config.storeCacheToColdStorageOnQuit && (config.storeCacheColdStorageFileName != null)) {
        saveCache();
      }
    }
  }

  public void resetCache() {
    if (getCache() != null) {
      try {
        shutdown();
      } catch (FileNotFoundException e) {
        getLog()
            .error(
                "Unable to store SSL Verifier cache:"
                    + config.storeCacheColdStorageFileName
                    + "\n"
                    + e);
      } catch (IOException e) {
        getLog()
            .error(
                "Unable to store SSL Verifier cache:"
                    + config.storeCacheColdStorageFileName
                    + "\n"
                    + e);
      } finally {
        setCache(null);
      }
    }
    cacheStatsBaseline = null;
    scheduler = null;
    validityCheckerHandle = null;

    if (config.useCache) {
      CacheBuilder<Object, Object> cacheBuilder = CacheBuilder.newBuilder();
      cacheBuilder = cacheBuilder.maximumSize(config.cacheMaxSize);
      if (config.trackCacheStats) {
        cacheBuilder.recordStats();
      }
      setCache(cacheBuilder.build());

      //Load the cache from disk
      if (config.loadCacheFromColdStorageOnStart && (config.loadCacheColdStorageFileName != null)) {
        loadCache();
      }

      //Set up a periodic cleaner
      scheduler = Executors.newScheduledThreadPool(1);

      //Launch cleaner immediately to deal with possible stale data in the cold loaded file, then periodically
      validityCheckerHandle =
          scheduler.scheduleAtFixedRate(
              getValidityCheckerCode(), 0, config.duration, config.timeUnit);

      cacheStatsBaseline = getCache().stats();
    }
  }

  public CacheStats getCacheStats() {
    if (config.useCache && (getCache() != null)) {
      CacheStats stats = getCache().stats().minus(cacheStatsBaseline);
      return stats;
    }
    return null;
  }

  public void triggerGarbageCollection() {
    if (config.useCache && (getCache() != null)) {
      Runnable code = getValidityCheckerCode();
      Thread t = new Thread(code);
      t.setDaemon(false);
      t.setName("Manual Cache Validity Checker");
      t.run();
    }
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
  public abstract VerificationStatus checkRevocationStatus(
      final X509Certificate peerCert,
      final X509Certificate issuerCert,
      final X509Certificate[] fullChain)
      throws CertificateVerificationException, ExecutionException;
}
