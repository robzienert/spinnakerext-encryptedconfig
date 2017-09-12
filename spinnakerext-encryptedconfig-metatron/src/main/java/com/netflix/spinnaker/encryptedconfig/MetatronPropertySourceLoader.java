/*
 * Copyright 2017 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.spinnaker.encryptedconfig;

import com.netflix.metatronmock.MetatronDecryptor;
import com.netflix.spinnaker.encryptedconfig.exceptions.MetatronPropertySourceException;
import org.springframework.boot.env.PropertySourceLoader;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class MetatronPropertySourceLoader implements PropertySourceLoader {

  private final MetatronDecryptor decryptor;
  private final YamlPropertySourceLoader yamlPropertySourceLoader;

  private Map<String, MetatronEncryptedPolicyPair> loadedConfigs = new HashMap<>();

  private Map<String, byte[]> plaintextCache = new HashMap<>();

  public MetatronPropertySourceLoader() {
    this(new MetatronDecryptor(), new YamlPropertySourceLoader());
  }

  public MetatronPropertySourceLoader(MetatronDecryptor decryptor, YamlPropertySourceLoader yamlPropertySourceLoader) {
    this.decryptor = decryptor;
    this.yamlPropertySourceLoader = yamlPropertySourceLoader;
  }

  @Override
  public String[] getFileExtensions() {
    return new String[] { "mte" };
  }

  @Override
  public PropertySource<?> load(String name, Resource resource, String profile) throws IOException {
    String key = resource.getFilename();
    if (!loadedConfigs.containsKey(key)) {
      // lol "this should never happen". If it does, it likely means that loadedConfigs has not been set at all.
      throw new MetatronPropertySourceException("failed to find metatron config in loadedConfigs: this should never happen");
    }

    if (!plaintextCache.containsKey(key)) {
      try {
        plaintextCache.put(key, decryptor.decryptSecret(
          readUrl(resource.getURL()),
          readUrl(loadedConfigs.get(key).policy.getURL())
        ));
      } catch (Throwable t) {
        throw new MetatronPropertySourceException("Failed decrypting secrets", t);
      }
    }

    return yamlPropertySourceLoader.load(
      name + ":" + profile,
      new InputStreamResource(new ByteArrayInputStream(plaintextCache.get(key))),
      profile
    );
  }

  private byte[] readUrl(URL url) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    InputStream is = null;
    try {
      is = url.openStream();
      byte[] byteChunk = new byte[4096];
      int n;
      while ((n = is.read(byteChunk)) > 0) {
        baos.write(byteChunk, 0, n);
      }
    } finally {
      if (is != null) {
        is.close();
      }
    }
    return baos.toByteArray();
  }

  public void setLoadedConfigs(Map<String, MetatronEncryptedPolicyPair> loadedConfigs) {
    this.loadedConfigs = loadedConfigs;
  }
}
