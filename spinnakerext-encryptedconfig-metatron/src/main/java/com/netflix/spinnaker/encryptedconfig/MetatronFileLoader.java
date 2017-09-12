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

import com.netflix.spinnaker.encryptedconfig.exceptions.MetatronSecretLoaderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MetatronFileLoader implements MetatronSecretLoader {

  private final static Logger log = LoggerFactory.getLogger(MetatronFileLoader.class);

  private final static String CONFIG_PATH_FORMAT = "/apps/spinnaker%s/metatron/encrypted";
  private final static String POLICY_PATH_FORMAT = "/apps/spinnaker%s/metatron/policy";

  private final String configPathFormat;
  private final String policyPathFormat;

  public MetatronFileLoader() {
    this(CONFIG_PATH_FORMAT, POLICY_PATH_FORMAT);
  }

  public MetatronFileLoader(String configPathFormat, String policyPathFormat) {
    this.configPathFormat = configPathFormat;
    this.policyPathFormat = policyPathFormat;
  }

  @Override
  public Collection<MetatronEncryptedPolicyPair> load(String namespace) {
    String configPath = buildConfigPath(configPathFormat, namespace);
    String policyPath = buildPolicyPath(policyPathFormat, namespace);

    if (!Files.isDirectory(Paths.get(configPath)) || !Files.isDirectory(Paths.get(policyPath))) {
      log.warn("Metatron filepath " + configPath + " does not exist, skipping load");
      return Collections.emptyList();
    }

    Stream<Path> files;
    try {
      files = Files.list(Paths.get(configPath));
    } catch (IOException e) {
      throw new MetatronSecretLoaderException("Could not list encrypted metatron files at " + configPath, e);
    }

    return files
      .filter(f -> {
        if (f.toFile().exists()) {
          return true;
        }
        log.warn("config file inaccessible or does not exist: " + f.toFile().toString());
        return false;
      })
      .map(path -> new MetatronEncryptedPolicyPair(
        new FileSystemResource(path.toFile()),
        loadPolicy(policyPath, parseConfigVersion(path.getFileName().toString()))
      ))
      .collect(Collectors.toList());
  }

  private Resource loadPolicy(String policyPath, int version) {
    Stream<Path> files;
    try {
      files = Files.list(Paths.get(policyPath));
    } catch (IOException e) {
      throw new MetatronSecretLoaderException("Could not list metatron policy files at " + policyPath, e);
    }

    return files
      .filter(f -> f.toFile().exists())
      .filter(p -> parsePolicyVersion(p.getFileName().toString()) == version)
      .findFirst()
      .map(path -> new FileSystemResource(path.toFile()))
      .orElseThrow((Supplier<RuntimeException>) () -> new MetatronSecretLoaderException("No matching policy for version " + Integer.toString(version)));
  }
}
