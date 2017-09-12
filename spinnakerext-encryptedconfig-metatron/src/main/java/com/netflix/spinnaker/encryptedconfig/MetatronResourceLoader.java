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
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.util.ClassUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class MetatronResourceLoader implements MetatronSecretLoader {

  private final static String CONFIG_PATTERN_FORMAT = "classpath*:%s/metatron/encrypted/*.mte";
  private final static String POLICY_PATTERN_FORMAT = "classpath*:%s/metatron/policy/*.mtp";

  private final String configPattern;
  private final String policyPattern;

  public MetatronResourceLoader() {
    this(CONFIG_PATTERN_FORMAT, POLICY_PATTERN_FORMAT);
  }

  public MetatronResourceLoader(String configPattern, String policyPattern) {
    this.configPattern = configPattern;
    this.policyPattern = policyPattern;
  }

  @Override
  public Collection<MetatronEncryptedPolicyPair> load(String namespace) {
    String configPath = buildConfigPath(configPattern, namespace);
    String policyPath = buildPolicyPath(policyPattern, namespace);

    Resource[] resources;
    try {
      resources = new PathMatchingResourcePatternResolver(ClassUtils.getDefaultClassLoader()).getResources(configPath);
    } catch (IOException e) {
      throw new MetatronSecretLoaderException("Could not resolve metatron encrypted config resources", e);
    }

    return Arrays.stream(resources)
      .filter(Resource::exists)
      .map(resource -> new MetatronEncryptedPolicyPair(resource, loadPolicy(policyPath, parseConfigVersion(resource.getFilename()))))
      .collect(Collectors.toList());
  }

  private Resource loadPolicy(String policyPath, int version) {
    Resource[] resources;
    try {
      resources = new PathMatchingResourcePatternResolver(ClassUtils.getDefaultClassLoader()).getResources(policyPath);
    } catch (IOException e) {
      throw new MetatronSecretLoaderException("Could not find a metatron policy for version " + version, e);
    }

    return Arrays.stream(resources)
      .filter(Resource::exists)
      .filter(r -> parsePolicyVersion(r.getFilename()) == version)
      .findFirst()
      .orElseThrow((Supplier<RuntimeException>) () -> new MetatronSecretLoaderException("No matching policy for version " + Integer.toString(version)));
  }
}
