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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.boot.env.EnumerableCompositePropertySource;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Wires up the MetatronPropertySourceLoader, discovering all metatron encrypted configs. We search
 * for secrets at two locations:
 *
 * 1. Resources on all classpaths at the path <namespace>/metatron.
 * 2. On the filesystem at /apps/spinnaker<namespace>/metatron.
 */
public class MetatronApplicationListener implements ApplicationListener<ApplicationEnvironmentPreparedEvent>, Ordered {

  private final static Logger log = LoggerFactory.getLogger(MetatronApplicationListener.class);

  private final static String METATRON_ENABLED_FLAG = "metatron.enabled";
  private final static String METATRON_NAMESPACES_PROPERTY = "metatron.namespaces";

  private MetatronPropertySourceLoader propertySourceLoader;

  private Collection<MetatronSecretLoader> secretLoaders;

  public MetatronApplicationListener() {
    this(new MetatronPropertySourceLoader(), Arrays.asList(
      new MetatronResourceLoader(),
      new MetatronFileLoader()
    ));
  }

  public MetatronApplicationListener(MetatronPropertySourceLoader propertySourceLoader, Collection<MetatronSecretLoader> secretLoaders) {
    this.propertySourceLoader = propertySourceLoader;
    this.secretLoaders = secretLoaders;
  }

  @Override
  public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
    if (isMetatronDisabled()) {
      log.warn("Metatron secret decryption is disabled!");
      return;
    }
    onInterestedEvent(event.getEnvironment());
  }

  private void onInterestedEvent(ConfigurableEnvironment environment) {
    for (String namespace : getMetatronNamespaces()) {
      Collection<MetatronEncryptedPolicyPair> pairs = secretLoaders.stream()
        .map(l -> l.load(namespace))
        .flatMap(Collection::stream)
        .collect(Collectors.toList());

      log.info("Found " + pairs.size() + " metatron secret sources");

      propertySourceLoader.setLoadedConfigs(pairs.stream()
        .collect(Collectors.toMap(s -> s.secret.getFilename(), metatronEncryptedPolicyPair -> metatronEncryptedPolicyPair)));

      if (!pairs.isEmpty()) {
        EnumerableCompositePropertySource ps = new EnumerableCompositePropertySource("metatron" + namespace);
        pairs.forEach(p -> {
          String[] profiles = environment.getActiveProfiles();
          if (profiles.length > 0) {
            // Given profiles "mgmt,test,local", PropertySources will load first match, so we want "local" first
            List<String> reversedProfiles = Arrays.asList(profiles);
            Collections.reverse(reversedProfiles);
            for (String profile : profiles) {
              load(ps, p.secret, profile);
            }
          }
          load(ps, p.secret, null);
        });
        environment.getPropertySources().addLast(ps);
      }
    }
  }

  private void load(EnumerableCompositePropertySource compositePropertySource, Resource resource, String profile) {
    try {
      PropertySource<?> propertySource = propertySourceLoader.load(resource.getFilename(), resource, profile);
      if (propertySource == null) {
        log.warn("Could not load PropertySource: " + resource.getFilename() + ":" + profile);
      } else {
        compositePropertySource.add(propertySource);
        log.info("Loaded PropertySource: " + resource.getFilename() + ":" + profile);
      }
    } catch (IOException e) {
      throw new RuntimeException("Could not load metatron encrypted config", e);
    }
  }

  private static boolean isMetatronDisabled() {
    String flag = System.getProperty(METATRON_ENABLED_FLAG, "true");
    return !flag.equals("") && !Boolean.parseBoolean(flag);
  }

  private static List<String> getMetatronNamespaces() {
    List<String> namespaces = new ArrayList<>();
    // Add the root Metatron folder as an empty namespace
    namespaces.add("");

    namespaces.addAll(
      Arrays.stream(System.getProperty(METATRON_NAMESPACES_PROPERTY, "").split(","))
        .filter(s -> !s.isEmpty())
        .map(s -> s.startsWith("/") ? s : "/" + s)
        .collect(Collectors.toList())
    );

    return namespaces;
  }

  @Override
  public int getOrder() {
    return LOWEST_PRECEDENCE;
  }
}
