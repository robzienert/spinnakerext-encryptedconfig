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

import java.util.Collection;

public interface MetatronSecretLoader {

  Collection<MetatronEncryptedPolicyPair> load(String namespace);

  default int parsePolicyVersion(String filename) {
    String[] p = filename.split("\\.");
    if (p.length != 3) {
      throw new IllegalStateException("Malformed config filename '" + filename + "' expected 'POLICY_NAME.POLICY_NUMBER.mtp'");
    }
    return Integer.parseInt(p[1]);
  }

  default int parseConfigVersion(String filename) {
    String[] p = filename.split("\\.");
    if (p.length != 4) {
      throw new IllegalStateException("Malformed config filename '" + filename + "' expected 'APP_NAME.yml.POLICY_NUMBER.mte'");
    }
    return Integer.parseInt(p[2]);
  }

  default String buildConfigPath(String format, String namespace) {
    return String.format(format, namespace);
  }

  default String buildPolicyPath(String format, String namespace) {
    return String.format(format, namespace);
  }
}
