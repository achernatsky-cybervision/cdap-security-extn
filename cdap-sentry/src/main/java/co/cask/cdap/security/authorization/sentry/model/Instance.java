/*
 * Copyright 2016 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package co.cask.cdap.security.authorization.sentry.model;

/**
 * Represents the {@link Authorizable.AuthorizableType#INSTANCE} authorizable in CDAP
 */
public class Instance implements Authorizable {
  private String name;

  /**
   * Create an {@link Authorizable.AuthorizableType#INSTANCE} authorizable of the given name.
   *
   * @param name Name of the {@link Authorizable.AuthorizableType#INSTANCE}
   */
  public Instance(String name) {
    this.name = name;
  }

  /**
   * Get type of {@link Authorizable.AuthorizableType#INSTANCE} authorizable.
   *
   * @return Type of {@link Authorizable.AuthorizableType#INSTANCE} authorizable.
   */
  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.INSTANCE;
  }

  /**
   * Get name of the {@link Authorizable.AuthorizableType#INSTANCE}.
   *
   * @return Name of the {@link Authorizable.AuthorizableType#INSTANCE}.
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * Get type name of Instance authorizable.
   *
   * @return Type name of {@link Authorizable.AuthorizableType#INSTANCE} authorizable.
   */
  @Override
  public String getTypeName() {
    return getAuthzType().name();
  }
}