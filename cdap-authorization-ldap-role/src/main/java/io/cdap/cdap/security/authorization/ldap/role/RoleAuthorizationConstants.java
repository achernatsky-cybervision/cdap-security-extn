/*
 * Copyright © 2016-2021 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization.ldap.role;

/**
 * Constants for {@link RoleAuthorization} class
 */
public final class RoleAuthorizationConstants {
  // Property to ignore users with full access
  public static final String IGNORE_FULL_ACCESS_USERS = "ignoreFullAccessUsers";

  // System namespace name
  public static final String SYSTEM_NAMESPACE = "system";

  // LDAP bind properties names for SecureStore
  public static final String LDAP_BIND_DN = "ldap_bind_dn";
  public static final String LDAP_BIND_PASS = "ldap_bind_pass";

  // LDAP config properties names
  public static final String URL = "url";
  public static final String SEARCH_FILTER = "searchFilter";
  public static final String SEARCH_BASE_DN = "searchBaseDn";
  public static final String MEMBER_ATTRIBUTE = "memberAttribute";
  public static final String LOOK_UP_BIND_DN = "lookUpBindDn";
  public static final String LOOK_UP_BIND_PASSWORD = "lookUpBindPassword";
  public static final String RECURSIVE_SEARCH = "recursiveSearch";
  public static final String IGNORE_SSL_VERIFY = "ignoreSSLVerify";

  // LDAP pool config properties names
  public static final String LDAP_POOL_AUTHENTICATION = "pool.authentication";
  public static final String LDAP_POOL_DEBUG = "pool.debug";
  public static final String LDAP_POOL_INITSIZE = "pool.initsize";
  public static final String LDAP_POOL_MAXSIZE = "pool.maxsize";
  public static final String LDAP_POOL_PREFSIZE = "pool.prefsize";
  public static final String LDAP_POOL_PROTOCOL = "pool.protocol";
  public static final String LDAP_POOL_TIMEOUT = "pool.timeout";

  // YAML config property name
  public static final String ROLE_YAML_PATH = "roleYamlPath";

  // Property to disable plugin and leave just debug logging
  public static final String LOGGING_ONLY = "loggingOnly";

  // Disable permissions propagation property name
  public static final String DISABLE_PERMISSIONS_PROPAGATION = "disablePermissionsPropagation";

  // Constants for start extension info
  public static final String MANIFEST_PATH = "META-INF/MANIFEST.MF";
  public static final String MANIFEST_TITLE_NAME = "Specification-Title";
  public static final String MANIFEST_VERSION_NAME = "Specification-Version";
  public static final String MANIFEST_BUILD_TIME_NAME = "Build-Time";
}
