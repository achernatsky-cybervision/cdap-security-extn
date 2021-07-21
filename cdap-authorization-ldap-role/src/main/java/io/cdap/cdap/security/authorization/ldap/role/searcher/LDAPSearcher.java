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

package io.cdap.cdap.security.authorization.ldap.role.searcher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;


/**
 * Service for searching user's groups in LDAP
 */
public class LDAPSearcher {
  private static final Logger LOG = LoggerFactory.getLogger(LDAPSearcher.class);

  private final Hashtable<String, String> properties;
  private final LDAPSearchConfig config;
  private final String[] baseDNList;

  /**
   * Constructor
   *
   * @param config {@link LDAPSearchConfig} configuration for LDAP searcher
   */
  public LDAPSearcher(LDAPSearchConfig config) {
    this.config = config;
    properties = getConnectionProperties();
    baseDNList = config.getSearchBaseDn().split(LDAPConstants.BASE_DN_SPLITTER);
  }

  /**
   * Tests connection to LDAP
   */
  public void testConnection() {
    try {
      DirContext context = getConnection();
      context.close();
    } catch (NamingException e) {
      String errorMsg = String.format("Failed to establish connection to '%s'", config.getUrl());
      throw new RuntimeException(errorMsg, e);
    }
  }

  /**
   * Searches for groups by username
   *
   * @param username Name of user
   * @return Set of groups
   */
  public Set<String> searchGroups(String username) {
    for (int i = 1;; i++) {
      try {
        DirContext context = getConnection();

        SearchControls controls = new SearchControls();
        if (config.isRecursiveSearch()) {
          controls.setSearchScope(SUBTREE_SCOPE);
        }

        // Close of DirContext can also throw NamingException
        try {
          return Arrays.stream(baseDNList)
            .map(baseDN -> searchGroups(baseDN, username, context, controls))
            .flatMap(Collection::stream)
            .collect(Collectors.toSet());
        } finally {
          context.close();
        }
      } catch (NamingException e) {
        Throwable cause = e.getCause();

        // Getting informative error message
        String exceptionMessage;
        if (cause == null) {
          exceptionMessage = e.getMessage();
        } else {
          exceptionMessage = cause.getMessage();
        }

        String errorMsg = String.format("Failed to find groups for user '%s': %s", username, exceptionMessage);

        // Throw error if maximum of attempts is reached
        if (i == LDAPConstants.MAX_SEARCH_RETRIES) {
          throw new RuntimeException(errorMsg, e);
        }

        LOG.warn(errorMsg);
        sleep(i * LDAPConstants.DEFAULT_RETRY_INTERVAL);
      }
    }
  }

  private Set<String> searchGroups(String baseDN, String username, DirContext context, SearchControls controls) {
    String filter = String.format(config.getSearchFilter(), username);
    Set<String> groups = new HashSet<>();

    try {
      NamingEnumeration<SearchResult> renum = context.search(baseDN, filter, controls);

      if (!renum.hasMore()) {
        LOG.debug("Cannot locate user information for '{}'", username);
        return groups;
      }

      SearchResult result = renum.next();

      Attribute memberOf = result.getAttributes().get(config.getMemberAttribute());
      if (memberOf != null) {
        for (int i = 0; i < memberOf.size(); i++) {
          groups.add(memberOf.get(i).toString());
        }
      }
    } catch (PartialResultException e) {
      LOG.debug("Failed to find groups for '{}' in '{}'", username, baseDN);
    } catch (NamingException e) {
      String errorMsg = String.format("Failed to find groups for '%s' in '%s'", username, baseDN);
      throw new RuntimeException(errorMsg, e);
    }

    return groups;
  }

  private DirContext getConnection() throws NamingException {
    for (int i = 1;; i++) {
      try {
        return new InitialDirContext(properties);
      } catch (NamingException e) {
        LOG.warn("Failed connect to '{}' on attempt '{}'", config.getUrl(), i);

        // Throw error if maximum of attempts is reached
        if (i == LDAPConstants.MAX_CONNECTION_RETRIES) {
          throw e;
        }

        sleep(i * LDAPConstants.DEFAULT_RETRY_INTERVAL);
      }
    }
  }

  private Hashtable<String, String> getConnectionProperties() {
    Hashtable<String, String> props = new Hashtable<>();
    String url = config.getUrl();

    props.put(Context.SECURITY_PRINCIPAL, config.getLookUpBindDN());
    props.put(Context.SECURITY_CREDENTIALS, config.getLookUpBindPassword());
    props.put(Context.INITIAL_CONTEXT_FACTORY, LDAPConstants.LDAP_CONTEXT_FACTORY);
    props.put(Context.PROVIDER_URL, url);

    if (config.isIgnoreSSLVerify() && url.startsWith(LDAPConstants.LDAPS_PROTOCOl)) {
      props.put(LDAPConstants.LDAP_SOCKET_FACTORY, BlindSSLSocketFactory.class.getName());
    }

    props.put(LDAPConstants.LDAP_POOL, "true");
    setPropertyIfNotNull(LDAPConstants.LDAP_POOL_AUTHENTICATION, config.getPoolAuthentication(), properties);
    setPropertyIfNotNull(LDAPConstants.LDAP_POOL_DEBUG, config.getPoolDebug(), properties);
    setPropertyIfNotNull(LDAPConstants.LDAP_POOL_MAXSIZE, config.getPoolMaxsize(), properties);
    setPropertyIfNotNull(LDAPConstants.LDAP_POOL_INITSIZE, config.getPoolInitsize(), properties);
    setPropertyIfNotNull(LDAPConstants.LDAP_POOL_PREFSIZE, config.getPoolPrefsize(), properties);
    setPropertyIfNotNull(LDAPConstants.LDAP_POOL_PROTOCOL, config.getPoolProtocol(), properties);
    setPropertyIfNotNull(LDAPConstants.LDAP_POOL_TIMEOUT, config.getPoolTimeout(), properties);

    return props;
  }

  private void sleep(long time) {
    try {
      Thread.sleep(time);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    }
  }

  private static void setPropertyIfNotNull(String propertyName, String propertyValue, Hashtable<String, String> properties) {
    if (Objects.nonNull(propertyValue)) {
      properties.put(propertyName, propertyValue);
    }
  }
}
