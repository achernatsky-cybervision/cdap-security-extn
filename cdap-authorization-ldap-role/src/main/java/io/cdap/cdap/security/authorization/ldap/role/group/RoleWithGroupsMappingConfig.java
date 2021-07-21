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

package io.cdap.cdap.security.authorization.ldap.role.group;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermission;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Config of mapping {@link Role} to {@link RolePermission} and LDAP groups
 */
public class RoleWithGroupsMappingConfig {
  private Map<String, Role> roles;
  @JsonProperty("mappings")
  private Map<String, GroupWithRoles> roleMapping;

  public RoleWithGroupsMappingConfig() {
    roles = new HashMap<>();
    roleMapping = new HashMap<>();
  }

  public RoleWithGroupsMappingConfig(Map<String, Role> roles, Map<String, GroupWithRoles> roleMapping) {
    this.roles = roles;
    this.roleMapping = roleMapping;
  }

  public Map<String, Role> getRoles() {
    return roles;
  }

  public Map<String, GroupWithRoles> getRoleMapping() {
    return roleMapping;
  }

  public void setRoles(Map<String, Role> roles) {
    this.roles = roles;
  }

  @JsonSetter
  public void setRoles(List<Role> roles) {
    this.roles = roles.stream()
      .collect(Collectors.toMap(Role::getName, Function.identity()));
  }

  public void setRoleMapping(Map<String, GroupWithRoles> roleMapping) {
    this.roleMapping = roleMapping;
  }

  @JsonSetter
  public void setRoleMapping(List<GroupWithRoles> roleMapping) {
    this.roleMapping = roleMapping.stream()
      .collect(Collectors.toMap(GroupWithRoles::getGroup, Function.identity()));
  }

  public boolean isEmpty() {
    return roles.isEmpty() && roleMapping.isEmpty();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    RoleWithGroupsMappingConfig that = (RoleWithGroupsMappingConfig) o;
    return Objects.equals(roles, that.roles) && Objects.equals(roleMapping, that.roleMapping);
  }

  @Override
  public int hashCode() {
    return Objects.hash(roles, roleMapping);
  }
}
