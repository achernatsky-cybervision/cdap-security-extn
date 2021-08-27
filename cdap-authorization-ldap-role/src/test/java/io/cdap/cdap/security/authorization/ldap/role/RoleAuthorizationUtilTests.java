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

import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.id.ArtifactId;
import io.cdap.cdap.proto.id.SecureKeyId;
import io.cdap.cdap.proto.security.Permission;
import io.cdap.cdap.proto.security.StandardPermission;
import io.cdap.cdap.security.authorization.ldap.role.group.PrincipalPermissions;
import io.cdap.cdap.security.authorization.ldap.role.permission.EntityTypeWithPermission;
import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermissionConverter;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Tests for {@link RoleAuthorizationUtil} class
 */
public class RoleAuthorizationUtilTests {
  private final static String TEST_NAMESPACE = "test";
  private final static String TEST_JAR = "test-1.0.jar";
  private final static Permission PERMISSION = StandardPermission.GET;

  private static PrincipalPermissions PRINCIPAL_PERMISSIONS;

  @BeforeClass
  public static void init() {
    Map<String, Set<EntityTypeWithPermission>> permissionsMap = new HashMap<>();

    EntityTypeWithPermission entityTypeWithPermission = new EntityTypeWithPermission(EntityType.NAMESPACE, PERMISSION);
    permissionsMap.put(TEST_NAMESPACE, Collections.singleton(entityTypeWithPermission));

    entityTypeWithPermission = new EntityTypeWithPermission(EntityType.NAMESPACE, PERMISSION, true);
    permissionsMap.put(RolePermissionConverter.SYSTEM_NAMESPACE, Collections.singleton(entityTypeWithPermission));

    PRINCIPAL_PERMISSIONS = new PrincipalPermissions(permissionsMap);
  }

  @Test
  public void testGetPropagatedPermissionsInSystemNamespace() {
    ArtifactId artifactId = new ArtifactId(RolePermissionConverter.SYSTEM_NAMESPACE, TEST_JAR);

    boolean isAllowed = RoleAuthorizationUtil.getPropagatedPermission(artifactId, PERMISSION, PRINCIPAL_PERMISSIONS)
      .isPresent();

    Assert.assertFalse(isAllowed);
  }

  @Test
  public void testGetPropagatedPermissionsInNonSystemNamespace() {
    ArtifactId artifactId = new ArtifactId(TEST_NAMESPACE, TEST_JAR);

    boolean isAllowed = RoleAuthorizationUtil.getPropagatedPermission(artifactId, PERMISSION, PRINCIPAL_PERMISSIONS)
      .isPresent();

    Assert.assertTrue(isAllowed);
  }

  @Test
  public void testGetPropagatedPermissionsWithSecureKey() {
    SecureKeyId secureKeyId = new SecureKeyId(TEST_NAMESPACE, TEST_NAMESPACE);

    boolean isAllowed = RoleAuthorizationUtil.getPropagatedPermission(secureKeyId, PERMISSION, PRINCIPAL_PERMISSIONS)
      .isPresent();

    Assert.assertFalse(isAllowed);
  }
}
