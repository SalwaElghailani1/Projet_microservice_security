package faculte.microservice_security.service;

import faculte.microservice_security.entities.Role;

import java.util.List;

public interface RoleService {
    Role createRole(String roleName);
    void assignPermissionToRole(String roleName, String permissionName);
    List<Role> getAllRoles();
}
