package faculte.microservice_security.service.impl;

import faculte.microservice_security.entities.PermissionEntity;
import faculte.microservice_security.repository.PermissionEntityRepository;
import faculte.microservice_security.service.PermissionService;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Transactional
public class PermissionServiceImpl implements PermissionService {

    private final PermissionEntityRepository permissionRepository;

    public PermissionServiceImpl(PermissionEntityRepository permissionRepository) {
        this.permissionRepository = permissionRepository;
    }

    @Override
    public PermissionEntity createPermission(String permissionName) {

        PermissionEntity permission = new PermissionEntity();
        permission.setName(permissionName);

        return permissionRepository.save(permission);
    }

    @Override
    public List<PermissionEntity> getAllPermissions() {
        return permissionRepository.findAll();
    }
}

