//package faculte.microservice_security.config;
//
//import faculte.microservice_security.entities.PermissionEntity;
//import faculte.microservice_security.entities.Role;
//import faculte.microservice_security.entities.User;
//import faculte.microservice_security.repository.PermissionEntityRepository;
//import faculte.microservice_security.repository.RoleRepository;
//import faculte.microservice_security.repository.UserRepository;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import java.util.HashSet;
//import java.util.Set;
//
//
//@Component
//public class DataInitializer implements CommandLineRunner {
//
//    private final UserRepository userRepository;
//    private final RoleRepository roleRepository;
//    private final PermissionEntityRepository permissionRepository;
//    private final PasswordEncoder passwordEncoder;
//
//    public DataInitializer(UserRepository userRepository,
//                           RoleRepository roleRepository,
//                           PermissionEntityRepository permissionRepository,
//                           PasswordEncoder passwordEncoder) {
//        this.userRepository = userRepository;
//        this.roleRepository = roleRepository;
//        this.permissionRepository = permissionRepository;
//        this.passwordEncoder = passwordEncoder;
//    }
//
//    @Override
//    public void run(String... args) throws Exception {
//
//        //  Créer les permissions par défaut si elles n'existent pas
//        String[] defaultPermissions = {"USER_CREATE", "USER_READ", "USER_UPDATE", "USER_DELETE"};
//        Set<PermissionEntity> permissions = new HashSet<>();
//        for (String permName : defaultPermissions) {
//            PermissionEntity perm = permissionRepository.findByName(permName)
//                    .orElseGet(() -> {
//                        PermissionEntity p = new PermissionEntity();
//                        p.setName(permName);
//                        return permissionRepository.save(p);
//                    });
//            permissions.add(perm);
//        }
//
//        //  Créer le rôle ADMIN si pas existant
//        Role adminRole = roleRepository.findByName("ADMIN")
//                .orElseGet(() -> {
//                    Role role = new Role();
//                    role.setName("ADMIN");
//                    role.setDescription("Role administrateur principal");
//                    role.setPermissions(permissions); // assigner permissions ici
//                    return roleRepository.save(role);
//                });
//
//        //  Vérifier si l'admin existe déjà
//        boolean adminExists = userRepository.findAll().stream()
//                .anyMatch(u -> u.getRoles().contains(adminRole));
//
//        // Créer l'Admin User si nécessaire
//        if (!adminExists) {
//            User adminUser = new User();
//            adminUser.setEmail("admin@example.com");  // utilisé comme username
//            adminUser.setPassword(passwordEncoder.encode("admin123"));
//            adminUser.setActive(true);
//            adminUser.getRoles().add(adminRole);
//
//            userRepository.save(adminUser);
//            System.out.println("✅ Admin user et permissions créés avec succès !");
//        } else {
//            System.out.println("ℹ Admin user déjà existant, aucune action prise.");
//        }
//    }
//}
//
//
