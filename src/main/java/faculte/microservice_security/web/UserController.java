package faculte.microservice_security.web;

import faculte.microservice_security.dto.RefreshTokenRequestDTO;
import faculte.microservice_security.dto.UserRequestDTO;
import faculte.microservice_security.dto.UserResponseDTO;
import faculte.microservice_security.entities.PermissionEntity;
import faculte.microservice_security.entities.RefreshToken;
import faculte.microservice_security.entities.Role;
import faculte.microservice_security.entities.User;
import faculte.microservice_security.repository.RoleRepository;
import faculte.microservice_security.repository.UserRepository;
import faculte.microservice_security.service.UserService;
import faculte.microservice_security.service.impl.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Tag(name = "Users", description = "API pour la gestion des utilisateurs")
@RestController
@RequestMapping("/v1/users")
public class UserController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserService userService, AuthenticationManager authenticationManager, JwtEncoder jwtEncoder, UserRepository userRepository, RefreshTokenService refreshTokenService, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Operation(
            summary = "Créer un nouvel utilisateur",
            description = "Crée un utilisateur avec nom, prénom, email et mot de passe"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Utilisateur créé avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Données invalides fournies"
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Email déjà utilisé"
            )
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/create")
    public ResponseEntity<UserResponseDTO> createUser(@RequestBody UserRequestDTO request) {
        UserResponseDTO responce = userService.createUser(request);

        if(responce.isActive() == false){
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(responce);
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(responce);
    }



    @Operation(
            summary = "Obtenir un utilisateur par ID",
            description = "Retourne les détails d'un utilisateur spécifique"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Utilisateur trouvé",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Utilisateur non trouvé"
            )
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/{id}")
    public ResponseEntity<UserResponseDTO> getUserById(
            @Parameter(
                    name = "id",
                    description = "ID de l'utilisateur",
                    required = true,
                    example = "1"
            )
            @PathVariable Integer id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    @Operation(
            summary = "Lister tous les utilisateurs",
            description = "Retourne la liste complète des utilisateurs"
    )
    @ApiResponse(
            responseCode = "200",
            description = "Liste des utilisateurs récupérée",
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = UserResponseDTO[].class)
            )
    )
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    @GetMapping
    public ResponseEntity<List<UserResponseDTO>> getAllUsers(@AuthenticationPrincipal Jwt jwt) {
        List<UserResponseDTO> users = userService.getAllUsers(); // fetch all users
        List<String> roles = jwt.getClaim("roles"); // roles dyal current user

        if (roles.contains("ADMIN")) {
            // ADMIN yjib kolchi
            return ResponseEntity.ok(users);
        } else if (roles.contains("MANAGER")) {
            // MANAGER yjib ghyr internal roles
            List<String> internalRoles = List.of("HOUSEKEEPING", "RECEPTIONNISTE", "MAINTENANCE", "COMPTABLE", "MANAGER");
            List<UserResponseDTO> filteredUsers = users.stream()
                    .filter(u -> u.getRoles().stream().anyMatch(internalRoles::contains))
                    .collect(Collectors.toList());
            return ResponseEntity.ok(filteredUsers);
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build(); // li ma fihch ADMIN/MANAGER
        }
    }


    @Operation(
            summary = "Supprimer un utilisateur",
            description = "Supprime un utilisateur existant par son ID"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Utilisateur supprimé avec succès"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Utilisateur non trouvé"
            )
    })
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteUser(
            @Parameter(
                    name = "id",
                    description = "ID de l'utilisateur à supprimer",
                    required = true
            )
            @PathVariable Integer id) {
        userService.deleteUser(id);
        return ResponseEntity.ok("Utilisateur supprimé avec succès");
    }

    @Operation(
            summary = "Assigner un rôle à un utilisateur",
            description = "Attribue un rôle existant à un utilisateur"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Rôle assigné avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Utilisateur ou rôle non trouvé"
            )
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/{userId}/roles")
    public ResponseEntity<UserResponseDTO> assignRoleToUser(
            @Parameter(
                    name = "userId",
                    description = "ID de l'utilisateur",
                    required = true
            )
            @PathVariable Integer userId,
            @Parameter(
                    name = "roleName",
                    description = "Nom du rôle à assigner",
                    required = true,
                    example = "ADMIN"
            )
            @RequestParam String roleName) {
        return ResponseEntity.ok(userService.assignRoleToUser(userId, roleName));
    }











    @PostMapping("/register")
    @Operation(
            summary = "Inscription d’un nouvel utilisateur (CLIENT)",
            description = "Permet à un utilisateur de s’inscrire avec son email et son mot de passe. "
                    + "Le rôle est automatiquement défini à CLIENT et ne peut pas être choisi par l’utilisateur."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Utilisateur inscrit avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserResponseDTO.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Données invalides (email ou mot de passe incorrect)"
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Adresse email déjà utilisée"
            )
    })
    public ResponseEntity<UserResponseDTO> registerUserClient(
            @Valid @RequestBody UserRequestDTO request) {

        // Forcer le rôle à CLIENT
        request.setRole(Set.of("CLIENT"));
        UserResponseDTO response = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

//AuthController


    @PostMapping("/login")
    @Operation(
            summary = "Authentification utilisateur",
            description = "Authentifie un utilisateur avec email/mot de passe et retourne les tokens d'accès et de rafraîchissement"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Authentification réussie",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserResponseDTO.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Email ou mot de passe incorrect",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Compte utilisateur désactivé",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Erreur interne du serveur",
                    content = @Content
            )
    })

    public ResponseEntity<UserResponseDTO> login(
            @Parameter(description = "Informations d'authentification", required = true)
            @RequestBody UserRequestDTO request) {
        try {
            // 1. Authentification
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            // 2. Récupérer utilisateur
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            // 3. Récupérer rôles et permissions
            Set<String> allRoles = new HashSet<>();
            if (user.getRoles() != null) {
                for (Role role : user.getRoles()) {
                    allRoles.add(role.getName());
                }
            }

            Set<String> allPermissions = new HashSet<>();
            if (user.getRoles() != null) {
                for (Role role : user.getRoles()) {
                    if (role.getPermissions() != null) {
                        for (PermissionEntity perm : role.getPermissions()) {
                            allPermissions.add(perm.getName());
                        }
                    }
                }
            }



            // 4. Générer ACCESS TOKEN (JWT - 1 heure)
            String authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));

            Instant now = Instant.now();
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("microservice-security")
                    .issuedAt(now)
                    .expiresAt(now.plus(1, ChronoUnit.HOURS))
                    .subject(authentication.getName())
                    .claim("authorities", authorities)
                    .claim("email", user.getEmail())
                    .claim("prenom", user.getFirstName())
                    .claim("nom", user.getLastName())
                    .claim("userId", user.getId())
                    .claim("roles", allRoles)
                    .claim("permissions", allPermissions)
                    .claim("type", "access")
                    .build();

            String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

            // 5. Créer et stocker REFRESH TOKEN en base (UUID - 7 jours)
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

            // 6. Créer la réponse
            UserResponseDTO response = new UserResponseDTO();
            response.setId(user.getId());
            response.setEmail(user.getEmail());
            response.setFirstName(user.getFirstName());
            response.setLastName(user.getLastName());
            response.setActive(user.isActive());
            response.setCreatedAt(user.getCreatedAt());
            response.setUpdatedAt(user.getUpdatedAt());
            response.setRoles(allRoles);
            response.setAccessToken(accessToken);
            response.setRefreshToken(refreshToken.getToken()); // UUID stocké en base
            response.setTokenType("Bearer");
            response.setTokenExpiresIn(3600);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
    @PostMapping("/refresh")
    @Operation(
            summary = "Rafraîchir le token d'accès",
            description = "Utilise le refresh token pour obtenir un nouveau token d'accès. Implémente la rotation des refresh tokens pour plus de sécurité."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token rafraîchi avec succès",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserResponseDTO.class))
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Refresh token invalide, expiré ou révoqué",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Compte utilisateur désactivé",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Erreur interne du serveur",
                    content = @Content
            )
    })
    public ResponseEntity<UserResponseDTO> refresh(
            @Parameter(description = "Refresh token à utiliser pour obtenir un nouveau token d'accès", required = true)
            @RequestBody RefreshTokenRequestDTO request) {
        try {
            // 1. Vérifier le refresh token dans la base
            RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(request.getRefreshToken());
            User user = refreshToken.getUser();

            // 2. Vérifier si le compte est actif
            if (!user.isActive()) {
                refreshTokenService.revokeRefreshToken(refreshToken.getToken());
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            // 3. Récupérer rôles et permissions (au cas où ils auraient changé)
            Set<String> allRoles = new HashSet<>();
            if (user.getRoles() != null) {
                for (Role role : user.getRoles()) {
                    allRoles.add(role.getName());
                }
            }

            Set<String> allPermissions = new HashSet<>();
            if (user.getRoles() != null) {
                for (Role role : user.getRoles()) {
                    if (role.getPermissions() != null) {
                        for (PermissionEntity perm : role.getPermissions()) {
                            allPermissions.add(perm.getName());
                        }
                    }
                }
            }



            // 4. Générer NOUVEAU ACCESS TOKEN
            Instant now = Instant.now();
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("microservice-security")
                    .issuedAt(now)
                    .expiresAt(now.plus(1, ChronoUnit.HOURS))
                    .subject(user.getEmail())
                    .claim("email", user.getEmail())
                    .claim("userId", user.getId())
                    .claim("prenom", user.getFirstName())
                    .claim("nom", user.getLastName())
                    .claim("roles", allRoles)
                    .claim("permissions", allPermissions)
                    .claim("type", "access")
                    .build();

            String newAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

            // 5. ROTATION: Créer nouveau refresh token
            RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getId());

            // 6. Révoquer l'ancien refresh token
            refreshTokenService.revokeRefreshToken(refreshToken.getToken());

            // 7. Créer la réponse
            UserResponseDTO response = new UserResponseDTO();
            response.setId(user.getId());
            response.setFirstName(user.getFirstName());
            response.setLastName(user.getLastName());
            response.setEmail(user.getEmail());
            response.setActive(user.isActive());
            response.setRoles(allRoles);
            response.setAccessToken(newAccessToken);
            response.setRefreshToken(newRefreshToken.getToken()); // Nouveau refresh token
            response.setTokenType("Bearer");
            response.setTokenExpiresIn(3600);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/logout")
    @Operation(
            summary = "Déconnexion utilisateur",
            description = "Révoque le refresh token spécifié, invalidant ainsi la session utilisateur"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Déconnexion réussie",
                    content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Refresh token invalide",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Erreur interne du serveur",
                    content = @Content
            )
    })
    public ResponseEntity<String> logout(
            @Parameter(description = "Refresh token à révoquer", required = true)
            @RequestBody RefreshTokenRequestDTO request) {
        try {
            refreshTokenService.revokeRefreshToken(request.getRefreshToken());
            return ResponseEntity.ok("Déconnexion réussie");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erreur lors de la déconnexion");
        }
    }
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/logout-all")
    @Operation(
            summary = "Déconnexion globale",
            description = "Révoque tous les refresh tokens d'un utilisateur, déconnectant ainsi toutes ses sessions actives"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Déconnexion globale réussie",
                    content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Email utilisateur invalide",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Utilisateur non trouvé",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Erreur interne du serveur",
                    content = @Content
            )
    })
    public ResponseEntity<String> logoutAll(
            @Parameter(description = "Email de l'utilisateur à déconnecter", required = true, example = "user@example.com")
            @RequestParam String email) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            refreshTokenService.revokeAllUserTokens(user.getId());
            return ResponseEntity.ok("Déconnexion de tous les appareils réussie");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erreur");
        }
    }
}