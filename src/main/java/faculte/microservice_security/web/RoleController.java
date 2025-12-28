package faculte.microservice_security.web;

import faculte.microservice_security.entities.Role;
import faculte.microservice_security.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Roles", description = "API pour la gestion des rôles et permissions")
@RestController
@RequestMapping("/v1/roles")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @Operation(
            summary = "Créer un nouveau rôle",
            description = "Crée un rôle avec un nom spécifique"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "201",
                    description = "Rôle créé avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Role.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Nom du rôle invalide ou déjà utilisé"
            )
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<Role> createRole(
            @Parameter(
                    name = "name",
                    description = "Nom du rôle à créer",
                    required = true,
                    example = "ADMIN"
            )
            @RequestParam String name) {
        Role role = roleService.createRole(name);
        return ResponseEntity.status(HttpStatus.CREATED).body(role);
    }

    @Operation(
            summary = "Assigner une permission à un rôle",
            description = "Attribue une permission existante à un rôle"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Permission assignée avec succès"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Rôle ou permission non trouvé"
            )
    })
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/{roleName}/permissions")
    public ResponseEntity<String> assignPermissionToRole(
            @Parameter(
                    name = "roleName",
                    description = "Nom du rôle",
                    required = true,
                    example = "ADMIN"
            )
            @PathVariable String roleName,
            @Parameter(
                    name = "permissionName",
                    description = "Nom de la permission",
                    required = true,
                    example = "READ_USERS"
            )
            @RequestParam String permissionName) {
        roleService.assignPermissionToRole(roleName, permissionName);
        return ResponseEntity.ok("Permission assignée avec succès");
    }
    @Operation(
            summary = "Afficher la liste des rôles",
            description = "Retourne la liste de tous les rôles existants"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Liste des rôles récupérée avec succès",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Role.class)
                    )
            )
    })
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<?> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

}