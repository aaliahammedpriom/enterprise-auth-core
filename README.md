
src/
 ├── modules/                  # Core domain modules (all features here)
 │    ├── auth/                # Authentication, JWT, login, OTP
 │    │    ├── controllers/
 │    │    ├── services/
 │    │    ├── schemas/
 │    │    ├── dto/
 │    │    └── strategies/
 │    │
 │    ├── users/               # User profile, management
 │    │    ├── controllers/
 │    │    ├── services/
 │    │    ├── schemas/
 │    │    └── dto/
 │    │
 │    ├── roles/               # Roles & RBAC
 │    │    ├── controllers/
 │    │    ├── services/
 │    │    ├── schemas/
 │    │    └── dto/
 │    │
 │    ├── permissions/         # Permissions & fine-grained access
 │    │    ├── controllers/
 │    │    ├── services/
 │    │    ├── schemas/
 │    │    └── dto/
 │    │
 │    ├── sessions/            # Device sessions, refresh tokens
 │    │    ├── controllers/
 │    │    ├── services/
 │    │    ├── schemas/
 │    │    └── dto/
 │    │
 │    └── audit/               # Audit logs, security tracking
 │         ├── controllers/
 │         ├── services/
 │         ├── schemas/
 │         └── dto/
 │
 ├── common/                   # Reusable tools, cross-cutting concerns
 │    ├── decorators/          # @CurrentUser, @Roles, etc.
 │    ├── guards/              # JwtAuthGuard, RolesGuard, PermissionsGuard
 │    ├── interceptors/        # Logging, transformation, etc.
 │    ├── filters/             # Exception filters
 │    ├── pipes/               # Validation pipes, transform pipes
 │    ├── constants/           # App constants, enums
 │    └── utils/               # Helper functions
 │
 ├── config/                   # Type-safe configuration
 │    └── index.ts
 │
 ├── database/                 # Database connection
 │    ├── database.module.ts
 │    └── database.providers.ts
 │
 ├── shared/                   # Shared types/interfaces
 │    ├── interfaces/
 │    └── types/
 │
 ├── app.module.ts
 └── main.ts