use std::collections::HashMap;

use crate::types::rbac::*;

pub struct RbacGraph {
    roles: HashMap<String, RoleNode>,
    principals: HashMap<String, PrincipalNode>,
    orgs: HashMap<String, OrgNode>,
    role_assignments: Vec<(String, String, HasRoleEdge)>,
    role_inherits: Vec<(String, String, RoleInheritsEdge)>,
    org_members: Vec<(String, String, OrgMemberEdge)>,
}

impl RbacGraph {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            principals: HashMap::new(),
            orgs: HashMap::new(),
            role_assignments: Vec::new(),
            role_inherits: Vec::new(),
            org_members: Vec::new(),
        }
    }

    pub fn insert_role(&mut self, role: RoleNode) {
        self.roles.insert(role.role_id.clone(), role);
    }

    pub fn get_role(&self, id: &str) -> Option<&RoleNode> {
        self.roles.get(id)
    }

    pub fn insert_principal(&mut self, principal: PrincipalNode) {
        self.principals
            .insert(principal.principal_id.clone(), principal);
    }

    pub fn get_principal(&self, id: &str) -> Option<&PrincipalNode> {
        self.principals.get(id)
    }

    pub fn insert_org(&mut self, org: OrgNode) {
        self.orgs.insert(org.org_id.clone(), org);
    }

    pub fn assign_role(&mut self, principal_id: &str, role_id: &str, edge: HasRoleEdge) {
        self.role_assignments.push((
            principal_id.to_string(),
            role_id.to_string(),
            edge,
        ));
    }

    pub fn revoke_role(&mut self, principal_id: &str, role_id: &str) {
        self.role_assignments
            .retain(|(p, r, _)| !(p == principal_id && r == role_id));
    }

    pub fn add_role_inheritance(&mut self, child: &str, parent: &str, edge: RoleInheritsEdge) {
        self.role_inherits
            .push((child.to_string(), parent.to_string(), edge));
    }

    pub fn add_org_member(&mut self, org_id: &str, principal_id: &str, edge: OrgMemberEdge) {
        self.org_members
            .push((org_id.to_string(), principal_id.to_string(), edge));
    }

    pub fn roles_for_principal(&self, principal_id: &str) -> Vec<(&HasRoleEdge, Option<&RoleNode>)> {
        self.role_assignments
            .iter()
            .filter(|(p, _, _)| p == principal_id)
            .map(|(_, r, e)| (e, self.roles.get(r)))
            .collect()
    }

    pub fn resolve_effective_mask(&self, role_id: &str) -> u64 {
        let role = match self.roles.get(role_id) {
            Some(r) => r,
            None => return 0,
        };

        let mut mask = role.permission_mask;
        for parent_id in &role.inherits_from {
            mask |= self.resolve_effective_mask(parent_id);
        }
        mask
    }

    pub fn check_access(
        &self,
        principal_id: &str,
        required_permission: u64,
        vault_scope: &str,
        now_ms: u64,
    ) -> RbacDecision {
        let principal = match self.principals.get(principal_id) {
            Some(p) => p,
            None => return RbacDecision::Deny,
        };

        if !principal.active {
            return RbacDecision::Deny;
        }

        let mut effective_mask: u64 = 0;

        for (p_id, _r_id, edge) in &self.role_assignments {
            if p_id != principal_id {
                continue;
            }
            if edge.expires_at != 0 && edge.expires_at < now_ms {
                continue;
            }
            if !vault_scope.is_empty()
                && !edge.scope_vault_id.is_empty()
                && edge.scope_vault_id != vault_scope
            {
                continue;
            }
            effective_mask |= self.resolve_effective_mask(&edge.role_id);
        }

        if (effective_mask & required_permission) == required_permission {
            RbacDecision::Allow
        } else if principal.mfa_required && (effective_mask & (required_permission >> 1)) > 0 {
            RbacDecision::Escalate
        } else {
            RbacDecision::Deny
        }
    }

    pub fn members_of_org(&self, org_id: &str) -> Vec<&PrincipalNode> {
        self.org_members
            .iter()
            .filter(|(o, _, _)| o == org_id)
            .filter_map(|(_, p, _)| self.principals.get(p))
            .collect()
    }
}

impl Default for RbacGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_principal(id: &str, active: bool) -> PrincipalNode {
        PrincipalNode {
            principal_id: id.to_string(),
            org_id: "org1".to_string(),
            display_name_hash: String::new(),
            email_hash: String::new(),
            signing_pubkey: String::new(),
            active,
            mfa_required: false,
            last_auth_at: 0,
            created_at: 1000,
        }
    }

    fn make_role(id: &str, mask: u64) -> RoleNode {
        RoleNode {
            role_id: id.to_string(),
            org_id: "org1".to_string(),
            name: id.to_string(),
            description: String::new(),
            permission_mask: mask,
            inherits_from: vec![],
            max_vault_access: 0,
            max_credential_access: 0,
            created_by: "admin".to_string(),
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn make_edge(role_id: &str) -> HasRoleEdge {
        HasRoleEdge {
            edge_id: [0u8; 16],
            role_id: role_id.to_string(),
            granted_at: 1000,
            granted_by: "admin".to_string(),
            expires_at: 0,
            scope_vault_id: String::new(),
        }
    }

    #[test]
    fn test_access_allow() {
        let mut g = RbacGraph::new();
        g.insert_principal(make_principal("alice", true));
        g.insert_role(make_role("viewer", PERM_READ));
        g.assign_role("alice", "viewer", make_edge("viewer"));

        assert_eq!(g.check_access("alice", PERM_READ, "", 2000), RbacDecision::Allow);
    }

    #[test]
    fn test_access_deny() {
        let mut g = RbacGraph::new();
        g.insert_principal(make_principal("bob", true));
        g.insert_role(make_role("viewer", PERM_READ));
        g.assign_role("bob", "viewer", make_edge("viewer"));

        assert_eq!(
            g.check_access("bob", PERM_ADMIN, "", 2000),
            RbacDecision::Deny
        );
    }

    #[test]
    fn test_access_inactive_principal() {
        let mut g = RbacGraph::new();
        g.insert_principal(make_principal("charlie", false));
        g.insert_role(make_role("owner", 0xFF));
        g.assign_role("charlie", "owner", make_edge("owner"));

        assert_eq!(
            g.check_access("charlie", PERM_READ, "", 2000),
            RbacDecision::Deny
        );
    }

    #[test]
    fn test_role_inheritance() {
        let mut g = RbacGraph::new();
        let mut user_role = make_role("user", PERM_READ | PERM_DECRYPT | PERM_WRITE);
        user_role.inherits_from = vec!["viewer".to_string()];
        g.insert_role(make_role("viewer", PERM_READ));
        g.insert_role(user_role);

        let mask = g.resolve_effective_mask("user");
        assert_eq!(mask, PERM_READ | PERM_DECRYPT | PERM_WRITE);
    }

    #[test]
    fn test_expired_role() {
        let mut g = RbacGraph::new();
        g.insert_principal(make_principal("dave", true));
        g.insert_role(make_role("admin", 0xFF));

        let mut edge = make_edge("admin");
        edge.expires_at = 500;
        g.assign_role("dave", "admin", edge);

        assert_eq!(
            g.check_access("dave", PERM_READ, "", 2000),
            RbacDecision::Deny
        );
    }

    #[test]
    fn test_revoke_role() {
        let mut g = RbacGraph::new();
        g.insert_principal(make_principal("eve", true));
        g.insert_role(make_role("admin", 0xFF));
        g.assign_role("eve", "admin", make_edge("admin"));

        assert_eq!(g.check_access("eve", PERM_READ, "", 2000), RbacDecision::Allow);
        g.revoke_role("eve", "admin");
        assert_eq!(g.check_access("eve", PERM_READ, "", 2000), RbacDecision::Deny);
    }
}
