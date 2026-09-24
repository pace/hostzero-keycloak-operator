package controller

import (
	"encoding/json"
	"testing"
)

// Shape taken from a live Keycloak 26 GET .../protocol-mappers/models: the
// server adds "id" and reorders keys, which must not count as drift.
const liveMapperList = `[
	{"id":"eb2a593f-8dc6-4791-8d7d-5c576a203fd4","name":"realm roles","protocol":"openid-connect","protocolMapper":"oidc-usermodel-realm-role-mapper","consentRequired":false,"config":{"access.token.claim":"true","introspection.token.claim":"true","claim.name":"realm_access.roles","jsonType.label":"String","multivalued":"true"}},
	{"id":"9544248a-c141-43fd-97a7-b5a918fcf9c9","name":"email","protocol":"openid-connect","protocolMapper":"oidc-usermodel-property-mapper","consentRequired":false,"config":{"user.attribute":"email","claim.name":"email"}}
]`

func liveMappers(t *testing.T) []json.RawMessage {
	t.Helper()
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(liveMapperList), &items); err != nil {
		t.Fatal(err)
	}
	return items
}

func TestFindMapperByName(t *testing.T) {
	id, raw := findMapperByName(liveMappers(t), "realm roles")
	if id != "eb2a593f-8dc6-4791-8d7d-5c576a203fd4" || raw == nil {
		t.Fatalf("got id=%q raw=%s", id, raw)
	}
	if id, raw := findMapperByName(liveMappers(t), "missing"); id != "" || raw != nil {
		t.Fatalf("expected no match, got id=%q", id)
	}
}

func TestProtocolMapperDrift_InSyncSkipsUpdate(t *testing.T) {
	desired := json.RawMessage(`{"config":{"access.token.claim":"true","claim.name":"realm_access.roles","introspection.token.claim":"true","jsonType.label":"String","multivalued":"true"},"consentRequired":false,"name":"realm roles","protocol":"openid-connect","protocolMapper":"oidc-usermodel-realm-role-mapper"}`)
	_, current := findMapperByName(liveMappers(t), "realm roles")
	if !definitionsMatch(desired, current) {
		t.Fatal("unchanged mapper reported as drift; would re-PUT on every sync")
	}
}

func TestProtocolMapperDrift_ConfigChangeDetected(t *testing.T) {
	desired := json.RawMessage(`{"name":"realm roles","protocolMapper":"oidc-usermodel-realm-role-mapper","config":{"claim.name":"roles"}}`)
	_, current := findMapperByName(liveMappers(t), "realm roles")
	if definitionsMatch(desired, current) {
		t.Fatal("changed config.claim.name not detected")
	}
}

func TestProtocolMapperDrift_NoCurrentForcesUpdate(t *testing.T) {
	if definitionsMatch(json.RawMessage(`{"name":"x"}`), nil) {
		t.Fatal("missing current representation must fall through to update")
	}
}

func TestRoleDrift_CompositesStrippedBeforeCompare(t *testing.T) {
	// Role GET does not return composites; the controller strips them from the
	// definition and syncs them via the composites endpoint instead.
	desired := removeFieldFromDefinition(json.RawMessage(`{"name":"default-roles-x","composite":true,"composites":{"realm":["offline_access"]}}`), "composites")
	current := json.RawMessage(`{"id":"1","name":"default-roles-x","composite":true,"clientRole":false,"containerId":"x","attributes":{}}`)
	if !definitionsMatch(desired, current) {
		t.Fatal("unchanged role reported as drift")
	}
}
