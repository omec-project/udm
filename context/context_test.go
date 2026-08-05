// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
)

func TestManageSmData_HandlesNilDnnConfigurations(t *testing.T) {
	ctx := &UDMContext{}
	singleNssai := models.NewSnssai(1)
	singleNssai.SetSd("010101")
	smData := []models.SessionManagementSubscriptionData{{
		SingleNssai: *singleNssai,
	}}

	_, _, dnnsByDnn, allDnns := ctx.ManageSmData(smData, "1-", "internet")
	if len(dnnsByDnn) != 0 {
		t.Fatalf("expected no matching DNN configs, got %d", len(dnnsByDnn))
	}
	if len(allDnns) != 1 {
		t.Fatalf("expected one AllDnns entry, got %d", len(allDnns))
	}
	if allDnns[0] == nil {
		t.Fatal("expected AllDnns entry to be an empty map, not nil")
	}
}

func TestManageSmData_DoesNotPrependZeroValueDnnConfigs(t *testing.T) {
	ctx := &UDMContext{}
	dnnConfigurations := map[string]models.DnnConfiguration{
		"internet": *models.NewDnnConfigurationWithDefaults(),
	}
	singleNssai := models.NewSnssai(1)
	singleNssai.SetSd("010101")
	smSubsData := models.NewSessionManagementSubscriptionData(*singleNssai)
	smSubsData.SetDnnConfigurations(dnnConfigurations)
	smData := []models.SessionManagementSubscriptionData{*smSubsData}

	dnnsByDnn, _ := func() ([]models.DnnConfiguration, []map[string]models.DnnConfiguration) {
		_, _, dnnsByDnn, allDnns := ctx.ManageSmData(smData, "1-", "internet")
		return dnnsByDnn, allDnns
	}()
	if len(dnnsByDnn) != 1 {
		t.Fatalf("expected one matching DNN config, got %d", len(dnnsByDnn))
	}
}

func TestSameAsStoredGUAMI3gppMatchesEqualNidValues(t *testing.T) {
	registration := models.NewAmf3GppAccessRegistrationWithDefaults()
	plmnID := models.NewPlmnIdNid("001", "01")
	plmnID.SetNid("ABCDEFABCDEF")
	guami := models.NewGuami(*plmnID, "123456")
	registration.SetGuami(*guami)

	ue := &UdmUeContext{
		Amf3GppAccessRegistration: registration,
	}
	inGuami := models.NewGuami(*plmnID, "123456")

	if !ue.SameAsStoredGUAMI3gpp(*inGuami) {
		t.Fatal("expected GUAMI comparison to match equal values even when Nid pointers differ")
	}
}

func TestSameAsStoredGUAMINon3gppMatchesEqualNidValues(t *testing.T) {
	registration := models.NewAmfNon3GppAccessRegistrationWithDefaults()
	plmnID := models.NewPlmnIdNid("001", "01")
	plmnID.SetNid("ABCDEFABCDEF")
	guami := models.NewGuami(*plmnID, "654321")
	registration.SetGuami(*guami)

	ue := &UdmUeContext{
		AmfNon3GppAccessRegistration: registration,
	}
	inGuami := models.NewGuami(*plmnID, "654321")

	if !ue.SameAsStoredGUAMINon3gpp(*inGuami) {
		t.Fatal("expected non-3GPP GUAMI comparison to match equal values even when Nid pointers differ")
	}
}

func TestInitNFService_PopulatesNfServiceMap(t *testing.T) {
	ctx := &UDMContext{
		RegisterIPv4: "10.0.0.1",
		SBIPort:      8080,
		UriScheme:    models.URISCHEME_HTTP,
		NfService:    make(map[models.ServiceName]models.NFService),
	}

	serviceNames := []string{"nudm-sdm", "nudm-uecm"}
	ctx.InitNFService(serviceNames, "1.2.3")

	if len(ctx.NfService) != 2 {
		t.Fatalf("expected 2 NF services, got %d", len(ctx.NfService))
	}

	for _, nameStr := range serviceNames {
		name := models.ServiceName(nameStr)
		svc, ok := ctx.NfService[name]
		if !ok {
			t.Errorf("expected service %q to be registered", nameStr)
			continue
		}
		if svc.GetNfServiceStatus() != models.NFSERVICESTATUS_REGISTERED {
			t.Errorf("service %q: expected status REGISTERED, got %v", nameStr, svc.GetNfServiceStatus())
		}
		versions := svc.GetVersions()
		if len(versions) != 1 {
			t.Fatalf("service %q: expected 1 version, got %d", nameStr, len(versions))
		}
		if versions[0].GetApiVersionInUri() != "v1" {
			t.Errorf("service %q: expected version URI %q, got %q", nameStr, "v1", versions[0].GetApiVersionInUri())
		}
		if versions[0].GetApiFullVersion() != "1.2.3" {
			t.Errorf("service %q: expected full version %q, got %q", nameStr, "1.2.3", versions[0].GetApiFullVersion())
		}
		endpoints := svc.GetIpEndPoints()
		if len(endpoints) != 1 {
			t.Fatalf("service %q: expected 1 IP endpoint, got %d", nameStr, len(endpoints))
		}
		if endpoints[0].GetIpv4Address() != ctx.RegisterIPv4 {
			t.Errorf("service %q: expected IP %q, got %q", nameStr, ctx.RegisterIPv4, endpoints[0].GetIpv4Address())
		}
		if endpoints[0].GetPort() != int32(ctx.SBIPort) {
			t.Errorf("service %q: expected port %d, got %d", nameStr, ctx.SBIPort, endpoints[0].GetPort())
		}
		expectedPrefix := ctx.GetIPv4Uri()
		if svc.GetApiPrefix() != expectedPrefix {
			t.Errorf("service %q: expected API prefix %q, got %q", nameStr, expectedPrefix, svc.GetApiPrefix())
		}
	}
}

func newTestUeContext(subscriptionID string, sub *models.SdmSubscription) *UdmUeContext {
	ue := &UdmUeContext{}
	ue.init()
	if sub != nil {
		ue.SubscribeToNotifChange[subscriptionID] = sub
	}
	return ue
}

func TestUpdateSubscriptionToNotifChange_SubscriptionNotFound(t *testing.T) {
	ue := newTestUeContext("sub-1", nil)
	result := ue.UpdateSubscriptionToNotifChange("sub-1", &models.SdmSubsModification{})
	if result != nil {
		t.Fatalf("expected nil for missing subscription, got %+v", result)
	}
}

func TestUpdateSubscriptionToNotifChange_UpdatesPresent(t *testing.T) {
	existing := models.NewSdmSubscriptionWithDefaults()
	t1 := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	existing.SetExpires(t1)
	existing.SetMonitoredResourceUris([]string{"/old-uri"})

	ue := newTestUeContext("sub-1", existing)

	mod := models.NewSdmSubsModificationWithDefaults()
	mod.SetExpires(t2)
	mod.SetMonitoredResourceUris([]string{"/new-uri-1", "/new-uri-2"})

	result := ue.UpdateSubscriptionToNotifChange("sub-1", mod)
	if result == nil {
		t.Fatal("expected non-nil result for existing subscription")
	}
	if !result.GetExpires().Equal(t2) {
		t.Errorf("expires: expected %v, got %v", t2, result.GetExpires())
	}
	uris := result.GetMonitoredResourceUris()
	if len(uris) != 2 || uris[0] != "/new-uri-1" {
		t.Errorf("monitoredResourceUris: unexpected value %v", uris)
	}
}

func TestUpdateSubscriptionToNotifChange_SkipsAbsentFields(t *testing.T) {
	existing := models.NewSdmSubscriptionWithDefaults()
	t1 := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	existing.SetExpires(t1)
	existing.SetMonitoredResourceUris([]string{"/keep-me"})

	ue := newTestUeContext("sub-1", existing)

	// modification that only sets expires, leaving monitoredResourceUris untouched
	mod := models.NewSdmSubsModificationWithDefaults()
	mod.SetExpires(t2)

	result := ue.UpdateSubscriptionToNotifChange("sub-1", mod)
	if result == nil {
		t.Fatal("expected non-nil result for existing subscription")
	}
	if !result.GetExpires().Equal(t2) {
		t.Errorf("expires: expected %v, got %v", t2, result.GetExpires())
	}
	uris := result.GetMonitoredResourceUris()
	if len(uris) != 1 || uris[0] != "/keep-me" {
		t.Errorf("monitoredResourceUris should be unchanged, got %v", uris)
	}
}

func TestUpdateSubscriptionToNotifChange_NilModificationReturnsCopy(t *testing.T) {
	existing := models.NewSdmSubscriptionWithDefaults()
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	existing.SetExpires(t1)
	existing.SetMonitoredResourceUris([]string{"/uri-a"})

	ue := newTestUeContext("sub-1", existing)

	result := ue.UpdateSubscriptionToNotifChange("sub-1", nil)
	if result == nil {
		t.Fatal("expected non-nil result when modification is nil")
	}
	if !result.GetExpires().Equal(t1) {
		t.Errorf("expires should be unchanged: expected %v, got %v", t1, result.GetExpires())
	}
	uris := result.GetMonitoredResourceUris()
	if len(uris) != 1 || uris[0] != "/uri-a" {
		t.Errorf("monitoredResourceUris should be unchanged, got %v", uris)
	}
}

func TestUpdateSubscriptionToNotifChange_ReturnedCopyIsIsolated(t *testing.T) {
	existing := models.NewSdmSubscriptionWithDefaults()
	existing.SetMonitoredResourceUris([]string{"/uri-a", "/uri-b"})
	thresholds := map[string]models.ExpectedUeBehaviourThreshold{"key1": {}}
	existing.SetExpectedUeBehaviourThresholds(thresholds)

	ue := newTestUeContext("sub-1", existing)

	result := ue.UpdateSubscriptionToNotifChange("sub-1", nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Mutate the returned copy's slice — must not affect the cached subscription.
	uris := result.GetMonitoredResourceUris()
	uris[0] = "/mutated"
	cachedUris := ue.SubscribeToNotifChange["sub-1"].GetMonitoredResourceUris()
	if cachedUris[0] != "/uri-a" {
		t.Errorf("mutating returned slice corrupted cached subscription: got %v", cachedUris[0])
	}

	// Mutate the returned copy's map — must not affect the cached subscription.
	resultMap := result.GetExpectedUeBehaviourThresholds()
	resultMap["injected"] = models.ExpectedUeBehaviourThreshold{}
	cachedSub := ue.SubscribeToNotifChange["sub-1"]
	if _, ok := cachedSub.GetExpectedUeBehaviourThresholds()["injected"]; ok {
		t.Error("mutating returned map corrupted cached subscription")
	}
}

const testUdrUri = "https://udr.example.com"

func TestGetOrSetUdrUri_CachesNonEmptyResult(t *testing.T) {
	ue := &UdmUeContext{}
	calls := 0
	fetch := func() string {
		calls++
		return testUdrUri
	}

	first := ue.GetOrSetUdrUri(fetch)
	second := ue.GetOrSetUdrUri(fetch)

	if first != testUdrUri {
		t.Errorf("first call: got %q, want %q", first, testUdrUri)
	}
	if second != testUdrUri {
		t.Errorf("second call: got %q, want %q", second, testUdrUri)
	}
	if calls != 1 {
		t.Errorf("fetch called %d times, want 1 (result should be cached)", calls)
	}
}

func TestGetOrSetUdrUri_DoesNotCacheEmptyResult(t *testing.T) {
	ue := &UdmUeContext{}
	calls := 0
	fetch := func() string {
		calls++
		return ""
	}

	first := ue.GetOrSetUdrUri(fetch)
	second := ue.GetOrSetUdrUri(fetch)

	if first != "" || second != "" {
		t.Errorf("expected empty URI on discovery failure, got %q / %q", first, second)
	}
	if calls != 2 {
		t.Errorf("fetch called %d times, want 2 (empty URI must not be cached)", calls)
	}
}

func TestGetOrSetUdrUri_RecoversAfterFailure(t *testing.T) {
	ue := &UdmUeContext{}
	calls := 0
	fetch := func() string {
		calls++
		if calls < 3 {
			return ""
		}
		return testUdrUri
	}

	for i := 0; i < 2; i++ {
		if got := ue.GetOrSetUdrUri(fetch); got != "" {
			t.Errorf("call %d: expected empty URI during failure, got %q", i+1, got)
		}
	}
	got := ue.GetOrSetUdrUri(fetch)
	if got != testUdrUri {
		t.Errorf("recovery call: got %q, want %q", got, testUdrUri)
	}
	// Further calls must use the cache.
	extra := ue.GetOrSetUdrUri(fetch)
	if extra != testUdrUri {
		t.Errorf("post-recovery call: got %q, want %q", extra, testUdrUri)
	}
	if calls != 3 {
		t.Errorf("fetch called %d times, want 3", calls)
	}
}

func TestGetOrSetUdrUri_ConcurrentCallsResultInSingleFetch(t *testing.T) {
	ue := &UdmUeContext{}
	calls := 0
	start := make(chan struct{})
	fetch := func() string {
		calls++
		<-start // all goroutines unblock simultaneously
		time.Sleep(5 * time.Millisecond)
		return testUdrUri
	}

	const n = 20
	results := make([]string, n)
	done := make(chan int, n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			results[idx] = ue.GetOrSetUdrUri(fetch)
			done <- idx
		}(i)
	}
	close(start)
	for i := 0; i < n; i++ {
		<-done
	}

	for i, r := range results {
		if r != testUdrUri {
			t.Errorf("goroutine %d: got %q, want %q", i, r, testUdrUri)
		}
	}
	if calls != 1 {
		t.Errorf("fetch called %d times under concurrency, want 1", calls)
	}
}

func TestClearUdrUri_ForcesRediscovery(t *testing.T) {
	ue := &UdmUeContext{}
	calls := 0
	fetch := func() string {
		calls++
		return testUdrUri
	}

	// Populate the cache.
	_ = ue.GetOrSetUdrUri(fetch)
	if calls != 1 {
		t.Fatalf("setup: expected 1 fetch call, got %d", calls)
	}

	// Evict the cached URI.
	ue.ClearUdrUri()

	// Next call must re-run discovery.
	got := ue.GetOrSetUdrUri(fetch)
	if got != testUdrUri {
		t.Errorf("post-eviction call: got %q, want %q", got, testUdrUri)
	}
	if calls != 2 {
		t.Errorf("fetch called %d times after eviction, want 2", calls)
	}
}
